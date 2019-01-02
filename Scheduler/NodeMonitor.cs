namespace CrimsonDev.Gameteki.Api.Scheduler
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.Extensions.Logging;
    using Newtonsoft.Json;
    using Quartz;
    using StackExchange.Redis;

    public class NodeMonitor : IJob
    {
        private readonly ILogger<NodeMonitor> logger;
        private readonly ISubscriber subscriber;
        private readonly IDatabase database;
        private readonly Dictionary<string, List<string>> nodeUsers;
        private readonly Dictionary<string, DateTime> nodeLastHeartbeat;

        public NodeMonitor(IConnectionMultiplexer redisConnection, ILogger<NodeMonitor> logger)
        {
            this.logger = logger;

            nodeUsers = new Dictionary<string, List<string>>();
            nodeLastHeartbeat = new Dictionary<string, DateTime>();

            subscriber = redisConnection.GetSubscriber();
            database = redisConnection.GetDatabase();

            subscriber.Subscribe(RedisChannels.LobbyHello, OnLobbyHello);
            subscriber.Subscribe(RedisChannels.LobbyHeartbeat, OnLobbyHeartbeat);
            subscriber.Subscribe(RedisChannels.NewUser, OnNodeNewUser);
            subscriber.Subscribe(RedisChannels.UserDisconnect, OnNodeUserDisconnect);
        }

        public async Task Execute(IJobExecutionContext context)
        {
            foreach (var (nodeName, lastHeartbeat) in nodeLastHeartbeat)
            {
                if (DateTime.UtcNow - lastHeartbeat < TimeSpan.FromMinutes(2))
                {
                    continue;
                }

                logger.LogError($"Node '{nodeName}' timed out after no heartbeat for 5 minutes");

                await subscriber.PublishAsync(RedisChannels.UsersDisconnect, JsonConvert.SerializeObject(nodeUsers[nodeName]));

                nodeUsers[nodeName].Clear();
                nodeUsers.Remove(nodeName);
            }
        }

        private void OnNodeUserDisconnect(RedisChannel channel, RedisValue user)
        {
            var lobbyUser = JsonConvert.DeserializeObject<LobbyUser>(user);

            if (!nodeUsers.ContainsKey(lobbyUser.Node))
            {
                logger.LogError($"Got disconnected user '{lobbyUser.Name}' from unknown node '{lobbyUser.Node}'");

                return;
            }

            nodeUsers[lobbyUser.Node].Remove(lobbyUser.Name);
        }

        private void OnNodeNewUser(RedisChannel channel, RedisValue user)
        {
            var lobbyUser = JsonConvert.DeserializeObject<LobbyUser>(user);

            if (!nodeUsers.ContainsKey(lobbyUser.Node))
            {
                logger.LogError($"Got new user '{lobbyUser.Name}' from unknown node '{lobbyUser.Node}'");

                return;
            }

            nodeUsers[lobbyUser.Node].Add(lobbyUser.Name);
        }

        private void OnLobbyHeartbeat(RedisChannel channel, RedisValue nodeName)
        {
            logger.LogDebug($"Node '{nodeName}' heartbeat");

            if (!nodeLastHeartbeat.ContainsKey(nodeName))
            {
                logger.LogError($"Got heartbeat from unknown node '{nodeName}'");

                return;
            }

            nodeLastHeartbeat[nodeName] = DateTime.UtcNow;
        }

        private void OnLobbyHello(RedisChannel channel, RedisValue nodeName)
        {
            logger.LogInformation($"Node '{nodeName}' came online");

            nodeLastHeartbeat[nodeName] = DateTime.UtcNow;
            nodeUsers[nodeName] = new List<string>();
        }
    }
}
