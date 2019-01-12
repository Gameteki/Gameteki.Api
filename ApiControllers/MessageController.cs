namespace CrimsonDev.Gameteki.Api.ApiControllers
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Newtonsoft.Json;
    using StackExchange.Redis;

    public class MessageController : Controller
    {
        private readonly IMessageService messageService;
        private readonly IUserService userService;
        private readonly ILogger<MessageController> logger;
        private readonly ISubscriber subscriber;

        public MessageController(IMessageService messageService, IUserService userService, IConnectionMultiplexer redisConnection, ILogger<MessageController> logger)
        {
            this.messageService = messageService;
            this.userService = userService;
            this.logger = logger;

            subscriber = redisConnection.GetSubscriber();
        }

        [HttpGet]
        [Route("api/messages")]
        public async Task<IActionResult> GetMessages()
        {
            var messages = await messageService.GetLatestLobbyMessagesAsync();

            return Json(new GetMessagesResponse { Success = true, Messages = messages.Select(m => m.ToApiLobbyMessage()).ToList() });
        }

        [HttpPost]
        [Route("api/messages")]
        [Authorize]
        public async Task<IActionResult> AddMessage([FromBody] AddMessageRequest request)
        {
            var user = await userService.GetUserFromUsernameAsync(User.Identity.Name);
            if (user == null)
            {
                logger.LogError($"Failed to find user '{User.Identity.Name}' when trying to add message '{request.Message}'");
                return this.FailureResponse("An error occurred trying to send your message.");
            }

            var newMessage = await messageService.AddMessageAsync(user.Id, request.Message);
            if (newMessage == null)
            {
                logger.LogError($"Failed add message '{request.Message}'");
                return this.FailureResponse("An error occurred trying to send your message.");
            }

            newMessage.Sender = user;

            var apiMessage = newMessage.ToApiLobbyMessage();

            await subscriber.PublishAsync(RedisChannels.LobbyMessage, JsonConvert.SerializeObject(apiMessage));

            return Json(new AddMessageResponse { Success = true, NewMessage = apiMessage });
        }

        [HttpDelete]
        [Route("api/messages/{messageId}")]
        [Authorize(Roles = Roles.ChatManager)]
        public async Task<IActionResult> RemoveMessage(int messageId)
        {
            var user = await userService.GetUserFromUsernameAsync(User.Identity.Name);
            if (user == null)
            {
                logger.LogError($"Failed to find user '{User.Identity.Name}' when trying to remove message '{messageId}'");
                return this.FailureResponse("An error occurred trying to remove the message.");
            }

            var message = await messageService.FindByIdAsync(messageId);
            if (message == null)
            {
                return NotFound();
            }

            message.Removed = true;
            message.RemovedById = user.Id;
            message.RemovedDateTime = DateTime.UtcNow;

            var result = await messageService.UpdateMessageAsync(message);
            if (!result)
            {
                logger.LogError($"Failed to remove message '{messageId}'");
                return this.FailureResponse("An error occurred trying to remove the message.");
            }

            await subscriber.PublishAsync(RedisChannels.LobbyMessageRemoved, messageId);

            return Json(new DeleteMessageResponse { Success = true, MessageId = messageId });
        }
    }
}
