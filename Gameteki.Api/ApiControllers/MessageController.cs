namespace CrimsonDev.Gameteki.Api.ApiControllers
{
    using System;
    using System.Diagnostics;
    using System.Linq;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Localization;
    using Microsoft.Extensions.Logging;
    using Newtonsoft.Json;
    using StackExchange.Redis;

    public class MessageController : Controller
    {
        private readonly IMessageService messageService;
        private readonly IUserService userService;
        private readonly ILogger<MessageController> logger;
        private readonly IStringLocalizer<MessageController> t;
        private readonly ISubscriber subscriber;

        public MessageController(
            IMessageService messageService,
            IUserService userService,
            IConnectionMultiplexer redisConnection,
            ILogger<MessageController> logger,
            IStringLocalizer<MessageController> localizer)
        {
            this.messageService = messageService;
            this.userService = userService;
            this.logger = logger;
            t = localizer;

            if (redisConnection == null)
            {
                throw new ArgumentNullException(nameof(redisConnection));
            }

            subscriber = redisConnection.GetSubscriber();
        }

        [HttpGet]
        [Route("api/messages")]
        public async Task<ActionResult<GetMessagesResponse>> GetMessages()
        {
            var messages = await messageService.GetLatestLobbyMessagesAsync().ConfigureAwait(false);

            var response = new GetMessagesResponse
            {
                Success = true
            };

            response.Messages.AddRange(messages.Select(m => m.ToApiLobbyMessage()).ToList());

            return response;
        }

        [HttpPost]
        [Route("api/messages")]
        [Authorize]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "ASP.NET will ensure this is not null")]
        public async Task<ActionResult<ApiResponse>> AddMessage([FromBody] AddMessageRequest request)
        {
            Debug.Assert(request != null, "Asp.net core failed us and request was null");

            var user = await userService.GetUserFromUsernameAsync(User.Identity.Name).ConfigureAwait(false);
            if (user == null)
            {
                logger.LogError($"Failed to find user '{User.Identity.Name}' when trying to add message '{request.Message}'");
                return this.FailureResponse(t["An error occurred trying to send your message"]);
            }

            var newMessage = await messageService.AddMessageAsync(user.Id, request.Message).ConfigureAwait(false);
            if (newMessage == null)
            {
                logger.LogError($"Failed add message '{request.Message}'");
                return this.FailureResponse(t["An error occurred trying to send your message"]);
            }

            newMessage.Sender = user;

            var apiMessage = newMessage.ToApiLobbyMessage();

            await subscriber.PublishAsync(RedisChannels.LobbyMessage, JsonConvert.SerializeObject(apiMessage)).ConfigureAwait(false);

            return new AddMessageResponse { Success = true, NewMessage = apiMessage };
        }

        [HttpDelete]
        [Route("api/messages/{messageId}")]
        [Authorize(Roles = Roles.ChatManager)]
        public async Task<ActionResult<ApiResponse>> RemoveMessage(int messageId)
        {
            var user = await userService.GetUserFromUsernameAsync(User.Identity.Name).ConfigureAwait(false);
            if (user == null)
            {
                logger.LogError($"Failed to find user '{User.Identity.Name}' when trying to remove message '{messageId}'");
                return this.FailureResponse(t["An error occurred trying to remove the message"]);
            }

            var message = await messageService.FindByIdAsync(messageId).ConfigureAwait(false);
            if (message == null)
            {
                return NotFound();
            }

            message.Removed = true;
            message.RemovedById = user.Id;
            message.RemovedDateTime = DateTime.UtcNow;

            var result = await messageService.UpdateMessageAsync(message).ConfigureAwait(false);
            if (!result)
            {
                logger.LogError($"Failed to remove message '{messageId}'");
                return this.FailureResponse(t["An error occurred trying to remove the message"]);
            }

            await subscriber.PublishAsync(RedisChannels.LobbyMessageRemoved, messageId).ConfigureAwait(false);

            return new DeleteMessageResponse { Success = true, MessageId = messageId };
        }
    }
}
