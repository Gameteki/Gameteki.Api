namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Logging;

    public class MessageService : IMessageService
    {
        private readonly IGametekiDbContext context;
        private readonly ILogger<MessageService> logger;

        public MessageService(IGametekiDbContext context, ILogger<MessageService> logger)
        {
            this.context = context;
            this.logger = logger;
        }

        public Task<List<LobbyMessage>> GetLatestLobbyMessagesAsync()
        {
            return context.LobbyMessage.Include(m => m.Sender).Where(m => !m.Removed).OrderBy(m => m.MessageDateTime).Take(100).ToListAsync();
        }

        public Task<LobbyMessage> AddMessageAsync(string userId, string message)
        {
            if (string.IsNullOrEmpty(userId))
            {
                throw new ArgumentNullException(nameof(userId));
            }

            if (string.IsNullOrEmpty(message))
            {
                throw new ArgumentNullException(nameof(message));
            }

            return AddMessageInternalAsync(userId, message);
        }

        public Task<LobbyMessage> FindByIdAsync(int messageId)
        {
            return context.LobbyMessage.SingleOrDefaultAsync(m => m.Id == messageId);
        }

        public Task<bool> UpdateMessageAsync(LobbyMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return UpdateMessageInternalAsync(message);
        }

        private async Task<bool> UpdateMessageInternalAsync(LobbyMessage message)
        {
            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException ex)
            {
                logger.LogError(ex, $"Failed to update message {message.Id}");

                return false;
            }

            return true;
        }

        private async Task<LobbyMessage> AddMessageInternalAsync(string userId, string message)
        {
            var newMessage = new LobbyMessage
            {
                MessageDateTime = DateTime.UtcNow,
                MessageText = message,
                SenderId = userId
            };

            context.LobbyMessage.Add(newMessage);

            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException exception)
            {
                logger.LogError(exception, $"Error saving message '{message}' for user '{userId}'");
                return null;
            }

            return newMessage;
        }
    }
}
