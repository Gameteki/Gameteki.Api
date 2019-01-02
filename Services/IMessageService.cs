namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Data.Models;

    public interface IMessageService
    {
        Task<List<LobbyMessage>> GetLatestLobbyMessagesAsync();
        Task<LobbyMessage> AddMessageAsync(string userId, string message);
        Task<LobbyMessage> FindByIdAsync(int messageId);
        Task<bool> UpdateMessageAsync(LobbyMessage message);
    }
}
