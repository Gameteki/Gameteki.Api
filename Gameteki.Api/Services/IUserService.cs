namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.AspNetCore.Identity;

    public interface IUserService
    {
        // Task<RegisterAccountResult> RegisterUserAsync(RegisterAccountRequest request, string ipAddress);
        // Task<bool> SendActivationEmailAsync(GametekiUser user, AccountVerificationModel model);
        // Task<bool> ValidateUserAsync(string userId, string token);
        // Task<LoginResult> LoginUserAsync(string username, string password, string ipAddress);
        Task<GametekiUser> GetUserFromIdAsync(string userId);
        Task<GametekiUser> GetUserFromUsernameAsync(string username);
        Task<bool> AddBlockListEntryAsync(GametekiUser user, string username);
        Task<bool> RemoveBlockListEntryAsync(GametekiUser user, string username);
        Task<IdentityResult> UpdateUserAsync();
        Task<bool> LogoutUserAsync(string token);
        Task<bool> UpdatePermissionsAsync(GametekiUser user, GametekiPermissions newPermissions);
        Task<GametekiUser> CreateOrUpdateUserAsync(string userId, string username, string email);
    }
}
