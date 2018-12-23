namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.AspNetCore.Identity;

    public interface IUserService
    {
        Task<bool> IsUsernameInUseAsync(string username);
        Task<bool> IsEmailInUseAsync(string email);
        Task<IdentityResult> RegisterUserAsync(GametekiUser user, string password);
        Task<bool> SendActivationEmailAsync(GametekiUser user, AccountVerificationModel model);
        Task<bool> ValidateUserAsync(string userId, string token);
        Task<LoginResult> LoginUserAsync(string username, string password, string ipAddress);
        Task<RefreshToken> CreateRefreshTokenAsync(GametekiUser user, string ipAddress);
        Task<GametekiUser> GetUserFromUsernameAsync(string username);
        Task<LoginResult> RefreshTokenAsync(string token, string refreshToken, string ipAddress);
        Task<RefreshToken> GetRefreshTokenByIdAsync(int tokenId);
        Task<bool> DeleteRefreshTokenAsync(RefreshToken token);
        Task<bool> AddBlockListEntryAsync(GametekiUser user, string username);
        Task<bool> RemoveBlockListEntryAsync(GametekiUser user, string username);
        Task<IdentityResult> UpdateUserAsync(GametekiUser user, string existingPassword = null, string newPassword = null);
        Task<bool> ClearRefreshTokensAsync(GametekiUser user);
        Task<bool> LogoutUserAsync(string requestToken, string requestRefreshToken);
        Task<bool> UpdatePermissionsAsync(GametekiUser user, Permissions newPermissions);
    }
}