namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Data.Models;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Identity;

    public interface IUserService
    {
        Task<RegisterAccountResult> RegisterUserAsync(RegisterAccountRequest request, string ipAddress);
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
        Task<bool> LogoutUserAsync(string token, string refreshToken);
        Task<bool> UpdatePermissionsAsync(GametekiUser user, GametekiPermissions newPermissions);
    }
}
