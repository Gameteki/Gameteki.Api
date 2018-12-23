namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Config;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.IdentityModel.Tokens;

    internal class UserService : IUserService
    {
        private const int TokenExpiry = 30;
        private readonly IGametekiDbContext context;
        private readonly UserManager<GametekiUser> userManager;
        private readonly GametekiApiOptions apiOptions;
        private readonly IEmailSender emailSender;
        private readonly IViewRenderService viewRenderService;
        private readonly ILogger<UserService> logger;
        private readonly AuthTokenOptions tokenOptions;

        public UserService(
            IGametekiDbContext context,
            UserManager<GametekiUser> userManager,
            IOptions<AuthTokenOptions> optionsAccessor,
            IOptions<GametekiApiOptions> lobbyOptions,
            IEmailSender emailSender,
            IViewRenderService viewRenderService,
            ILogger<UserService> logger)
        {
            this.context = context;
            this.userManager = userManager;
            this.apiOptions = lobbyOptions.Value;
            this.emailSender = emailSender;
            this.viewRenderService = viewRenderService;
            this.logger = logger;
            tokenOptions = optionsAccessor.Value;
        }

        public async Task<bool> IsUsernameInUseAsync(string username)
        {
            return await context.Users.AnyAsync(u => u.UserName.Equals(username, StringComparison.InvariantCultureIgnoreCase));
        }

        public async Task<bool> IsEmailInUseAsync(string email)
        {
            return await context.Users.AnyAsync(u => u.Email.Equals(email, StringComparison.InvariantCultureIgnoreCase));
        }

        public async Task<IdentityResult> RegisterUserAsync(GametekiUser newUser, string password)
        {
            try
            {
                var result = await userManager.CreateAsync(newUser, password);
                if (!result.Succeeded)
                {
                    logger.LogError($"Failed to register user '{newUser.UserName}': {result.Errors.Aggregate(string.Empty, (prev, error) => prev + $" ({error.Code}) - {error.Description}")}");
                    return result;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, $"Failed to register user '{newUser.UserName}'");
                return IdentityResult.Failed(new IdentityError
                    { Code = "InternalError", Description = "An error occurred registering the user" });
            }

            return IdentityResult.Success;
        }

        public async Task<bool> SendActivationEmailAsync(GametekiUser user, AccountVerificationModel model)
        {
            try
            {
                var code = await userManager.GenerateEmailConfirmationTokenAsync(user);
                model.VerificationUrl += $"&token={Uri.EscapeDataString(code)}";

                var emailBody = await viewRenderService.RenderToStringAsync("Email/AccountVerification", model);

                await emailSender.SendEmailAsync(user.Email, $"{apiOptions.ApplicationName} - Account activation", emailBody);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred sending account verification email");

                return false;
            }

            return true;
        }

        public async Task<bool> ValidateUserAsync(string userId, string token)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return false;
            }

            if (string.IsNullOrEmpty(token))
            {
                return false;
            }

            var user = await userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return false;
            }

            var result = await userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
            {
                return false;
            }

            return true;
        }

        public async Task<LoginResult> LoginUserAsync(string username, string password, string ipAddress)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            var user = await GetUserFromUsernameAsync(username);
            if (user == null)
            {
                return null;
            }

            if (user.Disabled)
            {
                return null;
            }

            var isPasswordCorrect = await userManager.CheckPasswordAsync(user, password);
            if (!isPasswordCorrect)
            {
                return null;
            }

            var refreshToken = await CreateRefreshTokenAsync(user, ipAddress);
            var result = new LoginResult
            {
                Token = GenerateTokenForUser(user),
                User = user,
                RefreshToken = refreshToken.Token
            };

            user.LastLoginDate = DateTime.UtcNow;

            await context.SaveChangesAsync();

            return result;
        }

        public async Task<RefreshToken> CreateRefreshTokenAsync(GametekiUser user, string ipAddress)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (ipAddress == null)
            {
                throw new ArgumentNullException(nameof(ipAddress));
            }

            var token = new RefreshToken
            {
                UserId = user.Id,
                IpAddress = ipAddress,
                Expires = DateTime.UtcNow.AddDays(TokenExpiry),
                LastUsed = DateTime.UtcNow,
                Token = GenerateRefreshToken()
            };

            try
            {
                user.RefreshTokens.Add(token);
                context.RefreshToken.Add(token);

                await context.SaveChangesAsync();
            }
            catch (Exception)
            {
                return null;
            }

            return token;
        }

        public virtual async Task<GametekiUser> GetUserFromUsernameAsync(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException(nameof(username));
            }

            return await context.Users
                .Include(u => u.RefreshTokens)
                .Include(u => u.BlockList)
                .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.User)
                .Include("UserRoles.Role")
                .SingleOrDefaultAsync(u => u.UserName.Equals(username, StringComparison.OrdinalIgnoreCase));
        }

        public async Task<LoginResult> RefreshTokenAsync(string token, string refreshToken, string ipAddress)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (refreshToken == null)
            {
                throw new ArgumentNullException(nameof(refreshToken));
            }

            var claimsPrincipal = GetPrincipalFromExpiredToken(token);
            if (claimsPrincipal == null)
            {
                return null;
            }

            var dbToken = await context.RefreshToken
                .Include(rt => rt.User)
                .ThenInclude(u => u.UserRoles)
                .ThenInclude(ur => ur.User)
                .Include("User.UserRoles.Role")
                .SingleOrDefaultAsync(rt => rt.User.UserName.Equals(claimsPrincipal.Identity.Name, StringComparison.InvariantCultureIgnoreCase) && rt.Token == refreshToken);

            if (dbToken == null)
            {
                return null;
            }

            var result = await UpdateRefreshTokenUsage(dbToken, ipAddress);
            if (!result)
            {
                return null;
            }

            return new LoginResult
            {
                RefreshToken = dbToken.Token,
                User = dbToken.User,
                Token = GenerateTokenForUser(dbToken.User)
            };
        }

        public Task<RefreshToken> GetRefreshTokenByIdAsync(int tokenId)
        {
            return context.RefreshToken.SingleOrDefaultAsync(t => t.Id == tokenId);
        }

        public async Task<bool> DeleteRefreshTokenAsync(RefreshToken token)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            try
            {
                context.RefreshToken.Remove(token);
                await context.SaveChangesAsync();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        public async Task<bool> AddBlockListEntryAsync(GametekiUser user, string username)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (username == null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            var blockListEntry = new BlockListEntry
            {
                BlockedUser = username,
                UserId = user.Id
            };

            try
            {
                context.BlockListEntry.Add(blockListEntry);
                await context.SaveChangesAsync();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        public async Task<bool> RemoveBlockListEntryAsync(GametekiUser user, string username)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (username == null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            try
            {
                var blockListEntry = await context.BlockListEntry.SingleOrDefaultAsync(bl => bl.BlockedUser.Equals(username, StringComparison.InvariantCultureIgnoreCase));

                context.BlockListEntry.Remove(blockListEntry);

                await context.SaveChangesAsync();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        public async Task<IdentityResult> UpdateUserAsync(GametekiUser user, string currentPassword, string newPassword)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            try
            {
                await context.SaveChangesAsync();
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Error updating user");
                return IdentityResult.Failed(new IdentityError { Code = "Internal Error", Description = "An error occurred saving your profile.  Please try again later." });
            }

            if (currentPassword == null || newPassword == null)
            {
                return IdentityResult.Success;
            }

            var result = await userManager.ChangePasswordAsync(user, currentPassword, newPassword);

            return !result.Succeeded ? result : IdentityResult.Success;
        }

        public async Task<bool> ClearRefreshTokensAsync(GametekiUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.RefreshTokens.Clear();

            try
            {
                await context.SaveChangesAsync();
            }
            catch (Exception exception)
            {
                logger.LogError(exception, $"Error clearing refresh tokens for user {user.UserName}");
                return false;
            }

            return true;
        }

        public async Task<bool> LogoutUserAsync(string token, string refreshToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (refreshToken == null)
            {
                throw new ArgumentNullException(nameof(refreshToken));
            }

            var claimsPrincipal = GetPrincipalFromExpiredToken(token);
            if (claimsPrincipal == null)
            {
                return false;
            }

            var dbToken = await context.RefreshToken
                .Include(rt => rt.User)
                .SingleOrDefaultAsync(rt => rt.User.UserName.Equals(claimsPrincipal.Identity.Name, StringComparison.InvariantCultureIgnoreCase) && rt.Token == refreshToken);

            if (dbToken == null)
            {
                return false;
            }

            context.RefreshToken.Remove(dbToken);

            try
            {
                await context.SaveChangesAsync();
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Failed to remove refresh token");

                return false;
            }

            return true;
        }

        public async Task<bool> UpdatePermissionsAsync(GametekiUser user, Permissions newPermissions)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (newPermissions == null)
            {
                throw new ArgumentNullException(nameof(newPermissions));
            }

            var existingPermissions = user.ToApiUser().Permissions;
            var toAdd = new List<string>();
            var toRemove = new List<string>();

            ProcessPermission(newPermissions.CanEditNews, existingPermissions.CanEditNews, Roles.NewsManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanManageGames, existingPermissions.CanManageGames, Roles.GameManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanManageNodes, existingPermissions.CanManageNodes, Roles.NodeManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanManagePermissions, existingPermissions.CanManagePermissions, Roles.PermissionsManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanManageUsers, existingPermissions.CanManageUsers, Roles.UserManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanModerateChat, existingPermissions.CanModerateChat, Roles.ChatManager, toRemove, toAdd);

            foreach (var roleToAdd in toAdd)
            {
                var role = await context.Roles.SingleOrDefaultAsync(r => r.Name == roleToAdd);
                if (role == null)
                {
                    continue;
                }

                user.UserRoles.Add(new GametekiUserRole { Role = role, User = user });
            }

            foreach (var roleToRemove in toRemove)
            {
                var userRole = user.UserRoles.Single(ur => ur.Role.Name == roleToRemove);

                user.UserRoles.Remove(userRole);
            }

            try
            {
                await context.SaveChangesAsync();
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Failed updating permissions");
                return false;
            }

            return true;
        }

        private static void ProcessPermission(bool newPermission, bool existingPermission, string roleName, ICollection<string> toRemove, ICollection<string> toAdd)
        {
            if (existingPermission && !newPermission)
            {
                toRemove.Add(roleName);
            }

            if (!existingPermission && newPermission)
            {
                toAdd.Add(roleName);
            }
        }

        private string GenerateTokenForUser(GametekiUser user)
        {
            var claims = new List<Claim> { new Claim(ClaimTypes.Name, user.UserName) };

            claims.AddRange(user.UserRoles.Select(ur => new Claim(ClaimTypes.Role, ur.Role.Name)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.Key));
            var jwt = new JwtSecurityToken(
                tokenOptions.Issuer,
                audience: tokenOptions.Issuer,
                claims: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(value: 5),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private async Task<bool> UpdateRefreshTokenUsage(RefreshToken token, string ipAddress)
        {
            token.IpAddress = ipAddress;
            token.LastUsed = DateTime.UtcNow;
            token.Expires = DateTime.UtcNow.AddDays(TokenExpiry);

            try
            {
                await context.SaveChangesAsync();
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }

        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = true,
                ValidAudience = tokenOptions.Issuer,
                ValidateIssuer = true,
                ValidIssuer = tokenOptions.Issuer,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.Key)),
                ValidateLifetime = false
            };

            ClaimsPrincipal principal;
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);

                if (!(securityToken is JwtSecurityToken jwtSecurityToken) || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                {
                    return null;
                }
            }
            catch (Exception)
            {
                return null;
            }

            return principal;
        }
    }
}
