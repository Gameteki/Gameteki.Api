﻿namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Text;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using CrimsonDev.Gameteki.Data.Models.Config;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Localization;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.IdentityModel.Tokens;

    public class UserService : IUserService
    {
        private const int TokenExpiry = 30;
        private readonly IGametekiDbContext context;
        private readonly UserManager<GametekiUser> userManager;
        private readonly GametekiApiOptions apiOptions;
        private readonly IEmailSender emailSender;
        private readonly IViewRenderService viewRenderService;
        private readonly ILogger<UserService> logger;
        private readonly IStringLocalizer<UserService> t;
        private readonly AuthTokenOptions tokenOptions;

        protected UserService(
            IGametekiDbContext context,
            UserManager<GametekiUser> userManager,
            IOptions<AuthTokenOptions> optionsAccessor,
            IOptions<GametekiApiOptions> lobbyOptions,
            IEmailSender emailSender,
            IViewRenderService viewRenderService,
            ILogger<UserService> logger,
            IStringLocalizer<UserService> localizer)
        {
            if (lobbyOptions == null)
            {
                throw new ArgumentNullException(nameof(lobbyOptions));
            }

            if (optionsAccessor == null)
            {
                throw new ArgumentNullException(nameof(optionsAccessor));
            }

            this.context = context;
            this.userManager = userManager;
            apiOptions = lobbyOptions.Value;
            this.emailSender = emailSender;
            this.viewRenderService = viewRenderService;
            this.logger = logger;
            t = localizer;

            tokenOptions = optionsAccessor.Value;
        }

        public async Task<RegisterAccountResult> RegisterUserAsync(RegisterAccountRequest request, string ipAddress)
        {
            if (request == null)
            {
                throw new ArgumentNullException(nameof(request));
            }

            if (await IsEmailInUseAsync(request.Email).ConfigureAwait(false))
            {
                logger.LogDebug($"Request to register account with email '{request.Email}' already in use");
                return RegisterAccountResult.Failed(t["An account with that email already exists, please use another"], "email");
            }

            if (await IsUsernameInUseAsync(request.Username).ConfigureAwait(false))
            {
                logger.LogDebug($"Request to register account with name '{request.Username}' already in use");
                return RegisterAccountResult.Failed(t["An account with that name already exists, please choose another"], "username");
            }

            var newUser = new GametekiUser
            {
                Email = request.Email,
                UserName = request.Username,
                LockoutEnabled = true,
                RegisteredDate = DateTime.UtcNow,
                Settings = new UserSettings(),
                EmailHash = request.Email.Md5Hash(),
                RegisterIp = ipAddress,
                EmailConfirmed = !apiOptions.AccountVerification
            };

            try
            {
                var result = await userManager.CreateAsync(newUser, request.Password).ConfigureAwait(false);
                if (!result.Succeeded)
                {
                    var registerResult = new RegisterAccountResult
                    {
                        Success = false
                    };

                    logger.LogError($"Failed to register user '{newUser.UserName}': {result.Errors.Aggregate(string.Empty, (prev, error) => prev + $" ({error.Code}) - {error.Description}")}");

                    foreach (var error in result.Errors)
                    {
                        registerResult.Errors.Add(error.Code, error.Description);
                    }

                    return registerResult;
                }
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception ex)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                logger.LogError(ex, $"Failed to register user '{newUser.UserName}'");
                return RegisterAccountResult.Failed(t["An error occurred registering your account.  Please try again later"]);
            }

            return RegisterAccountResult.Succeeded(newUser);
        }

        public async Task<bool> SendActivationEmailAsync(GametekiUser user, AccountVerificationModel model)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (model == null)
            {
                throw new ArgumentNullException(nameof(model));
            }

            try
            {
                var code = await userManager.GenerateEmailConfirmationTokenAsync(user).ConfigureAwait(false);
                model.VerificationUrl =
                    new Uri(Microsoft.AspNetCore.WebUtilities.QueryHelpers.AddQueryString(model.VerificationUrl.ToString(), "token", code));

                var emailBody = await viewRenderService.RenderToStringAsync("Email/AccountVerification", model).ConfigureAwait(false);

                await emailSender.SendEmailAsync(user.Email, $"{apiOptions.ApplicationName} - Account activation", emailBody).ConfigureAwait(false);
            }
#pragma warning disable CA1031 // Do not catch general exception types
#pragma warning disable CA1303 // Do not pass literals as localized parameters
            catch (Exception ex)
            {
                logger.LogError(ex, "An error occurred sending account verification email");
#pragma warning restore CA1303 // Do not pass literals as localized parameters
#pragma warning restore CA1031 // Do not catch general exception types

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

            var user = await userManager.FindByIdAsync(userId).ConfigureAwait(false);
            if (user == null)
            {
                return false;
            }

            var result = await userManager.ConfirmEmailAsync(user, token).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return false;
            }

            return true;
        }

        public Task<LoginResult> LoginUserAsync(string username, string password, string ipAddress)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            return LoginUserInternalAsync(username, password, ipAddress);
        }

        public Task<RefreshToken> CreateRefreshTokenAsync(GametekiUser user, string ipAddress)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (ipAddress == null)
            {
                throw new ArgumentNullException(nameof(ipAddress));
            }

            return CreateRefreshTokenInternalAsync(user, ipAddress);
        }

        public virtual Task<GametekiUser> GetUserFromUsernameAsync(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException(nameof(username));
            }

            return GetUserFromUsernameInternalAsync(username);
        }

        public Task<LoginResult> RefreshTokenAsync(string token, string refreshToken, string ipAddress)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (refreshToken == null)
            {
                throw new ArgumentNullException(nameof(refreshToken));
            }

            return RefreshTokenInternalAsync(token, refreshToken, ipAddress);
        }

        public Task<RefreshToken> GetRefreshTokenByIdAsync(int tokenId)
        {
            return context.RefreshToken.SingleOrDefaultAsync(t => t.Id == tokenId);
        }

        public Task<bool> DeleteRefreshTokenAsync(RefreshToken token)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            return DeleteRefreshTokenInternalAsync(token);
        }

        public Task<bool> AddBlockListEntryAsync(GametekiUser user, string username)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (username == null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            return AddBlockListEntryInternalAsync(user, username);
        }

        public Task<bool> RemoveBlockListEntryAsync(GametekiUser user, string username)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (username == null)
            {
                throw new ArgumentNullException(nameof(username));
            }

            return RemoveBlockListEntryInternalAsync(username);
        }

        public Task<IdentityResult> UpdateUserAsync(GametekiUser user, string existingPassword = null, string newPassword = null)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return UpdateUserInternalAsync(user, existingPassword, newPassword);
        }

        public Task<bool> ClearRefreshTokensAsync(GametekiUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return ClearRefreshTokensInternalAsync(user);
        }

        public Task<bool> LogoutUserAsync(string token, string refreshToken)
        {
            if (token == null)
            {
                throw new ArgumentNullException(nameof(token));
            }

            if (refreshToken == null)
            {
                throw new ArgumentNullException(nameof(refreshToken));
            }

            return LogoutUserInternalAsync(token, refreshToken);
        }

        public Task<bool> UpdatePermissionsAsync(GametekiUser user, Permissions newPermissions)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (newPermissions == null)
            {
                throw new ArgumentNullException(nameof(newPermissions));
            }

            return UpdatePermissionsInternalAsync(user, newPermissions);
        }

        protected virtual async Task<GametekiUser> GetUserFromUsernameInternalAsync(string username)
        {
            return await context.Users
                .Include(u => u.RefreshTokens)
                .Include(u => u.BlockList)
                .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.User)
                .Include("UserRoles.Role")
                .SingleOrDefaultAsync(u => u.UserName == username).ConfigureAwait(false);
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

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using var rng = RandomNumberGenerator.Create();

            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private async Task<bool> UpdatePermissionsInternalAsync(GametekiUser user, Permissions newPermissions)
        {
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
                var role = await context.Roles.SingleOrDefaultAsync(r => r.Name == roleToAdd).ConfigureAwait(false);
                if (role == null)
                {
                    continue;
                }

                user.UserRoles.Add(new GametekiUserRole { Role = role, User = user });
            }

            foreach (var userRole in toRemove.Select(roleToRemove => user.UserRoles.Single(ur => ur.Role.Name == roleToRemove)))
            {
                user.UserRoles.Remove(userRole);
            }

            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException exception)
            {
#pragma warning disable CA1303 // Do not pass literals as localized parameters
                logger.LogError(exception, "Failed updating permissions");
#pragma warning restore CA1303 // Do not pass literals as localized parameters
                return false;
            }

            return true;
        }

        private async Task<bool> LogoutUserInternalAsync(string token, string refreshToken)
        {
            var claimsPrincipal = GetPrincipalFromExpiredToken(token);
            if (claimsPrincipal == null)
            {
                return false;
            }

            var dbToken = await context.RefreshToken
                .Include(rt => rt.User)
                .SingleOrDefaultAsync(rt => rt.User.UserName.Equals(claimsPrincipal.Identity.Name, StringComparison.InvariantCultureIgnoreCase) && rt.Token == refreshToken).ConfigureAwait(false);

            if (dbToken == null)
            {
                return false;
            }

            context.RefreshToken.Remove(dbToken);

            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException exception)
            {
#pragma warning disable CA1303 // Do not pass literals as localized parameters
                logger.LogError(exception, "Failed to remove refresh token");
#pragma warning restore CA1303 // Do not pass literals as localized parameters

                return false;
            }

            return true;
        }

        private async Task<bool> ClearRefreshTokensInternalAsync(GametekiUser user)
        {
            user.RefreshTokens.Clear();

            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException exception)
            {
                logger.LogError(exception, $"Error clearing refresh tokens for user {user.UserName}");
                return false;
            }

            return true;
        }

        private async Task<bool> RemoveBlockListEntryInternalAsync(string username)
        {
            try
            {
                var blockListEntry = await context.BlockListEntry.SingleOrDefaultAsync(bl => bl.BlockedUser.Equals(username, StringComparison.InvariantCultureIgnoreCase)).ConfigureAwait(false);

                context.BlockListEntry.Remove(blockListEntry);

                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException ex)
            {
                logger.LogError($"Error deleting block list entry '{username}'", ex);

                return false;
            }

            return true;
        }

        private async Task<RefreshToken> CreateRefreshTokenInternalAsync(GametekiUser user, string ipAddress)
        {
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

                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException ex)
            {
                logger.LogError($"Error creating refresh token for {user.UserName} ({ipAddress})", ex);
                return null;
            }

            return token;
        }

        private async Task<bool> DeleteRefreshTokenInternalAsync(RefreshToken token)
        {
            try
            {
                context.RefreshToken.Remove(token);
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException ex)
            {
                logger.LogError($"Error deleting refresh token: {token.Id}/{token.Token}", ex);
                return false;
            }

            return true;
        }

        private async Task<bool> AddBlockListEntryInternalAsync(GametekiUser user, string username)
        {
            var blockListEntry = new BlockListEntry
            {
                BlockedUser = username,
                UserId = user.Id
            };

            try
            {
                context.BlockListEntry.Add(blockListEntry);
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException ex)
            {
                logger.LogError($"Error adding block list entry '{username}' for {user.UserName}", ex);
                return false;
            }

            return true;
        }

        private async Task<IdentityResult> UpdateUserInternalAsync(GametekiUser user, string existingPassword, string newPassword)
        {
            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException exception)
            {
#pragma warning disable CA1303 // Do not pass literals as localized parameters
                logger.LogError(exception, "Error updating user");
#pragma warning restore CA1303 // Do not pass literals as localized parameters
                return IdentityResult.Failed(new IdentityError { Code = "Internal Error", Description = t["An error occurred saving your profile.  Please try again later"] });
            }

            if (existingPassword == null || newPassword == null)
            {
                return IdentityResult.Success;
            }

            var result = await userManager.ChangePasswordAsync(user, existingPassword, newPassword).ConfigureAwait(false);

            return !result.Succeeded ? result : IdentityResult.Success;
        }

        private async Task<LoginResult> RefreshTokenInternalAsync(string token, string refreshToken, string ipAddress)
        {
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
                .SingleOrDefaultAsync(rt => rt.User.UserName == claimsPrincipal.Identity.Name && rt.Token == refreshToken).ConfigureAwait(false);

            if (dbToken == null)
            {
                return null;
            }

            var result = await UpdateRefreshTokenUsage(dbToken, ipAddress).ConfigureAwait(false);
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

        private async Task<LoginResult> LoginUserInternalAsync(string username, string password, string ipAddress)
        {
            var user = await GetUserFromUsernameAsync(username).ConfigureAwait(false);
            if (user == null)
            {
                return null;
            }

            if (user.Disabled)
            {
                return null;
            }

            var isPasswordCorrect = await userManager.CheckPasswordAsync(user, password).ConfigureAwait(false);
            if (!isPasswordCorrect)
            {
                return null;
            }

            var refreshToken = await CreateRefreshTokenAsync(user, ipAddress).ConfigureAwait(false);
            var result = new LoginResult
            {
                Token = GenerateTokenForUser(user),
                User = user,
                RefreshToken = refreshToken.Token
            };

            user.LastLoginDate = DateTime.UtcNow;

            await context.SaveChangesAsync().ConfigureAwait(false);

            return result;
        }

        private Task<bool> IsUsernameInUseAsync(string username)
        {
            return context.Users.AnyAsync(u => u.UserName == username);
        }

        private Task<bool> IsEmailInUseAsync(string email)
        {
            return context.Users.AnyAsync(u => u.Email == email);
        }

        private string GenerateTokenForUser(GametekiUser user)
        {
            var claims = new List<Claim> { new Claim(ClaimTypes.Name, user.UserName) };

            claims.AddRange(user.UserRoles.Select(ur => new Claim(ClaimTypes.Role, ur.Role.Name)));

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokenOptions.Key));
            var jwt = new JwtSecurityToken(
                tokenOptions.Issuer,
                tokenOptions.Issuer,
                claims,
                DateTime.UtcNow,
                DateTime.UtcNow.AddMinutes(5),
                new SigningCredentials(key, SecurityAlgorithms.HmacSha256))
            {
                Payload = { ["UserData"] = user.ToApiUser(), ["BlockList"] = user.BlockList }
            };

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        private async Task<bool> UpdateRefreshTokenUsage(RefreshToken token, string ipAddress)
        {
            token.IpAddress = ipAddress;
            token.LastUsed = DateTime.UtcNow;
            token.Expires = DateTime.UtcNow.AddDays(TokenExpiry);

            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException)
            {
                return false;
            }

            return true;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Validate token can throw too many exception types")]
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
