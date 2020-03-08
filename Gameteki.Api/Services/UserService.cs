namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Text;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models;
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
        private readonly IGametekiDbContext context;
        private readonly GametekiApiOptions apiOptions;
        private readonly IEmailSender emailSender;
        private readonly IViewRenderService viewRenderService;
        private readonly ILogger<UserService> logger;
        private readonly IStringLocalizer<UserService> t;
        private readonly AuthTokenOptions tokenOptions;

        protected UserService(
            IGametekiDbContext context,
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
            apiOptions = lobbyOptions.Value;
            this.emailSender = emailSender;
            this.viewRenderService = viewRenderService;
            this.logger = logger;
            t = localizer;

            tokenOptions = optionsAccessor.Value;
        }

        /*public async Task<RegisterAccountResult> RegisterUserAsync(RegisterAccountRequest request, string ipAddress)
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
                RegisteredDate = DateTime.UtcNow,
                Settings = new UserSettings(),
                EmailHash = request.Email.Md5Hash(),
                RegisterIp = ipAddress
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
        }*/

        /*public async Task<bool> SendActivationEmailAsync(GametekiUser user, AccountVerificationModel model)
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
        }*/

/*        public async Task<bool> ValidateUserAsync(string userId, string token)
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
        }*/

/*        public Task<LoginResult> LoginUserAsync(string username, string password, string ipAddress)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException(nameof(username));
            }

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            return LoginUserInternalAsync(username, password);
        }*/

        public Task<GametekiUser> GetUserFromIdAsync(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                throw new ArgumentNullException(nameof(userId));
            }

            return GetUserFromIdInternalAsync(userId);
        }

        public virtual Task<GametekiUser> GetUserFromUsernameAsync(string username)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentNullException(nameof(username));
            }

            return GetUserFromUsernameInternalAsync(username);
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

        public Task<IdentityResult> UpdateUserAsync()
        {
            return UpdateUserInternalAsync();
        }

        public Task<bool> LogoutUserAsync(string token)
        {
            return LogoutUserInternalAsync(token);
        }

        public Task<bool> UpdatePermissionsAsync(GametekiUser user, GametekiPermissions newPermissions)
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

        public async Task<GametekiUser> CreateOrUpdateUserAsync(string userId, string username, string email)
        {
            var user = await context.Users.Include(u => u.UserRoles).Include(u => u.BlockList).Include(u => u.PatreonToken).FirstOrDefaultAsync(u => u.ExternalId == userId)
                           .ConfigureAwait(false) ?? new GametekiUser
                       {
                           ExternalId = userId,
                           LastLoginDate = DateTime.UtcNow,
                           RegisteredDate = DateTime.UtcNow,
                           Settings = new UserSettings()
                       };

            if (user.Id == 0)
            {
                user = (await context.Users.AddAsync(user).ConfigureAwait(false)).Entity;
            }

            user.LastLoginDate = DateTime.UtcNow;
            user.UserName = username;
            user.Email = email;
            user.EmailHash = email.Md5Hash();

            await context.SaveChangesAsync().ConfigureAwait(false);

            return user;
        }

        protected virtual async Task<GametekiUser> GetUserFromIdInternalAsync(string userId)
        {
            return await context.Users
                .Include(u => u.PatreonToken)
                .Include(u => u.BlockList)
                .Include(u => u.UserRoles)
                .ThenInclude(ur => ur.User)
                .Include("UserRoles.Role")
                .SingleOrDefaultAsync(u => u.ExternalId == userId).ConfigureAwait(false);
        }

        protected virtual async Task<GametekiUser> GetUserFromUsernameInternalAsync(string username)
        {
            return await context.Users
                .Include(u => u.PatreonToken)
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

        private async Task<bool> UpdatePermissionsInternalAsync(GametekiUser user, GametekiPermissions newPermissions)
        {
            var existingPermissions = user.ToApiUser().GametekiPermissions;
            var toAdd = new List<string>();
            var toRemove = new List<string>();

            ProcessPermission(newPermissions.CanEditNews, existingPermissions.CanEditNews, Roles.NewsManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanManageGames, existingPermissions.CanManageGames, Roles.GameManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanManageNodes, existingPermissions.CanManageNodes, Roles.NodeManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanManagePermissions, existingPermissions.CanManagePermissions, Roles.PermissionsManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanManageUsers, existingPermissions.CanManageUsers, Roles.UserManager, toRemove, toAdd);
            ProcessPermission(newPermissions.CanModerateChat, existingPermissions.CanModerateChat, Roles.ChatManager, toRemove, toAdd);
            ProcessPermission(newPermissions.IsSupporter, existingPermissions.IsSupporter, Roles.Supporter, toRemove, toAdd);
            ProcessPermission(newPermissions.IsContributor, existingPermissions.IsContributor, Roles.Contributor, toRemove, toAdd);
            ProcessPermission(newPermissions.IsAdmin, existingPermissions.IsAdmin, Roles.Admin, toRemove, toAdd);

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

        private async Task<bool> LogoutUserInternalAsync(string token)
        {
            var claimsPrincipal = GetPrincipalFromExpiredToken(token);
            if (claimsPrincipal == null)
            {
                return false;
            }

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

        private async Task<bool> RemoveBlockListEntryInternalAsync(string username)
        {
            try
            {
                var blockListEntry = await context.BlockListEntry.SingleOrDefaultAsync(bl => bl.BlockedUser == username)
                    .ConfigureAwait(false);

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

        private async Task<IdentityResult> UpdateUserInternalAsync()
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

            // if (existingPassword == null || newPassword == null)
            // {
            return IdentityResult.Success;

            // }
        }

/*        private async Task<LoginResult> LoginUserInternalAsync(string username, string password)
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

            var result = new LoginResult
            {
                Token = GenerateTokenForUser(user),
                User = user
            };

            user.LastLoginDate = DateTime.UtcNow;

            await context.SaveChangesAsync().ConfigureAwait(false);

            return result;
        }*/

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
                Payload = { ["UserData"] = user.ToApiUser() }
            };

            return new JwtSecurityTokenHandler().WriteToken(jwt);
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
