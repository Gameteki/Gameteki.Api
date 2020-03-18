namespace CrimsonDev.Gameteki.Api.ApiControllers
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Claims;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data.Models;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using CrimsonDev.Gameteki.Data.Models.Config;
    using CrimsonDev.Gameteki.Data.Models.Patreon;
    using Microsoft.AspNetCore.Authentication;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Localization;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using SixLabors.ImageSharp;
    using SixLabors.ImageSharp.Processing;

    [ApiController]
    [Route("api/[controller]")]
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "ASP.NET will ensure this is not null")]
    public class AccountController : ControllerBase
    {
        private readonly IUserService userService;
        private readonly IHttpClient httpClient;
        private readonly ILogger<AccountController> logger;
        private readonly IStringLocalizer<AccountController> t;
        private readonly IPatreonService patreonService;
        private readonly GametekiApiOptions apiOptions;

        public AccountController(
            IUserService userService,
            IHttpClient httpClient,
            IOptions<GametekiApiOptions> options,
            ILogger<AccountController> logger,
            IStringLocalizer<AccountController> localizer,
            IPatreonService patreonService)
        {
            this.userService = userService;
            this.httpClient = httpClient;
            this.logger = logger;
            t = localizer;
            this.patreonService = patreonService;

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            apiOptions = options.Value;
        }

/*

        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<ApiResponse>> RegisterAccount(RegisterAccountRequest request)
        {
            var result = await userService.RegisterUserAsync(request, HttpContext.Connection.RemoteIpAddress.ToString()).ConfigureAwait(false);

            if (!result.Success)
            {
                logger.LogError($"Failed to register account {result.Errors.Aggregate(string.Empty, (prev, error) => prev + $" {error.Value}")}");

                foreach (var (field, message) in result.Errors)
                {
                    ModelState.AddModelError(field, message);
                }

                return BadRequest(ModelState);
            }

            if (apiOptions.AccountVerification)
            {
                var callbackUrl = new Uri($"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/activation?id={result.User.Id}");
                var verificationModel = new AccountVerificationModel
                {
                    VerificationUrl = callbackUrl,
                    SiteUrl = new Uri($"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}")
                };

                var emailResult = await userService.SendActivationEmailAsync(result.User, verificationModel).ConfigureAwait(false);
                if (!emailResult)
                {
                    logger.LogError($"Error sending activation email for {result.User.UserName}");
                }
            }

            var stringToHash = GetRandomString(32);
            await httpClient.DownloadFileAsync(new Uri($"https://www.gravatar.com/avatar/{stringToHash}?d=identicon&s=24"), Path.Combine(apiOptions.ImagePath, "avatar", $"{result.User.UserName}.png")).ConfigureAwait(false);

            logger.LogDebug($"Registered new account: '{result.User.UserName}'");

            return this.SuccessResponse(apiOptions.AccountVerification
                ? t["Your account was successfully registered, please verify your account using the link in the email sent to the address you have provided"]
                : t["Your account was successfully registered"]);
        }*/

/*        [HttpPost]
        [Route("api/account/activate")]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<ApiResponse>> ActivateAccount(VerifyAccountRequest request)
        {
            var result = await userService.ValidateUserAsync(request.Id, request.Token).ConfigureAwait(false);

            if (!result)
            {
                logger.LogError($"Error verifying {request.Id}");
                return this.FailureResponse(t["An error occurred validating your account.  Please check the URL is entered correctly and try again."]);
            }

            logger.LogDebug($"Verified account id '{request.Id}'");
            return this.SuccessResponse();
        }*/

/*        [HttpPost("login")]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<ApiResponse>> Login(LoginRequest request)
        {
            var result = await userService.LoginUserAsync(request.Username, request.Password, HttpContext.Connection.RemoteIpAddress.ToString()).ConfigureAwait(false);

            if (result == null)
            {
                logger.LogWarning($"AUTH: Failed login attempt for ${request.Username}");
                return Unauthorized();
            }

/*            if (!result.User.EmailConfirmed)
            {
                logger.LogWarning($"AUTH: Failed login attempt for ${request.Username} (Email not confirmed)");
                return this.FailureResponse(t["You must verify your account before trying to log in.  Please see the email we sent you for more details."]);
            }#1#

            var response = new LoginResponse
            {
                Success = true,
                User = result.User.ToApiUser(),
                Token = result.Token
            };

            logger.LogInformation($"AUTH: Successful login for {request.Username}");
            return response;
        }*/

        [HttpPost("logout")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<ApiResponse>> Logout(LogoutRequest request)
        {
            var authResult = await HttpContext.AuthenticateAsync().ConfigureAwait(false);
            var token = authResult.Properties.GetString(".Token.access_token");

            var result = await userService.LogoutUserAsync(token).ConfigureAwait(false);

            if (!result)
            {
                logger.LogWarning($"AUTH: Failed logout for user '{User.Identity.Name}', tokens '{request}'");
                return this.FailureResponse(t["An error occurred logging you out.  Please try again later."]);
            }

            logger.LogInformation($"AUTH: Logout succeeded for user '{User.Identity.Name}'");
            return this.SuccessResponse(t["You have been logged out"]);
        }

        [HttpPost("checkauth")]
        [Authorize]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<ActionResult<ApiResponse>> CheckAuth()
        {
            var userId = User.FindFirstValue("sub");

            var user = await userService.CreateOrUpdateUserAsync(userId, User.FindFirstValue("name"), User.FindFirstValue("email")).ConfigureAwait(false);

            logger.LogDebug($"Check auth succeeded for {User.Identity.Name}");

            if (user.PatreonToken == null)
            {
                return new CheckAuthResponse { Success = true, User = user.ToApiUser() };
            }

            if (user.PatreonToken.Expiry >= DateTime.UtcNow)
            {
                var token = await patreonService.RefreshTokenAsync(user.PatreonToken.RefreshToken)
                    .ConfigureAwait(false);

                if (token == null)
                {
                    return new CheckAuthResponse { Success = true, User = user.ToApiUser() };
                }

                user.PatreonToken = new PatreonToken
                {
                    Token = token.AccessToken,
                    RefreshToken = token.RefreshToken,
                    Expiry = DateTime.UtcNow.AddSeconds(token.ExpiresIn)
                };

                await userService.UpdateUserAsync().ConfigureAwait(false);
            }

            var apiUser = user.ToApiUser();
            apiUser.PatreonStatus = await patreonService.GetUserStatus(user.PatreonToken.Token).ConfigureAwait(false);

            return new CheckAuthResponse { Success = true, User = apiUser };
        }

        [HttpPut("{username}")]
        [Authorize]
        public async Task<ActionResult<ApiResponse>> UpdateProfile(string username, [FromBody] UpdateProfileRequest request)
        {
            if (username != User.Identity.Name)
            {
                logger.LogWarning($"Attempt to update profile for wrong user: '{username}' != '{User.Identity.Name}'");
                return NotFound();
            }

            var user = await userService.GetUserFromUsernameAsync(username).ConfigureAwait(false);

            if (user == null)
            {
                logger.LogWarning($"Attempt to update profile for unknown user: '{username}'");
                return NotFound();
            }

            if (request.Avatar != null)
            {
                await using var avatarStream = new MemoryStream(request.Avatar);

                using var image = Image.Load(avatarStream);

                image.Mutate(a => a.Resize(24, 24));

                Directory.CreateDirectory(Path.Combine(apiOptions.ImagePath, "avatar"));
                image.Save(Path.Combine(apiOptions.ImagePath, "avatar", $"{user.UserName}.png"));
            }
            else if (user.Email != request.Email)
            {
                var stringToHash = GetRandomString(32);

                await httpClient.DownloadFileAsync(new Uri($"https://www.gravatar.com/avatar/{stringToHash}?d=identicon&s=24"), Path.Combine(apiOptions.ImagePath, "avatar", $"{user.UserName}.png")).ConfigureAwait(false);
            }

            user.Email = request.Email;
            user.EmailHash = request.Email.Md5Hash();
            user.Settings.Background = request.Settings.Background;
            user.Settings.CardSize = request.Settings.CardSize;
            user.CustomData = request.CustomData;

            var result = await userService.UpdateUserAsync().ConfigureAwait(false);
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }

                return BadRequest(ModelState);
            }

            if (request.CurrentPassword == null || request.NewPassword == null)
            {
                return new UpdateProfileResponse
                {
                    Success = true,
                    User = user.ToApiUser()
                };
            }

            return new UpdateProfileResponse
            {
                Success = true,
                User = user.ToApiUser()
            };
        }

        [Authorize]
        [HttpGet("blocklist")]
        public async Task<ActionResult<GetBlockListResponse>> GetBlockList()
        {
            var username = User.Identity.Name;

            var user = await userService.GetUserFromUsernameAsync(username).ConfigureAwait(false);
            if (user == null)
            {
                logger.LogWarning($"Attempt to get blocklist for unknown user '{username}'");
                return NotFound();
            }

            logger.LogDebug($"Returned block list for user '{username}'");
            var response = new GetBlockListResponse { Success = true };
            response.BlockList.AddRange(user.BlockList.Select(bl => bl.BlockedUser).ToList());

            return response;
        }

        [Authorize]
        [HttpPut("blocklist/{entry}")]
        public async Task<ActionResult<ApiResponse>> AddBlockListEntry(string entry)
        {
            var username = User.Identity.Name;

            var user = await userService.GetUserFromUsernameAsync(username).ConfigureAwait(false);
            if (user == null)
            {
                logger.LogWarning($"Attempt to add blocklist entry for unknown user '{username}'");
                return NotFound();
            }

            if (user.BlockList.Any(bl => bl.BlockedUser == entry))
            {
                return this.FailureResponse(t["The block list already contains this user."]);
            }

            var result = await userService.AddBlockListEntryAsync(user, entry).ConfigureAwait(false);
            if (!result)
            {
                logger.LogError($"Error adding blocklist entry for user '{username}' ({entry}'");
                return this.FailureResponse(t["An error occurred adding the block list entry."]);
            }

            logger.LogDebug($"Added blocklist entry '{entry}' to user '{username}'");
            return new BlockListEntryResponse
            {
                Success = true,
                Username = entry,
                Message = t["Blocklist entry added successfully"]
            };
        }

        [Authorize]
        [HttpDelete("blocklist/{blockedUsername}")]
        public async Task<ActionResult<ApiResponse>> RemoveBlockListEntry(string blockedUsername)
        {
            var username = User.Identity.Name;

            var user = await userService.GetUserFromUsernameAsync(username).ConfigureAwait(false);
            if (user == null)
            {
                logger.LogWarning($"Attempt to remove blocklist entry for unknown user '{username}'");

                return NotFound();
            }

            if (user.BlockList.All(bl => bl.BlockedUser != blockedUsername))
            {
                return NotFound();
            }

            var result = await userService.RemoveBlockListEntryAsync(user, blockedUsername).ConfigureAwait(false);
            if (!result)
            {
                logger.LogWarning($"Error removing blocklist entry for user '{username}' ({blockedUsername})");

                return this.FailureResponse(t["An error occurred removing the block list entry."]);
            }

            logger.LogDebug($"Removed blocklist entry '{blockedUsername}' for user '{username}'");

            return new BlockListEntryResponse
            {
                Success = true,
                Username = blockedUsername,
                Message = t["Blocklist entry deleted successfully"]
            };
        }

        [HttpPost("linkPatreon")]
        [Authorize]
        public async Task<ActionResult<ApiResponse>> LinkPatreon(PatreonLinkRequest request)
        {
            var callbackUrl = new Uri($"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/patreon");
            var username = User.Identity.Name;

            var user = await userService.GetUserFromUsernameAsync(username).ConfigureAwait(false);
            if (user == null)
            {
                logger.LogWarning($"Attempt to remove blocklist entry for unknown user '{username}'");

                return NotFound();
            }

            var patreonToken =
                await patreonService.LinkAccountAsync(request.AuthCode, callbackUrl).ConfigureAwait(false);

            if (patreonToken == null)
            {
                logger.LogError($"Failed to link patreon account for {username}");
                return this.FailureResponse(
                    t["An error occured while linking your patreon account.  Please try again later"]);
            }

            user.PatreonToken = new PatreonToken
            {
                Token = patreonToken.AccessToken,
                RefreshToken = patreonToken.RefreshToken,
                Expiry = DateTime.UtcNow.AddSeconds(patreonToken.ExpiresIn)
            };

            await userService.UpdateUserAsync().ConfigureAwait(false);
            var patreonStatus = await patreonService.GetUserStatus(user.PatreonToken.Token).ConfigureAwait(false);

            var permissions = user.ToApiUser().Permissions;

            permissions.IsSupporter = patreonStatus == PatreonStatus.Pledged;

            await userService.UpdatePermissionsAsync(user, permissions).ConfigureAwait(false);

            return this.SuccessResponse();
        }

        private static string GetRandomString(int charCount)
        {
            var randomNumber = new byte[charCount];
            using var rng = RandomNumberGenerator.Create();

            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
    }
}
