namespace CrimsonDev.Gameteki.Api.ApiControllers
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using CrimsonDev.Gameteki.Data.Models.Config;
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
    public class AccountController : ControllerBase
    {
        private readonly IUserService userService;
        private readonly IHttpClient httpClient;
        private readonly ILogger<AccountController> logger;
        private readonly IStringLocalizer<AccountController> t;
        private readonly GametekiApiOptions apiOptions;

        public AccountController(
            IUserService userService,
            IHttpClient httpClient,
            IOptions<GametekiApiOptions> options,
            ILogger<AccountController> logger,
            IStringLocalizer<AccountController> localizer)
        {
            this.userService = userService;
            this.httpClient = httpClient;
            this.logger = logger;
            t = localizer;

            apiOptions = options.Value;
        }

        [HttpPost("register")]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status200OK)]
        public async Task<IActionResult> RegisterAccount(RegisterAccountRequest request)
        {
            var result = await userService.RegisterUserAsync(request, HttpContext.Connection.RemoteIpAddress.ToString());

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
                var callbackUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/activation?id={result.User.Id}";
                var verificationModel = new AccountVerificationModel
                {
                    VerificationUrl = callbackUrl,
                    SiteUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}"
                };

                var emailResult = await userService.SendActivationEmailAsync(result.User, verificationModel);
                if (!emailResult)
                {
                    logger.LogError($"Error sending activation email for {result.User.UserName}");
                }
            }

            var stringToHash = GetRandomString(32);
            await httpClient.DownloadFileAsync($"https://www.gravatar.com/avatar/{stringToHash}?d=identicon&s=24", Path.Combine(apiOptions.ImagePath, "avatar", $"{result.User.UserName}.png"));

            logger.LogDebug($"Registered new account: '{result.User.UserName}'");

            return this.SuccessResponse(apiOptions.AccountVerification ?
                t["Your account was successfully registered, please verify your account using the link in the email sent to the address you have provided"] :
                t["Your account was successfully registered"]);
        }

        [HttpPost]
        [Route("api/account/activate")]
        public async Task<IActionResult> ActivateAccount(VerifyAccountRequest request)
        {
            var result = await userService.ValidateUserAsync(request.Id, request.Token);

            if (!result)
            {
                logger.LogError($"Error verifying {request.Id}");
                return this.FailureResponse(t["An error occurred validating your account.  Please check the URL is entered correctly and try again."]);
            }

            logger.LogDebug($"Verified account id '{request.Id}'");
            return this.SuccessResponse();
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginRequest request)
        {
            var result = await userService.LoginUserAsync(request.Username, request.Password, HttpContext.Connection.RemoteIpAddress.ToString());

            if (result == null)
            {
                logger.LogWarning($"AUTH: Failed login attempt for ${request.Username}");
                return Unauthorized();
            }

            if (!result.User.EmailConfirmed)
            {
                logger.LogWarning($"AUTH: Failed login attempt for ${request.Username} (Email not confirmed)");
                return this.FailureResponse(t["You must verify your account before trying to log in.  Please see the email we sent you for more details."]);
            }

            var response = new LoginResponse
            {
                Success = true,
                User = result.User.ToApiUser(),
                Token = result.Token,
                RefreshToken = result.RefreshToken
            };

            logger.LogInformation($"AUTH: Successful login for {request.Username}");
            return Ok(response);
        }

        [Route("api/account/logout")]
        [Authorize]
        public async Task<IActionResult> Logout(RefreshTokenRequest request)
        {
            var result = await userService.LogoutUserAsync(request.Token, request.RefreshToken);

            if (!result)
            {
                logger.LogWarning($"AUTH: Failed logout for user '{User.Identity.Name}', tokens '{request.Token}' '{request.RefreshToken}'");
                return this.FailureResponse(t["An error occurred logging you out.  Please try again later."]);
            }

            logger.LogInformation($"AUTH: Logout succeeded for user '{User.Identity.Name}'");
            return this.SuccessResponse();
        }

        [HttpPost("checkauth")]
        [Authorize]
        public async Task<IActionResult> CheckAuth()
        {
            var user = await userService.GetUserFromUsernameAsync(User.Identity.Name);

            if (user != null)
            {
                logger.LogDebug($"Check auth succeeded for {User.Identity.Name}");
                return Ok(new CheckAuthResponse { Success = true, User = user.ToApiUser() });
            }

            logger.LogWarning($"AUTH: Failed check auth for '{User.Identity.Name}'");
            return this.FailureResponse(t["An error occurred.  Please try again later."]);
        }

        [HttpPost("token")]
        public async Task<IActionResult> GetNewToken(RefreshTokenRequest request)
        {
            var result = await userService.RefreshTokenAsync(
                request.Token,
                request.RefreshToken,
                HttpContext.Connection.RemoteIpAddress.ToString());
            if (result == null)
            {
                logger.LogWarning(
                    $"AUTH: Failed token refresh for '{User.Identity.Name}' token '{request.Token}' " +
                    $"and refresh token '{request.RefreshToken}'");
                return this.FailureResponse(t["An error occurred refreshing your token.  Please try again later."]);
            }

            logger.LogDebug(
                $"Successful token refresh for '{result.User.UserName}' using token '{request.Token} " +
                $"and refresh token '{request.RefreshToken}'");
            return Ok(new LoginResponse
            {
                Success = true,
                RefreshToken = result.RefreshToken,
                Token = result.Token,
                User = result.User.ToApiUser()
            });
        }

        [HttpPut("{username}")]
        [Authorize]
        public async Task<IActionResult> UpdateProfile(string username, [FromBody] UpdateProfileRequest request)
        {
            if (username != User.Identity.Name)
            {
                logger.LogWarning($"Attempt to update profile for wrong user: '{username}' != '{User.Identity.Name}'");
                return NotFound();
            }

            var user = await userService.GetUserFromUsernameAsync(username);

            if (user == null)
            {
                logger.LogWarning($"Attempt to update profile for unknown user: '{username}'");
                return NotFound();
            }

            if (request.Avatar != null)
            {
                var avatarStream = new MemoryStream(request.Avatar);

                using var image = Image.Load(avatarStream);

                image.Mutate(a => a.Resize(24, 24));

                image.Save(Path.Combine(apiOptions.ImagePath, "avatar", $"{user.UserName}.png"));
            }
            else if (user.Email != request.Email)
            {
                var stringToHash = GetRandomString(32);

                await httpClient.DownloadFileAsync($"https://www.gravatar.com/avatar/{stringToHash}?d=identicon&s=24", Path.Combine(apiOptions.ImagePath, "avatar", $"{user.UserName}.png"));
            }

            user.Email = request.Email;
            user.EmailHash = request.Email.Md5Hash();
            user.Settings.Background = request.Settings.Background;
            user.Settings.CardSize = request.Settings.CardSize;
            user.CustomData = request.CustomData;

            var result = await userService.UpdateUserAsync(user, request.CurrentPassword, request.NewPassword);
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
                return Ok(new UpdateProfileResponse
                {
                    Success = true,
                    User = user.ToApiUser(),
                    Token = null
                });
            }

            var clearResult = await userService.ClearRefreshTokensAsync(user);
            if (!clearResult)
            {
                return this.FailureResponse(t["An error occurred saving your profile.  Please try again later."]);
            }

            var newToken = await userService.CreateRefreshTokenAsync(user, HttpContext.Connection.RemoteIpAddress.ToString());
            if (newToken == null)
            {
                return this.FailureResponse(t["An error occurred saving your profile.  Please try again later."]);
            }

            return Ok(new UpdateProfileResponse
            {
                Success = true,
                User = user.ToApiUser(),
                Token = newToken
            });
        }

        [Route("api/account/{username}/sessions")]
        [Authorize]
        public async Task<IActionResult> GetUserSessions(string username)
        {
            if (username != User.Identity.Name)
            {
                logger.LogWarning($"Attempt to get user sessions for wrong user: '{username}' != '{User.Identity.Name}'");
                return NotFound();
            }

            var user = await userService.GetUserFromUsernameAsync(username);
            if (user == null)
            {
                logger.LogWarning($"Attempt to get user sessions for unknown user: '{username}'");
                return NotFound();
            }

            logger.LogDebug($"Returning user sessions for {username}");
            return Ok(new GetUserSessionsResponse
            {
                Success = true,
                Tokens = user.RefreshTokens.Select(rt => rt.ToApiToken()).ToList()
            });
        }

        [Route("api/account/{username}/sessions/{sessionId}")]
        [Authorize]
        [HttpDelete]
        public async Task<IActionResult> DeleteUserSession(string username, int sessionId)
        {
            if (username != User.Identity.Name)
            {
                logger.LogWarning($"Attempt to delete user session for wrong user: '{username}' != '{User.Identity.Name}'");

                return NotFound();
            }

            var refreshToken = await userService.GetRefreshTokenByIdAsync(sessionId);
            if (refreshToken == null)
            {
                logger.LogWarning($"Attempt to delete unknown user session: '{username}' ({sessionId})");

                return NotFound();
            }

            var result = await userService.DeleteRefreshTokenAsync(refreshToken);
            if (!result)
            {
                logger.LogError($"Failed to delete session '{sessionId}' for user {username}");
                return this.FailureResponse(t["An error occurred deleting the session.  Please try again later."]);
            }

            logger.LogDebug($"Deleted session '{sessionId}' for user '{username}'");
            return Ok(new DeleteSessionResponse
            {
                Success = true,
                TokenId = refreshToken.Id,
                Message = t["Session deleted successfully"]
            });
        }

        [Route("api/account/{username}/blocklist")]
        [Authorize]
        [HttpGet]
        public async Task<IActionResult> GetBlockList(string username)
        {
            if (username != User.Identity.Name)
            {
                logger.LogWarning($"Attempt to get blocklist for wrong user: '{username}' != '{User.Identity.Name}'");
                return NotFound();
            }

            var user = await userService.GetUserFromUsernameAsync(username);
            if (user == null)
            {
                logger.LogWarning($"Attempt to get blocklist for unknown user '{username}'");
                return NotFound();
            }

            logger.LogDebug($"Returned block list for user '{username}'");
            return Ok(new GetBlockListResponse { Success = true, BlockList = user.BlockList.Select(bl => bl.BlockedUser).ToList() });
        }

        [Route("api/account/{username}/blocklist")]
        [Authorize]
        [HttpPost]
        public async Task<IActionResult> AddBlockListEntry(string username, BlockListEntryRequest request)
        {
            if (username != User.Identity.Name)
            {
                logger.LogWarning($"Attempt to add blocklist entry for wrong user: '{username}' != '{User.Identity.Name}'");
                return NotFound();
            }

            var user = await userService.GetUserFromUsernameAsync(username);
            if (user == null)
            {
                logger.LogWarning($"Attempt to add blocklist entry for unknown user '{username}'");
                return NotFound();
            }

            if (user.BlockList.Any(bl => bl.BlockedUser.Equals(request.Username, StringComparison.InvariantCultureIgnoreCase)))
            {
                return this.FailureResponse(t["The block list already contains this user."]);
            }

            var result = await userService.AddBlockListEntryAsync(user, request.Username);
            if (!result)
            {
                logger.LogError($"Error adding blocklist entry for user '{username}' ({request.Username}'");
                return this.FailureResponse(t["An error occurred adding the block list entry."]);
            }

            logger.LogDebug($"Added blocklist entry '{request.Username}' to user '{username}'");
            return Ok(new BlockListEntryResponse
            {
                Success = true,
                Username = request.Username
            });
        }

        [Route("api/account/{username}/blocklist/{blockedUsername}")]
        [Authorize]
        [HttpDelete]
        public async Task<IActionResult> RemoveBlockListEntry(string username, string blockedUsername)
        {
            if (username != User.Identity.Name)
            {
                logger.LogWarning($"Attempt to remove blocklist entry for wrong user: '{username}' != '{User.Identity.Name}'");

                return NotFound();
            }

            var user = await userService.GetUserFromUsernameAsync(username);
            if (user == null)
            {
                logger.LogWarning($"Attempt to remove blocklist entry for unknown user '{username}'");

                return NotFound();
            }

            if (!user.BlockList.Any(bl => bl.BlockedUser.Equals(blockedUsername, StringComparison.InvariantCultureIgnoreCase)))
            {
                return NotFound();
            }

            var result = await userService.RemoveBlockListEntryAsync(user, blockedUsername);
            if (!result)
            {
                logger.LogWarning($"Error removing blocklist entry for user '{username}' ({blockedUsername})");

                return this.FailureResponse(t["An error occurred removing the block list entry."]);
            }

            logger.LogDebug($"Removed blocklist entry '{blockedUsername}' for user '{username}'");

            return Ok(new BlockListEntryResponse
            {
                Success = true,
                Username = blockedUsername
            });
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
