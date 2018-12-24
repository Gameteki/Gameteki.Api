namespace CrimsonDev.Gameteki.Api.ApiControllers
{
    using System;
    using System.Linq;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Api.Services;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;

    [ApiController]
    public class AccountController : Controller
    {
        private readonly IUserService userService;
        private readonly ILogger<AccountController> logger;

        public AccountController(IUserService userService, ILogger<AccountController> logger)
        {
            this.userService = userService;
            this.logger = logger;
        }

        [HttpPost]
        [Route("api/account/register")]
        public async Task<IActionResult> RegisterAccount(Models.Api.Request.RegisterAccountRequest request)
        {
            if (await userService.IsEmailInUseAsync(request.Email))
            {
                ModelState.AddModelError("email", "An account with that email already exists, please use another.");
                logger.LogDebug($"Request to register account with email '{request.Email}' already in use");
            }

            if (await userService.IsUsernameInUseAsync(request.Username))
            {
                ModelState.AddModelError("username", "An account with that name already exists, please choose another.");
                logger.LogDebug($"Request to register account with name '{request.Username}' already in use");
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var newUser = new Data.Models.GametekiUser
            {
                Email = request.Email,
                UserName = request.Username,
                LockoutEnabled = true,
                RegisteredDate = DateTime.UtcNow,
                Settings = new Data.Models.UserSettings
                {
                    EnableGravatar = request.EnableGravatar
                },
                EmailHash = request.Email.Md5Hash(),
                RegisterIp = HttpContext.Connection.RemoteIpAddress.ToString()
            };

            var result = await userService.RegisterUserAsync(newUser, request.Password);

            if (!result.Succeeded)
            {
                logger.LogError("Failed to register account, validation error");

                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError(string.Empty, error.Description);
                }

                return BadRequest(ModelState);
            }

            var callbackUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}/activation?id={newUser.Id}";
            var verificationModel = new AccountVerificationModel
            {
                VerificationUrl = callbackUrl,
                SiteUrl = $"{HttpContext.Request.Scheme}://{HttpContext.Request.Host}"
            };

            var emailResult = await userService.SendActivationEmailAsync(newUser, verificationModel);
            if (!emailResult)
            {
                logger.LogError($"Error sending activation email for {newUser.UserName}");
            }

            logger.LogDebug($"Registered new account: '{newUser.UserName}'");

            return this.SuccessResponse();
        }

        [HttpPost]
        [Route("api/account/activate")]
        public async Task<IActionResult> ActivateAccount(Models.Api.Request.VerifyAccountRequest request)
        {
            var result = await userService.ValidateUserAsync(request.Id, request.Token);

            if (!result)
            {
                logger.LogError($"Error verifying {request.Id}");
                return this.FailureResponse("An error occurred validating your account.  Please check the URL is entered correctly and try again.");
            }

            logger.LogDebug($"Verified account id '{request.Id}'");
            return this.SuccessResponse();
        }

        [HttpPost]
        [Route("api/account/login")]
        public async Task<IActionResult> Login(Models.Api.Request.LoginRequest request)
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
                return this.FailureResponse("You must verify your account before trying to log in.  Please see the email we sent you for more details.");
            }

            var response = new Models.Api.Response.LoginResponse
            {
                Success = true,
                User = result.User.ToApiUser(),
                Token = result.Token,
                RefreshToken = result.RefreshToken
            };

            logger.LogInformation($"AUTH: Successful login for ${request.Username}");
            return Json(response);
        }

        [Route("api/account/logout")]
        [Authorize]
        public async Task<IActionResult> Logout(Models.Api.Request.RefreshTokenRequest request)
        {
            var result = await userService.LogoutUserAsync(request.Token, request.RefreshToken);

            if (!result)
            {
                logger.LogWarning($"AUTH: Failed logout for user '{User.Identity.Name}', tokens '{request.Token}' '{request.RefreshToken}'");
                return this.FailureResponse("An error occurred logging you out.  Please try again later.");
            }

            logger.LogInformation($"AUTH: Logout succeeded for user '{User.Identity.Name}'");
            return this.SuccessResponse();
        }

        [Route("api/account/checkauth")]
        [Authorize]
        public async Task<IActionResult> CheckAuth()
        {
            var user = await userService.GetUserFromUsernameAsync(User.Identity.Name);

            if (user != null)
            {
                logger.LogDebug($"Check auth succeeded for {User.Identity.Name}");
                return Json(new Models.Api.Response.CheckAuthResponse { Success = true, User = user.ToApiUser() });
            }

            logger.LogWarning($"AUTH: Failed checkauth for '{User.Identity.Name}'");
            return this.FailureResponse("An error occurred.  Please try again later.");
        }

        [Route("api/account/token")]
        [HttpPost]
        public async Task<IActionResult> GetNewToken(Models.Api.Request.RefreshTokenRequest request)
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
                return this.FailureResponse("An error occurred refreshing your token.  Please try again later.");
            }

            logger.LogDebug(
                $"Successful token refresh for '{result.User.UserName}' using token '{request.Token} " +
                $"and refresh token '{request.RefreshToken}'");
            return Json(new Models.Api.Response.LoginResponse
            {
                Success = true,
                RefreshToken = result.RefreshToken,
                Token = result.Token,
                User = result.User.ToApiUser()
            });
        }

        [Route("api/account/{username}")]
        [Authorize]
        [HttpPut]
        public async Task<IActionResult> UpdateProfile(string username, [FromBody] Models.Api.Request.UpdateProfileRequest request)
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

            user.Email = request.Email;
            user.Settings.EnableGravatar = request.EnableGravatar;
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
                return Json(new Models.Api.Response.UpdateProfileResponse
                {
                    Success = true,
                    User = user.ToApiUser(),
                    Token = null
                });
            }

            var clearResult = await userService.ClearRefreshTokensAsync(user);
            if (!clearResult)
            {
                return this.FailureResponse("An error occurred saving your profile.  Please try again later.");
            }

            var newToken = await userService.CreateRefreshTokenAsync(user, HttpContext.Connection.RemoteIpAddress.ToString());
            if (newToken == null)
            {
                return this.FailureResponse("An error occurred saving your profile.  Please try again later.");
            }

            return Json(new Models.Api.Response.UpdateProfileResponse
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
            return Json(new Models.Api.Response.GetUserSessionsResponse
            {
                Success = true,
                Tokens = user.RefreshTokens.Select(rt => rt.ToApiToken()).ToList()
            });
        }

        [Route("api/account/{username}/sessions/{sessionId}")]
        [Authorize]
        [HttpDelete]
        public async Task<IActionResult> DeleteUserSession(string username, int? sessionId)
        {
            if (username != User.Identity.Name)
            {
                logger.LogWarning($"Attempt to delete user session for wrong user: '{username}' != '{User.Identity.Name}'");

                return NotFound();
            }

            var refreshToken = await userService.GetRefreshTokenByIdAsync(sessionId.Value);
            if (refreshToken == null)
            {
                logger.LogWarning($"Attempt to delete unknown user session: '{username}' ({sessionId.Value})");

                return NotFound();
            }

            var result = await userService.DeleteRefreshTokenAsync(refreshToken);
            if (!result)
            {
                logger.LogError($"Failed to delete session '{sessionId.Value}' for user {username}");
                return this.FailureResponse("An error occurred deleting the session.  Please try again later.");
            }

            logger.LogDebug($"Deleted session '{sessionId.Value}' for user '{username}'");
            return Json(new Models.Api.Response.DeleteSessionResponse
            {
                Success = true,
                TokenId = refreshToken.Id,
                Message = "Session deleted successfully"
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
            return Json(new Models.Api.Response.GetBlockListResponse { Success = true, BlockList = user.BlockList.Select(bl => bl.BlockedUser).ToList() });
        }

        [Route("api/account/{username}/blocklist")]
        [Authorize]
        [HttpPost]
        public async Task<IActionResult> AddBlockListEntry(string username, Models.Api.Request.BlockListEntryRequest request)
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
                return this.FailureResponse("The block list already contains this user.");
            }

            var result = await userService.AddBlockListEntryAsync(user, request.Username);
            if (!result)
            {
                logger.LogError($"Error adding blocklist entry for user '{username}' ({request.Username}'");
                return this.FailureResponse("An error occurred adding the block list entry.");
            }

            logger.LogDebug($"Added blocklist entry '{request.Username}' to user '{username}'");
            return Json(new Models.Api.Response.BlockListEntryResponse
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

                return this.FailureResponse("An error occurred removing the block list entry.");
            }

            logger.LogDebug($"Removed blocklist entry '{blockedUsername}' for user '{username}'");

            return Json(new Models.Api.Response.BlockListEntryResponse
            {
                Success = true,
                Username = blockedUsername
            });
        }
    }
}
