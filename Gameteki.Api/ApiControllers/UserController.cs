namespace CrimsonDev.Gameteki.Api.ApiControllers
{
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Localization;

    [ApiController]
    public class UserController : Controller
    {
        private readonly IUserService userService;
        private readonly IStringLocalizer<UserController> t;

        public UserController(IUserService userService, IStringLocalizer<UserController> localizer)
        {
            this.userService = userService;
            t = localizer;
        }

        [HttpGet]
        [Route("api/user/{username}")]
        [Authorize(Roles = Roles.UserManager)]
        public async Task<ActionResult<ApiResponse>> FindUser(string username)
        {
            var user = await userService.GetUserFromUsernameAsync(username).ConfigureAwait(false);
            if (user == null)
            {
                return NotFound();
            }

            var userForAdmin = user.ToApiUserAdmin();

            return new FindUserResponse
            {
                Success = true,
                User = userForAdmin
            };
        }

        [HttpPut]
        [Route("api/user/{username}")]
        [Authorize(Roles = Roles.UserManager)]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "ASP.NET Ensures this is not null")]
        public async Task<ActionResult<ApiResponse>> UpdateUser(string username, ApiUserAdmin request)
        {
            var user = await userService.GetUserFromUsernameAsync(username).ConfigureAwait(false);
            if (user == null)
            {
                return NotFound();
            }

            user.EmailConfirmed = request.Verified;
            user.Disabled = request.Disabled;

            var result = await userService.UpdateUserAsync(user).ConfigureAwait(false);
            if (!result.Succeeded)
            {
                return this.FailureResponse(t["An error occurred saving the user details"]);
            }

            if (!User.IsInRole(Roles.PermissionsManager))
            {
                return this.SuccessResponse();
            }

            var permissionsResult = await userService.UpdatePermissionsAsync(user, request.GametekiPermissions).ConfigureAwait(false);
            if (!permissionsResult)
            {
                return this.FailureResponse(t["An error occurred saving the user details"]);
            }

            return this.SuccessResponse();
        }
    }
}
