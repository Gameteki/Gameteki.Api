namespace CrimsonDev.Gameteki.Api.ApiControllers
{
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Models.Api;
    using CrimsonDev.Gameteki.Api.Models.Api.Response;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data.Constants;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;

    [ApiController]
    internal class UserController : Controller
    {
        private readonly IUserService userService;

        public UserController(IUserService userService)
        {
            this.userService = userService;
        }

        [HttpGet]
        [Route("api/user/{username}")]
        [Authorize(Roles = Roles.UserManager)]
        public async Task<IActionResult> FindUser(string username)
        {
            var user = await userService.GetUserFromUsernameAsync(username);
            if (user == null)
            {
                return NotFound();
            }

            var userForAdmin = user.ToApiUserAdmin();

            return Json(new FindUserResponse
            {
                Success = true,
                User = userForAdmin
            });
        }

        [HttpPut]
        [Route("api/user/{username}")]
        [Authorize(Roles = Roles.UserManager)]
        public async Task<IActionResult> UpdateUser(string username, ApiUserAdmin request)
        {
            var user = await userService.GetUserFromUsernameAsync(username);
            if (user == null)
            {
                return NotFound();
            }

            user.EmailConfirmed = request.Verified;
            user.Disabled = request.Disabled;

            var result = await userService.UpdateUserAsync(user);
            if (!result.Succeeded)
            {
                return this.FailureResponse("An error occurred saving the user details.");
            }

            if (!User.IsInRole(Roles.PermissionsManager))
            {
                return this.SuccessResponse();
            }

            var permissionsResult = await userService.UpdatePermissionsAsync(user, request.Permissions);
            if (!permissionsResult)
            {
                return this.FailureResponse("An error occurred saving the user details.");
            }

            return this.SuccessResponse();
        }
    }
}
