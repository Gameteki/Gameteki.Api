namespace CrimsonDev.Gameteki.Api
{
    using System.Security.Claims;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Services;
    using Microsoft.AspNetCore.Authentication;

    public class ClaimsTransformer : IClaimsTransformation
    {
        private readonly IUserService userService;

        public ClaimsTransformer(IUserService userService)
        {
            this.userService = userService;
        }

        public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            if (principal == null)
            {
                return null;
            }

            var identity = (ClaimsIdentity)principal.Identity;

            if (principal.Identity == null)
            {
                return principal;
            }

            var user = await userService.GetUserFromUsernameAsync(principal.Identity.Name).ConfigureAwait(false);

            foreach (var userRole in user.UserRoles)
            {
                var claim = new Claim(identity.RoleClaimType, userRole.Role.Name);

                identity.AddClaim(claim);
            }

            return principal;
        }
    }
}