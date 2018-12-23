namespace CrimsonDev.Gameteki.Api.Models.Api.Response
{
    using CrimsonDev.Gameteki.Data.Models;

    public class UpdateProfileResponse : ApiResponse
    {
        public ApiUser User { get; set; }
        public RefreshToken Token { get; set; }
    }
}