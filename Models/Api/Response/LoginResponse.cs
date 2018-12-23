namespace CrimsonDev.Gameteki.Api.Models.Api.Response
{
    public class LoginResponse : ApiResponse
    {
        public ApiUser User { get; set; }
        public string Token { get; set; }
        public string RefreshToken { get; set; }
    }
}