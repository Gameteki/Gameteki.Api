namespace CrimsonDev.Gameteki.Api.Models.Api
{
    public class ApiUserAdmin : ApiUser
    {
        public bool Verified { get; set; }
        public bool Disabled { get; set; }
    }
}