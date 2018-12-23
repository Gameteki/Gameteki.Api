namespace CrimsonDev.Gameteki.Api.Models.Api
{
    using CrimsonDev.Gameteki.Data.Models;

    public class ApiUser
    {
        public string Id { get; set; }
        public string Username { get; set; }
        public string Email { get; set; }
        public ApiSettings Settings { get; set; }
        public Permissions Permissions { get; set; }
        public bool EnableGravatar { get; set; }
        public string CustomData { get; set; }
    }
}