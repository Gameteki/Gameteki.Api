namespace CrimsonDev.Gameteki.Api.Models.Api.Request
{
    using System.ComponentModel.DataAnnotations;

    public class UpdateProfileRequest
    {
        [Required]
        public string Email { get; set; }
        public string CurrentPassword { get; set; }
        public string NewPassword { get; set; }
        public bool EnableGravatar { get; set; }
        public string CustomData { get; set; }
        [Required]
        public ApiSettings Settings { get; set; }
    }
}