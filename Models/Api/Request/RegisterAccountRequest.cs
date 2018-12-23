namespace CrimsonDev.Gameteki.Api.Models.Api.Request
{
    using System.ComponentModel.DataAnnotations;

    public class RegisterAccountRequest
    {
        [Required]
        [MinLength(length: 3, ErrorMessage = "Username must be at least 3 characters and no more than 15 characters long.")]
        [MaxLength(length: 15, ErrorMessage = "Username must be at least 3 characters and no more than 15 characters long.")]
        [RegularExpression("[A-Za-z0-9_-]+$", ErrorMessage = "Usernames must only use the characters a-z, 0-9, _ and -.")]
        public string Username { get; set; }
        [Required]
        [MinLength(length: 6, ErrorMessage = "Password must be at least 6 characters.")]
        public string Password { get; set; }
        [Required]
        [RegularExpression(
            @"^(([^<>()[\]\.,;:\s@""]+(\.[^<>()[\]\.,;:\s@""]+)*)|("".+""))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$",
            ErrorMessage = "Email must be a valid email address.")]
        public string Email { get; set; }
        public bool EnableGravatar { get; set; }
    }
}
