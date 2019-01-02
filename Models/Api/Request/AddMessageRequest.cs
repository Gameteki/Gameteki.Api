namespace CrimsonDev.Gameteki.Api.Models.Api.Request
{
    using System.ComponentModel.DataAnnotations;

    public class AddMessageRequest
    {
        [Required]
        [MaxLength(512)]
        public string Message { get; set; }
    }
}
