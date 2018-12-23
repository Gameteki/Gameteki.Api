namespace CrimsonDev.Gameteki.Api.Models.Api.Request
{
    using System.ComponentModel.DataAnnotations;

    public class AddNewsRequest
    {
        [Required]
        [MaxLength(512)]
        public string Text { get; set; }
    }
}
