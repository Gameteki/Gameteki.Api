namespace CrimsonDev.Gameteki.Api.Models.Api.Request
{
    using System.ComponentModel.DataAnnotations;

    public class BlockListEntryRequest
    {
        [Required]
        public string Username { get; set; }
    }
}