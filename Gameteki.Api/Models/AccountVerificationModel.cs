namespace CrimsonDev.Gameteki.Api.Models
{
    using Microsoft.AspNetCore.Mvc.RazorPages;

    public class AccountVerificationModel : PageModel
    {
        public string VerificationUrl { get; set; }
        public string SiteUrl { get; set; }
    }
}