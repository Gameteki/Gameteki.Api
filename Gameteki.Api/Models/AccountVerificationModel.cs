namespace CrimsonDev.Gameteki.Api.Models
{
    using System;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    public class AccountVerificationModel : PageModel
    {
        public Uri VerificationUrl { get; set; }
        public Uri SiteUrl { get; set; }
    }
}