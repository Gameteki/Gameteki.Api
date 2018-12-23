namespace CrimsonDev.Gameteki.Api.Models.Api.Response
{
    using CrimsonDev.Gameteki.Data.Models;

    public class AddNewsResponse : ApiResponse
    {
        public News NewsItem { get; set; }
    }
}
