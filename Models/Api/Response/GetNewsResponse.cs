namespace CrimsonDev.Gameteki.Api.Models.Api.Response
{
    using System.Collections.Generic;
    using CrimsonDev.Gameteki.Data.Models;

    public class GetNewsResponse : ApiResponse
    {
        public List<News> News { get; set; }
    }
}