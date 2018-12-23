namespace CrimsonDev.Gameteki.Api.Models.Api.Response
{
    using System.Collections.Generic;

    public class GetUserSessionsResponse : ApiResponse
    {
        public List<ApiToken> Tokens { get; set; }
    }
}