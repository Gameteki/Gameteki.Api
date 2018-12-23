namespace CrimsonDev.Gameteki.Api.Models.Api.Response
{
    using System.Collections.Generic;

    public class GetBlockListResponse : ApiResponse
    {
        public List<string> BlockList { get; set; }
    }
}