namespace CrimsonDev.Gameteki.Api.Models.Api.Response
{
    using System.Collections.Generic;

    public class GetMessagesResponse : ApiResponse
    {
        public List<ApiLobbyMessage> Messages { get; set; }
    }
}
