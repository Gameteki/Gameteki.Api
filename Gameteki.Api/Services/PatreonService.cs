namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Models.Patreon;
    using CrimsonDev.Gameteki.Data.Models.Config;
    using Microsoft.Extensions.Options;

    public class PatreonService : IPatreonService
    {
        private readonly IHttpClient httpClient;
        private readonly PatreonOptions options;

        public PatreonService(IHttpClient httpClient, IOptions<PatreonOptions> options)
        {
            this.httpClient = httpClient;
            this.options = options.Value;
        }

        public async Task LinkAccountAsync(string code, string redirectUrl)
        {
            var request = new Dictionary<string, string>
            {
                { "code", code },
                { "grant_type", "authorization_code" },
                { "client_id", options.ClientId },
                { "client_secret", options.ClientSecret },
                { "redirect_uri", redirectUrl }
            };

            var response =
                await httpClient.PostRequestAsync<TokenResponse>(
                    $"https://www.patreon.com/api/oauth2/token?code={code}", request);
        }
    }
}
