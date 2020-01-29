namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Models.Patreon;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Models.Config;
    using CrimsonDev.Gameteki.Data.Models.Patreon;
    using JsonApiFramework.Json;
    using JsonApiFramework.JsonApi;
    using Microsoft.Extensions.Options;

    public class PatreonService : IPatreonService
    {
        private readonly IHttpClient httpClient;
        private readonly PatreonOptions options;

        public PatreonService(IHttpClient httpClient, IOptions<PatreonOptions> options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            this.httpClient = httpClient;
            this.options = options.Value;
        }

        public Task<TokenResponse> LinkAccountAsync(string code, string redirectUrl)
        {
            return LinkAccountAsync(code, new Uri(redirectUrl));
        }

        public async Task<TokenResponse> LinkAccountAsync(string code, Uri redirectUrl)
        {
            if (code == null)
            {
                throw new ArgumentNullException(nameof(code));
            }

            if (redirectUrl == null)
            {
                throw new ArgumentNullException(nameof(redirectUrl));
            }

            var request = new Dictionary<string, string>
            {
                { "code", code },
                { "grant_type", "authorization_code" },
                { "client_id", options.ClientId },
                { "client_secret", options.ClientSecret },
                { "redirect_uri", redirectUrl.AbsoluteUri }
            };

            return await httpClient.PostRequestAsync<TokenResponse>(
                new Uri($"https://www.patreon.com/api/oauth2/token?code={code}"), request).ConfigureAwait(false);
        }

        public async Task<PatreonUser> GetCurrentUserAsync(string token)
        {
            httpClient.AuthToken = "CMGnU2qLf9kcrUezw0fnH6njsel1Oich7Kj49KV301w";

            var documentString = await httpClient.GetRequestAsync(
                new Uri($"https://www.patreon.com/api/oauth2/api/current_user")).ConfigureAwait(false);
            var document = JsonObject.Parse<Document>(documentString);

            using (var documentContext = new PatreonDocumentContext(document))
            {
                var documentType = documentContext.GetDocumentType();
                var user = documentContext.GetResource(typeof(PatreonUser));
            }

            return new PatreonUser();
        }
    }
}
