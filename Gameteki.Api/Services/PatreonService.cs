namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
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
                new Uri("https://www.patreon.com/api/oauth2/token"), request).ConfigureAwait(false);
        }

        public async Task<PatreonStatus> GetUserStatus(string token)
        {
            httpClient.AuthToken = token;

            var documentString = await httpClient.GetRequestAsync(
                new Uri("https://www.patreon.com/api/oauth2/api/current_user")).ConfigureAwait(false);

            if (string.IsNullOrEmpty(documentString))
            {
                return PatreonStatus.NotLinked;
            }

            var document = JsonObject.Parse<Document>(documentString);
            using var documentContext = new PatreonDocumentContext(document);

            if (!(documentContext.GetResource(typeof(PatreonPledge)) is PatreonPledge pledge))
            {
                return PatreonStatus.Linked;
            }

            if (!pledge.IsPaused && !pledge.DeclinedSince.HasValue)
            {
                return PatreonStatus.Pledged;
            }

            return PatreonStatus.NotLinked;
        }

        public async Task<TokenResponse> RefreshTokenAsync(string refreshToken)
        {
            if (refreshToken == null)
            {
                throw new ArgumentNullException(nameof(refreshToken));
            }

            var request = new Dictionary<string, string>
            {
                { "refresh_token", refreshToken },
                { "grant_type", "refresh_token" },
                { "client_id", options.ClientId },
                { "client_secret", options.ClientSecret }
            };

            return await httpClient.PostRequestAsync<TokenResponse>(
                new Uri("https://www.patreon.com/api/oauth2/token"), request).ConfigureAwait(false);
        }
    }
}
