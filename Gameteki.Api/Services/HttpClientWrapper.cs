namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Text;
    using System.Text.Json;
    using System.Threading.Tasks;
    using Microsoft.Extensions.Logging;

    [ExcludeFromCodeCoverage]
    public sealed class HttpClientWrapper : IHttpClient, IDisposable
    {
        private readonly ILogger<HttpClientWrapper> logger;
        private readonly HttpClient httpClient;

        public HttpClientWrapper(ILogger<HttpClientWrapper> logger)
        {
            this.logger = logger;
            httpClient = new HttpClient();
        }

        public string AuthToken { get; set; }

        public async Task<bool> DownloadFileAsync(Uri url, string path)
        {
            Stream stream;

            try
            {
                stream = await httpClient.GetStreamAsync(url).ConfigureAwait(false);
            }
            catch (HttpRequestException exception)
            {
                logger.LogError(exception, $"Error downloading file from '{url}' to '{path}'");
                return false;
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                await using var fileStream = File.Create(path);
                await stream.CopyToAsync(fileStream).ConfigureAwait(false);
            }
#pragma warning disable CA1031 // Do not catch general exception types
            catch (Exception exception)
#pragma warning restore CA1031 // Do not catch general exception types
            {
                logger.LogError(exception, $"Error saving to '{path}'");
                return false;
            }

            return true;
        }

        public async Task<TResponse> PostRequestAsync<TResponse, TRequest>(Uri url, TRequest request = null)
            where TRequest : class
            where TResponse : class
        {
            var serialisedContent = JsonSerializer.Serialize(request);

            using var content = new StringContent(serialisedContent, Encoding.UTF8, "application/json");
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            HttpResponseMessage response;

            try
            {
                response = await httpClient.PostAsync(url, content).ConfigureAwait(false);
            }
            catch (HttpRequestException exception)
            {
                logger.LogError($"Error POSTing to API: {url}", exception);
                return null;
            }

            if (response.IsSuccessStatusCode)
            {
                return JsonSerializer.Deserialize<TResponse>(await response.Content.ReadAsStringAsync()
                    .ConfigureAwait(false));
            }

            logger.LogError(
                $"Error POSTing to API {url}.  Error code {response.StatusCode}.  Error: {await response.Content.ReadAsStringAsync().ConfigureAwait(false)}");
            return null;
        }

        public async Task<TResponse> PostRequestAsync<TResponse>(
            Uri url,
            IEnumerable<KeyValuePair<string, string>> request)
            where TResponse : class
        {
            HttpResponseMessage response;

            using var content = new FormUrlEncodedContent(request);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

            try
            {
                response = await httpClient.PostAsync(url, content).ConfigureAwait(false);
            }
            catch (HttpRequestException exception)
            {
                logger.LogError($"Error POSTing to API: {url}", exception);
                return null;
            }

            if (response.IsSuccessStatusCode)
            {
                return JsonSerializer.Deserialize<TResponse>(await response.Content.ReadAsStringAsync()
                    .ConfigureAwait(false));
            }

            logger.LogError(
                $"Error POSTing to API {url}.  Error code {response.StatusCode}.  Error: {await response.Content.ReadAsStringAsync().ConfigureAwait(false)}");
            return null;
        }

        public async Task<string> GetRequestAsync(Uri url)
        {
            if (AuthToken != null)
            {
                httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", AuthToken);
            }

            try
            {
                return await httpClient.GetStringAsync(url).ConfigureAwait(false);
            }
            catch (HttpRequestException ex)
            {
                logger.LogError(ex, $"Error in GET request for url {url}");
                return null;
            }
        }

        public void Dispose()
        {
            httpClient?.Dispose();
        }
    }
}
