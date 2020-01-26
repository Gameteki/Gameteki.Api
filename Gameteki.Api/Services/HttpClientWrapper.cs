﻿namespace CrimsonDev.Gameteki.Api.Services
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
    public class HttpClientWrapper : IHttpClient
    {
        private readonly ILogger<HttpClientWrapper> logger;
        private readonly HttpClient httpClient;

        public HttpClientWrapper(ILogger<HttpClientWrapper> logger)
        {
            this.logger = logger;
            httpClient = new HttpClient();
        }

        public async Task<bool> DownloadFileAsync(string url, string path)
        {
            Stream stream;

            try
            {
                stream = await httpClient.GetStreamAsync(url);
            }
            catch (Exception exception)
            {
                logger.LogError(exception, $"Error downloading file from '{url}' to '{path}'");
                return false;
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(path));
                await using var fileStream = File.Create(path);
                await stream.CopyToAsync(fileStream);
            }
            catch (Exception exception)
            {
                logger.LogError(exception, $"Error saving to '{path}'");
                return false;
            }

            return true;
        }

        public async Task<TResponse> PostRequestAsync<TResponse, TRequest>(string url, TRequest request = null)
            where TRequest : class
            where TResponse : class
        {
            var serialisedContent = JsonSerializer.Serialize(request);

            using var content = new StringContent(serialisedContent, Encoding.UTF8, "application/json");
            content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            HttpResponseMessage response;

            try
            {
                response = await httpClient.PostAsync(url, content);
            }
            catch (Exception exception)
            {
                logger.LogError($"Error POSTing to API: {url}", exception);
                return null;
            }

            if (response.IsSuccessStatusCode)
            {
                return JsonSerializer.Deserialize<TResponse>(await response.Content.ReadAsStringAsync());
            }

            logger.LogError(
                $"Error POSTing to API {url}.  Error code {response.StatusCode}.  Error: {await response.Content.ReadAsStringAsync()}");
            return null;
        }

        public async Task<TResponse> PostRequestAsync<TResponse>(string url, IEnumerable<KeyValuePair<string, string>> request)
            where TResponse : class
        {
            HttpResponseMessage response;

            using var content = new FormUrlEncodedContent(request);
            content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

            try
            {
                response = await httpClient.PostAsync(url, content);
            }
            catch (Exception exception)
            {
                logger.LogError($"Error POSTing to API: {url}", exception);
                return null;
            }

            if (response.IsSuccessStatusCode)
            {
                return JsonSerializer.Deserialize<TResponse>(await response.Content.ReadAsStringAsync());
            }

            logger.LogError(
                $"Error POSTing to API {url}.  Error code {response.StatusCode}.  Error: {await response.Content.ReadAsStringAsync()}");
            return null;
        }
    }
}
