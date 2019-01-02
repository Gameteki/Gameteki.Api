namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Net.Http;
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
                using (var fileStream = File.Create(path))
                {
                    await stream.CopyToAsync(fileStream);
                }
            }
            catch (Exception exception)
            {
                logger.LogError(exception, $"Error saving to '{path}'");
                return false;
            }

            return true;
        }
    }
}
