namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface IHttpClient
    {
        string AuthToken { get; set; }
        Task<bool> DownloadFileAsync(Uri url, string path);
        Task<TResponse> PostRequestAsync<TResponse, TRequest>(Uri url, TRequest request = null)
            where TRequest : class
            where TResponse : class;
        Task<TResponse> PostRequestAsync<TResponse>(Uri url, IEnumerable<KeyValuePair<string, string>> request)
            where TResponse : class;
        Task<TResponse> GetRequestAsync<TResponse>(Uri url)
                    where TResponse : class;
    }
}
