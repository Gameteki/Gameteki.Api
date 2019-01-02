namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Threading.Tasks;

    public interface IHttpClient
    {
        Task<bool> DownloadFileAsync(string url, string path);
    }
}
