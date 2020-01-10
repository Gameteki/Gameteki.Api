namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Collections.Generic;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Data.Models;

    public interface INewsService
    {
        Task<List<News>> GetLatestNewsAsync();
        Task<List<News>> GetAllNewsAsync();
        Task<bool> AddNewsAsync(News newsItem);
        ValueTask<News> FindNewsByIdAsync(int newsId);
        Task<bool> DeleteNewsAsync(News newsItem);
        Task<bool> UpdateNewsAsync(News newsItem);
    }
}
