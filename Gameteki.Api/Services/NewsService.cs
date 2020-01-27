using System.Runtime.CompilerServices;

[assembly: InternalsVisibleTo("CrimsonDev.Gameteki.Api.Tests")]
[assembly: InternalsVisibleTo("DynamicProxyGenAssembly2, PublicKey=0024000004800000940000000602000000240000525341310004000001000100c547cac37abd99c8db225ef2f6c8a3602f3b3606cc9891605d02baa56104f4cfc0734aa39b93bf7852f7d9266654753cc297e7d2edfe0bac1cdcf9f717241550e0a7b191195b7667bb4f64bcb8e2121380fd1d9d46ad2d92d2d15605093924cceaf74c4861eff62abf69b9291ed0a340e113be11e6a7d3113e92484cf7045cc7")]
namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Logging;

    internal class NewsService : INewsService
    {
        private readonly IGametekiDbContext context;
        private readonly ILogger<NewsService> logger;

        public NewsService(IGametekiDbContext context, ILogger<NewsService> logger)
        {
            this.context = context;
            this.logger = logger;
        }

        public Task<List<News>> GetLatestNewsAsync()
        {
            return context.News.OrderByDescending(n => n.DatePublished).Take(3).ToListAsync();
        }

        public Task<List<News>> GetAllNewsAsync()
        {
            return context.News.OrderByDescending(n => n.DatePublished).ToListAsync();
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Globalization", "CA1303:Do not pass literals as localized parameters", Justification = "Logs aren't localised")]
        public async Task<bool> AddNewsAsync(News newsItem)
        {
            context.News.Add(newsItem);

            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException exception)
            {
                logger.LogError(exception, "Error saving news");

                return false;
            }

            return true;
        }

        public ValueTask<News> FindNewsByIdAsync(int newsId)
        {
            return context.News.FindAsync(newsId);
        }

        public async Task<bool> DeleteNewsAsync(News newsItem)
        {
            context.News.Remove(newsItem);

            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException exception)
            {
                logger.LogError(exception, $"Error deleting news '{newsItem.Id}'");

                return false;
            }

            return true;
        }

        public async Task<bool> UpdateNewsAsync(News newsItem)
        {
            try
            {
                await context.SaveChangesAsync().ConfigureAwait(false);
            }
            catch (DbUpdateException exception)
            {
                logger.LogError(exception, $"Error deleting news '{newsItem.Id}'");

                return false;
            }

            return true;
        }
    }
}
