namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
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

        public async Task<bool> AddNewsAsync(News newsItem)
        {
            context.News.Add(newsItem);

            try
            {
                await context.SaveChangesAsync();
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Error saving news");

                return false;
            }

            return true;
        }

        public Task<News> FindNewsByIdAsync(int newsId)
        {
            return context.News.FindAsync(newsId);
        }

        public async Task<bool> DeleteNewsAsync(News newsItem)
        {
            context.News.Remove(newsItem);

            try
            {
                await context.SaveChangesAsync();
            }
            catch (Exception exception)
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
                await context.SaveChangesAsync();
            }
            catch (Exception exception)
            {
                logger.LogError(exception, $"Error deleting news '{newsItem.Id}'");

                return false;
            }

            return true;
        }
    }
}
