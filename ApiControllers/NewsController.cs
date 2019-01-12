namespace CrimsonDev.Gameteki.Api.ApiControllers
{
    using System;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;

    [ApiController]
    public class NewsController : Controller
    {
        private readonly INewsService newsService;
        private readonly IUserService userService;
        private readonly ILogger<NewsController> logger;

        public NewsController(INewsService newsService, IUserService userService, ILogger<NewsController> logger)
        {
            this.newsService = newsService;
            this.userService = userService;
            this.logger = logger;
        }

        [HttpGet]
        [Route("api/news")]
        public async Task<IActionResult> GetNews()
        {
            var news = await newsService.GetLatestNewsAsync();

            return Json(new GetNewsResponse { Success = true, News = news });
        }

        [HttpGet]
        [Authorize(Roles = Roles.NewsManager)]
        [Route("api/news/all")]
        public async Task<IActionResult> GetAllNews()
        {
            var news = await newsService.GetAllNewsAsync();

            return Json(new GetNewsResponse { Success = true, News = news });
        }

        [HttpPost]
        [Authorize(Roles = Roles.NewsManager)]
        [Route("api/news")]
        public async Task<IActionResult> AddNews(AddNewsRequest request)
        {
            var poster = await userService.GetUserFromUsernameAsync(User.Identity.Name);
            if (poster == null)
            {
                logger.LogError($"Unknown username '{User.Identity.Name}' saving news");
                return this.FailureResponse("An error occurred saving the news item.");
            }

            var newNews = new News
            {
                DatePublished = DateTime.UtcNow,
                PosterId = poster.Id,
                Text = request.Text
            };

            var result = await newsService.AddNewsAsync(newNews);
            if (result)
            {
                return Json(new AddNewsResponse { Success = true, NewsItem = newNews });
            }

            logger.LogError("Failed saving news");
            return this.FailureResponse("An error occurred saving the news item.");
        }

        [HttpDelete]
        [Authorize(Roles = Roles.NewsManager)]
        [Route("api/news/{newsId}")]
        public async Task<IActionResult> DeleteNews(int newsId)
        {
            var newsItem = await newsService.FindNewsByIdAsync(newsId);
            if (newsItem == null)
            {
                return NotFound();
            }

            var result = await newsService.DeleteNewsAsync(newsItem);
            if (!result)
            {
                logger.LogError($"Error deleting news item {newsId}");
                return this.FailureResponse("An error occurred deleting this news entry.");
            }

            return Json(new DeleteNewsResponse
            {
                Success = true,
                Id = newsItem.Id
            });
        }

        [HttpPut]
        [Authorize(Roles = Roles.NewsManager)]
        [Route("api/news/{newsId}")]
        public async Task<IActionResult> SaveNews(int newsId, AddNewsRequest request)
        {
            var newsItem = await newsService.FindNewsByIdAsync(newsId);
            if (newsItem == null)
            {
                return NotFound();
            }

            newsItem.Text = request.Text;

            var result = await newsService.UpdateNewsAsync(newsItem);
            if (result)
            {
                return Json(new AddNewsResponse { Success = true, NewsItem = newsItem });
            }

            logger.LogError($"Failed to update news item {newsId}");
            return this.FailureResponse("An error occurred saving the news item.");
        }
    }
}
