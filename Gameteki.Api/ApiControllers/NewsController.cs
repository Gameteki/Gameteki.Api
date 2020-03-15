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
    using Microsoft.Extensions.Localization;
    using Microsoft.Extensions.Logging;

    [ApiController]
    public class NewsController : Controller
    {
        private readonly INewsService newsService;
        private readonly IUserService userService;
        private readonly ILogger<NewsController> logger;
        private readonly IStringLocalizer<NewsController> t;

        public NewsController(INewsService newsService, IUserService userService, ILogger<NewsController> logger, IStringLocalizer<NewsController> localizer)
        {
            this.newsService = newsService;
            this.userService = userService;
            this.logger = logger;
            t = localizer;
        }

        [HttpGet]
        [Route("api/news")]
        public async Task<ActionResult<GetNewsResponse>> GetNews()
        {
            var news = await newsService.GetLatestNewsAsync().ConfigureAwait(false);

            var ret = new GetNewsResponse { Success = true };
            ret.News.AddRange(news);

            return ret;
        }

        [HttpGet]
        [Authorize(Roles = Roles.NewsManager)]
        [Route("api/news/admin")]
        public async Task<ActionResult<GetNewsResponse>> GetAllNews()
        {
            var news = await newsService.GetAllNewsAsync().ConfigureAwait(false);

            var ret = new GetNewsResponse { Success = true };
            ret.News.AddRange(news);

            return ret;
        }

        [HttpPost]
        [Authorize(Roles = Roles.NewsManager)]
        [Route("api/news")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "ASP.NET ensures this is not null")]
        public async Task<ActionResult<ApiResponse>> AddNews(AddNewsRequest request)
        {
            var poster = await userService.GetUserFromUsernameAsync(User.Identity.Name).ConfigureAwait(false);
            if (poster == null)
            {
                logger.LogError($"Unknown username '{User.Identity.Name}' saving news");
                return this.FailureResponse(t["An error occurred saving the news item"]);
            }

            var newNews = new News
            {
                DatePublished = DateTime.UtcNow,
                PosterId = poster.Id,
                Text = request.Text
            };

            var result = await newsService.AddNewsAsync(newNews).ConfigureAwait(false);
            if (result)
            {
                newNews.Poster = poster;
                return new AddNewsResponse { Success = true, NewsItem = newNews, Message = t["News item added successfully"] };
            }

#pragma warning disable CA1303 // Do not pass literals as localized parameters
            logger.LogError("Failed saving news");
#pragma warning restore CA1303 // Do not pass literals as localized parameters
            return this.FailureResponse(t["An error occurred saving the news item."]);
        }

        [HttpDelete]
        [Authorize(Roles = Roles.NewsManager)]
        [Route("api/news/{newsId}")]
        public async Task<ActionResult<ApiResponse>> DeleteNews(int newsId)
        {
            var newsItem = await newsService.FindNewsByIdAsync(newsId).ConfigureAwait(false);
            if (newsItem == null)
            {
                return NotFound();
            }

            var result = await newsService.DeleteNewsAsync(newsItem).ConfigureAwait(false);
            if (!result)
            {
                logger.LogError($"Error deleting news item {newsId}");
                return this.FailureResponse(t["An error occurred deleting this news entry"]);
            }

            return new DeleteNewsResponse
            {
                Success = true,
                Id = newsItem.Id,
                Message = t["News item deleted successfully"]
            };
        }

        [HttpPut]
        [Authorize(Roles = Roles.NewsManager)]
        [Route("api/news/{newsId}")]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1062:Validate arguments of public methods", Justification = "ASP.NET ensures this is not null")]
        public async Task<ActionResult<ApiResponse>> SaveNews(int newsId, AddNewsRequest request)
        {
            var newsItem = await newsService.FindNewsByIdAsync(newsId).ConfigureAwait(false);
            if (newsItem == null)
            {
                return NotFound();
            }

            newsItem.Text = request.Text;

            var result = await newsService.UpdateNewsAsync(newsItem).ConfigureAwait(false);
            if (result)
            {
                return new AddNewsResponse { Success = true, NewsItem = newsItem };
            }

            logger.LogError($"Failed to update news item {newsId}");
            return this.FailureResponse(t["An error occurred saving the news item"]);
        }
    }
}
