using System.Collections.Generic;

namespace CrimsonDev.Gameteki.Api.Tests.Services
{
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Api.Tests.Helpers;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Logging;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    [TestClass]
    [ExcludeFromCodeCoverage]
    public class NewsServiceTests
    {
        private List<News> NewsItems { get; set; }
        private IGametekiDbContext DbContext { get; set; }
        private Mock<ILogger<NewsService>> MockLogger { get; set; }

        private INewsService Service { get; set; }

        [TestInitialize]
        public async Task SetupTest()
        {
            var options = new DbContextOptionsBuilder<GametekiDbContext>()
                .UseInMemoryDatabase(databaseName: "NewsServiceTests")
                .Options;
            DbContext = new GametekiDbContext(options);

            NewsItems = new List<News>();

            for (var i = 0; i < 10; i++)
            {
                NewsItems.Add(TestUtils.GetRandomNews());
            }

            await DbContext.News.AddRangeAsync(NewsItems);
            await DbContext.SaveChangesAsync();

            MockLogger = new Mock<ILogger<NewsService>>();

            Service = new NewsService(DbContext, MockLogger.Object);
        }

        [TestCleanup]
        public void CleanupTest()
        {
            DbContext?.Dispose();
        }

        [TestClass]
        public class GetLatestNewsAsync : NewsServiceTests
        {
            [TestMethod]
            public async Task WhenCalledReturnsTop3NewsItems()
            {
                var orderedNews = DbContext.News.OrderByDescending(n => n.DatePublished);
                var result = await Service.GetLatestNewsAsync();

                Assert.AreEqual(3, result.Count);
                Assert.AreEqual(orderedNews.First().Text, result.First().Text);
            }
        }

        [TestClass]
        public class GetAllNewsAsync : NewsServiceTests
        {
            [TestMethod]
            public async Task WhenCalledReturnsAllNewsItems()
            {
                var orderedNews = DbContext.News.OrderByDescending(n => n.DatePublished);
                var result = await Service.GetAllNewsAsync();

                Assert.AreEqual(DbContext.News.Count(), result.Count);
                Assert.AreEqual(orderedNews.First().Text, result.First().Text);
            }
        }

        [TestClass]
        public class FindByIdAsync : NewsServiceTests
        {
            [TestMethod]
            public async Task WhenNotFoundReturnsNull()
            {
                var result = await Service.FindNewsByIdAsync(1234);

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenFoundReturnsNewsItem()
            {
                var newsItem = DbContext.News.First();

                var result = await Service.FindNewsByIdAsync(newsItem.Id);

                Assert.IsNotNull(result);
                Assert.AreEqual(newsItem, result);
            }
        }

        [TestClass]
        public class AddNewsAsync : NewsServiceTests
        {
            [TestMethod]
            public async Task WhenAddSucceedsReturnsTrue()
            {
                var result = await Service.AddNewsAsync(new News());

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class DeleteNewsAsync : NewsServiceTests
        {
            [TestMethod]
            public async Task WhenDeleteSucceedsReturnsTrue()
            {
                var result = await Service.DeleteNewsAsync(NewsItems[0]);

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class UpdateNewsAsync : NewsServiceTests
        {
            [TestMethod]
            public async Task WhenUpdateSucceedsReturnsTrue()
            {
                var news = NewsItems[3];

                news.Text = "updated";

                var result = await Service.UpdateNewsAsync(news);

                Assert.IsTrue(result);
            }
        }
    }
}
