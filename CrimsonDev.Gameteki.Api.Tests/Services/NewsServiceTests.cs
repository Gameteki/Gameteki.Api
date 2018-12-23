namespace CrimsonDev.Gameteki.Api.Tests.Services
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Threading;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Api.Tests.Helpers;
    using CrimsonDev.Gameteki.Data;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Logging;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    [TestClass]
    [ExcludeFromCodeCoverage]
    public class NewsServiceTests
    {
        private IGametekiDbContext DbContext { get; set; }
        private Mock<ILogger<NewsService>> MockLogger { get; set; }

        private INewsService Service { get; set; }

        [TestInitialize]
        public void SetupTest()
        {
            var options = new DbContextOptionsBuilder<GametekiDbContext>()
                .UseInMemoryDatabase(databaseName: "NewsServiceTests")
                .Options;
            DbContext = new GametekiDbContext(options);

            for (var i = 0; i < 10; i++)
            {
                DbContext.News.Add(TestUtils.GetRandomNews());
                DbContext.SaveChangesAsync().Wait();
            }

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
                Assert.AreEqual(orderedNews.First().Text, result.First<Data.Models.News>().Text);
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
                Assert.AreEqual(orderedNews.First().Text, result.First<Data.Models.News>().Text);
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
            private Mock<IGametekiDbContext> MockDbContext { get; set; }

            [TestInitialize]
            public new void SetupTest()
            {
                MockDbContext = new Mock<IGametekiDbContext>();
                MockLogger = new Mock<ILogger<NewsService>>();

                MockDbContext.Setup(c => c.News).Returns(new List<Data.Models.News>().ToMockDbSet().Object);

                Service = new NewsService(MockDbContext.Object, MockLogger.Object);
            }

            [TestMethod]
            public async Task WhenAddFailsReturnsFalse()
            {
                MockDbContext.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.AddNewsAsync(new Data.Models.News());

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenAddSucceedsReturnsTrue()
            {
                var result = await Service.AddNewsAsync(new Data.Models.News());

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class DeleteNewsAsync : NewsServiceTests
        {
            private Mock<IGametekiDbContext> MockDbContext { get; set; }

            [TestInitialize]
            public new void SetupTest()
            {
                MockDbContext = new Mock<IGametekiDbContext>();
                MockLogger = new Mock<ILogger<NewsService>>();

                MockDbContext.Setup(c => c.News).Returns(new List<Data.Models.News>().ToMockDbSet().Object);

                Service = new NewsService(MockDbContext.Object, MockLogger.Object);
            }

            [TestMethod]
            public async Task WhenDeleteFailsReturnsFalse()
            {
                MockDbContext.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.DeleteNewsAsync(new Data.Models.News());

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenDeleteSucceedsReturnsTrue()
            {
                var result = await Service.DeleteNewsAsync(new Data.Models.News());

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class UpdateNewsAsync : NewsServiceTests
        {
            private Mock<IGametekiDbContext> MockDbContext { get; set; }

            [TestInitialize]
            public new void SetupTest()
            {
                MockDbContext = new Mock<IGametekiDbContext>();
                MockLogger = new Mock<ILogger<NewsService>>();

                MockDbContext.Setup(c => c.News).Returns(new List<Data.Models.News>().ToMockDbSet().Object);

                Service = new NewsService(MockDbContext.Object, MockLogger.Object);
            }

            [TestMethod]
            public async Task WhenUpdateFailsReturnsFalse()
            {
                MockDbContext.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.UpdateNewsAsync(new Data.Models.News());

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenUpdateSucceedsReturnsTrue()
            {
                var result = await Service.UpdateNewsAsync(new Data.Models.News());

                Assert.IsTrue(result);
            }
        }
    }
}
