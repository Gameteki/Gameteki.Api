namespace CrimsonDev.Gameteki.Api.Tests.Controllers
{
    using System.Collections.Generic;
    using System.Net;
    using System.Security.Claims;
    using System.Security.Principal;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.ApiControllers;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Api.Tests.Helpers;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    public class NewsControllerTests
    {
        private const string TestUser = "TestUser";

        private Mock<INewsService> MockNewsService { get; set; }
        private Mock<IUserService> MockUserService { get; set; }
        private Mock<ILogger<NewsController>> MockLogger { get; set; }

        private NewsController Controller { get; set; }

        [TestInitialize]
        public void SetupTest()
        {
            MockNewsService = new Mock<INewsService>();
            MockLogger = new Mock<ILogger<NewsController>>();
            MockUserService = new Mock<IUserService>();

            Controller = new NewsController(MockNewsService.Object, MockUserService.Object, MockLogger.Object)
            {
                ControllerContext = new ControllerContext
                {
                    HttpContext = new DefaultHttpContext
                    {
                        Connection = { RemoteIpAddress = IPAddress.Loopback },
                        User = new ClaimsPrincipal(new GenericPrincipal(new GenericIdentity(TestUser), null))
                    }
                }
            };
        }

        [TestClass]
        public class GetNews : NewsControllerTests
        {
            [TestMethod]
            public async Task WhenCalledReturnsNewsResponse()
            {
                MockNewsService.Setup(ns => ns.GetLatestNewsAsync()).ReturnsAsync(new List<Data.Models.News> { new Data.Models.News() });

                var result = await Controller.GetNews();
                var response = TestUtils.GetResponseFromResult<GetNewsResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(1, response.News.Count);
            }
        }

        [TestClass]
        public class GetAllNews : NewsControllerTests
        {
            [TestMethod]
            public async Task WhenCalledReturnsNewsResponse()
            {
                MockNewsService.Setup(ns => ns.GetAllNewsAsync()).ReturnsAsync(new List<Data.Models.News> { new Data.Models.News() });

                var result = await Controller.GetAllNews();
                var response = TestUtils.GetResponseFromResult<GetNewsResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(1, response.News.Count);
            }
        }

        [TestClass]
        public class AddNews : NewsControllerTests
        {
            [TestMethod]
            public async Task WhenUserNotFoundReturnsFailureResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync((Data.Models.GametekiUser)null);

                var result = await Controller.AddNews(new AddNewsRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenAddNewsFailsReturnsFailureResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                MockNewsService.Setup(ns => ns.AddNewsAsync(It.IsAny<Data.Models.News>())).ReturnsAsync(false);

                var result = await Controller.AddNews(new AddNewsRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenAddNewsSucceedsReturnsSuccessResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                MockNewsService.Setup(ns => ns.AddNewsAsync(It.IsAny<Data.Models.News>())).ReturnsAsync(true);

                var result = await Controller.AddNews(new AddNewsRequest { Text = "Test News" });
                var response = TestUtils.GetResponseFromResult<AddNewsResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual("Test News", response.NewsItem.Text);
            }
        }

        [TestClass]
        public class DeleteNews : NewsControllerTests
        {
            [TestMethod]
            public async Task WhenNewsNotFoundReturnsNotFound()
            {
                MockNewsService.Setup(ns => ns.FindNewsByIdAsync(It.IsAny<int>())).ReturnsAsync((Data.Models.News)null);

                var result = await Controller.DeleteNews(1);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenErrorDeletingReturnsErrorResponse()
            {
                MockNewsService.Setup(ns => ns.FindNewsByIdAsync(It.IsAny<int>())).ReturnsAsync(new Data.Models.News());

                var result = await Controller.DeleteNews(1);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenDeleteSucceedsReturnsSuccessResponse()
            {
                MockNewsService.Setup(ns => ns.FindNewsByIdAsync(It.IsAny<int>())).ReturnsAsync(new Data.Models.News { Id = 1 });
                MockNewsService.Setup(ns => ns.DeleteNewsAsync(It.IsAny<Data.Models.News>())).ReturnsAsync(true);

                var result = await Controller.DeleteNews(1);
                var response = TestUtils.GetResponseFromResult<DeleteNewsResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(1, response.Id);
            }
        }

        [TestClass]
        public class SaveNews : NewsControllerTests
        {
            [TestMethod]
            public async Task WhenNewsNotFoundReturnsNotFound()
            {
                MockNewsService.Setup(ns => ns.FindNewsByIdAsync(It.IsAny<int>())).ReturnsAsync((Data.Models.News)null);

                var result = await Controller.SaveNews(1, new AddNewsRequest());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenErrorSavingReturnsErrorResponse()
            {
                MockNewsService.Setup(ns => ns.FindNewsByIdAsync(It.IsAny<int>())).ReturnsAsync(new Data.Models.News());

                var result = await Controller.SaveNews(1, new AddNewsRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenSaveSucceedsReturnsSuccessResponse()
            {
                MockNewsService.Setup(ns => ns.FindNewsByIdAsync(It.IsAny<int>())).ReturnsAsync(new Data.Models.News { Id = 1 });
                MockNewsService.Setup(ns => ns.UpdateNewsAsync(It.IsAny<Data.Models.News>())).ReturnsAsync(true);

                var result = await Controller.SaveNews(1, new AddNewsRequest());
                var response = TestUtils.GetResponseFromResult<AddNewsResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(1, response.NewsItem.Id);
            }
        }
    }
}
