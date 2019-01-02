namespace CrimsonDev.Gameteki.Api.Tests.Controllers
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Security.Claims;
    using System.Security.Principal;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.ApiControllers;
    using CrimsonDev.Gameteki.Api.Models.Api.Request;
    using CrimsonDev.Gameteki.Api.Models.Api.Response;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Api.Tests.Helpers;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;
    using StackExchange.Redis;

    [TestClass]
    public class MessageControllerTests
    {
        private const string TestUser = "TestUser";

        private Mock<IMessageService> MessageServiceMock { get; set; }
        private Mock<IUserService> UserServiceMock { get; set; }
        private Mock<IConnectionMultiplexer> RedisConnectionMock { get; set; }
        private Mock<ISubscriber> SubscriberMock { get; set; }
        private Mock<ILogger<MessageController>> LoggerMock { get; set; }

        private MessageController Controller { get; set; }

        [TestInitialize]
        public void SetupTest()
        {
            MessageServiceMock = new Mock<IMessageService>();
            UserServiceMock = new Mock<IUserService>();
            RedisConnectionMock = new Mock<IConnectionMultiplexer>();
            LoggerMock = new Mock<ILogger<MessageController>>();
            SubscriberMock = new Mock<ISubscriber>();

            RedisConnectionMock.Setup(c => c.GetSubscriber(It.IsAny<object>())).Returns(SubscriberMock.Object);

            Controller = new MessageController(MessageServiceMock.Object, UserServiceMock.Object, RedisConnectionMock.Object, LoggerMock.Object)
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
        public class GetMessages : MessageControllerTests
        {
            [TestMethod]
            public async Task WhenCalledReturnsMessagesResponse()
            {
                MessageServiceMock.Setup(ns => ns.GetLatestLobbyMessagesAsync()).ReturnsAsync(new List<LobbyMessage> { new LobbyMessage { Sender = new GametekiUser() } });

                var result = await Controller.GetMessages();
                var response = TestUtils.GetResponseFromResult<GetMessagesResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(1, response.Messages.Count);
            }
        }

        [TestClass]
        public class AddMessage : MessageControllerTests
        {
            [TestMethod]
            public async Task WhenUserNotFoundReturnsFailure()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync((GametekiUser)null);

                var result = await Controller.AddMessage(new AddMessageRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenAddFailsReturnsFailure()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                MessageServiceMock.Setup(ms => ms.AddMessageAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync((LobbyMessage)null);

                var result = await Controller.AddMessage(new AddMessageRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenAddFailsReturnsMessage()
            {
                var user = TestUtils.GetRandomUser();
                var lobbyMessage = new LobbyMessage
                {
                    Id = 1,
                    MessageDateTime = DateTime.UtcNow,
                    MessageText = "Test Message",
                    Sender = user
                };

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);
                MessageServiceMock.Setup(ms => ms.AddMessageAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(lobbyMessage);

                var result = await Controller.AddMessage(new AddMessageRequest());
                var response = TestUtils.GetResponseFromResult<AddMessageResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(lobbyMessage.Id, response.NewMessage.Id);
                Assert.AreEqual(lobbyMessage.MessageText, response.NewMessage.Message);
                Assert.AreEqual(lobbyMessage.MessageDateTime, response.NewMessage.Time);
                Assert.AreEqual(lobbyMessage.Sender.UserName, response.NewMessage.User);

                SubscriberMock.Verify(s => s.PublishAsync(It.IsAny<RedisChannel>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()), Times.Once);
            }
        }

        [TestClass]
        public class RemoveMessage : MessageControllerTests
        {
            [TestMethod]
            public async Task WhenUserNotFoundReturnsFailure()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync((GametekiUser)null);

                var result = await Controller.RemoveMessage(1);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenMessageNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                MessageServiceMock.Setup(ms => ms.FindByIdAsync(It.IsAny<int>())).ReturnsAsync((LobbyMessage)null);

                var result = await Controller.RemoveMessage(1);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenRemoveFailsReturnsFailure()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                MessageServiceMock.Setup(ms => ms.FindByIdAsync(It.IsAny<int>())).ReturnsAsync(new LobbyMessage());
                MessageServiceMock.Setup(ms => ms.UpdateMessageAsync(It.IsAny<LobbyMessage>())).ReturnsAsync(false);

                var result = await Controller.RemoveMessage(1);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenRemoveSucceedsReturnsSuccess()
            {
                var lobbyMessage = new LobbyMessage();

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                MessageServiceMock.Setup(ms => ms.FindByIdAsync(It.IsAny<int>())).ReturnsAsync(lobbyMessage);
                MessageServiceMock.Setup(ms => ms.UpdateMessageAsync(It.IsAny<LobbyMessage>())).ReturnsAsync(true);

                var result = await Controller.RemoveMessage(1);
                var response = TestUtils.GetResponseFromResult<DeleteMessageResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.IsTrue(lobbyMessage.Removed);
                Assert.AreEqual(DateTime.UtcNow.Date, lobbyMessage.RemovedDateTime.Date);
                Assert.AreEqual(1, response.MessageId);

                SubscriberMock.Verify(s => s.PublishAsync(It.IsAny<RedisChannel>(), It.IsAny<RedisValue>(), It.IsAny<CommandFlags>()), Times.Once);
            }
        }
    }
}
