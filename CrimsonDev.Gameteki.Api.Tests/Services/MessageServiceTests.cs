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
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Logging;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    [TestClass]
    [ExcludeFromCodeCoverage]
    public class MessageServiceTests
    {
        private readonly string testUser = Guid.NewGuid().ToString();
        private Mock<ILogger<MessageService>> LoggerMock { get; set; }

        private IGametekiDbContext DbContext { get; set; }
        private IMessageService Service { get; set; }

        [TestInitialize]
        public void SetupTest()
        {
            LoggerMock = new Mock<ILogger<MessageService>>();

            var options = new DbContextOptionsBuilder<GametekiDbContext>()
                .UseInMemoryDatabase(databaseName: "MessageServiceTests")
                .Options;
            DbContext = new GametekiDbContext(options);

            for (var i = 0; i < 500; i++)
            {
                var message = TestUtils.GetRandomLobbyMessage();

                if (i % 2 == 0)
                {
                    message.Removed = true;
                    message.RemovedById = Guid.NewGuid().ToString();
                    message.RemovedDateTime = DateTime.UtcNow;
                }

                DbContext.LobbyMessage.Add(message);
                DbContext.SaveChangesAsync().GetAwaiter().GetResult();
            }

            Service = new MessageService(DbContext, LoggerMock.Object);
        }

        [TestCleanup]
        public void CleanupTest()
        {
            DbContext?.Dispose();
        }

        [TestClass]
        public class GetLatestLobbyMessagesAsync : MessageServiceTests
        {
            [TestMethod]
            public async Task WhenCalledReturnsTop100MessagesAndNoneRemoved()
            {
                var orderedMessages = DbContext.LobbyMessage.Where(n => !n.Removed).OrderBy(n => n.MessageDateTime);
                var result = await Service.GetLatestLobbyMessagesAsync();

                Assert.AreEqual(100, result.Count);
                Assert.AreEqual(orderedMessages.First().MessageText, result.First().MessageText);
                Assert.IsFalse(result.Any(m => m.Removed));
            }
        }

        [TestClass]
        public class FindByIdAsync : MessageServiceTests
        {
            [TestMethod]
            public async Task WhenIdNotFoundReturnsNull()
            {
                var result = await Service.FindByIdAsync(-1);

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenIdIsFoundReturnsResult()
            {
                var expected = await DbContext.LobbyMessage.FirstAsync();

                var result = await Service.FindByIdAsync(expected.Id);

                Assert.AreEqual(expected, result);
            }
        }

        [TestClass]
        public class AddMessageAsync : MessageServiceTests
        {
            private Mock<IGametekiDbContext> DbContextMock { get; set; }

            [TestInitialize]
            public new void SetupTest()
            {
                DbContextMock = new Mock<IGametekiDbContext>();
                LoggerMock = new Mock<ILogger<MessageService>>();

                DbContextMock.Setup(c => c.LobbyMessage).Returns(new List<LobbyMessage>().ToMockDbSet().Object);

                Service = new MessageService(DbContextMock.Object, LoggerMock.Object);
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUserIdIsNullThrowsException()
            {
                await Service.AddMessageAsync(null, "TestMessage");
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenMessageIsNullThrowsException()
            {
                await Service.AddMessageAsync(testUser, null);
            }

            [TestMethod]
            public async Task WhenAddFailsReturnsNull()
            {
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.AddMessageAsync(testUser, "TestMessage");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenAddSucceedsReturnsAddedItem()
            {
                var result = await Service.AddMessageAsync(testUser, "TestMessage");

                Assert.IsNotNull(result);
                Assert.AreEqual(testUser, result.SenderId);
                Assert.AreEqual(DateTime.UtcNow.Date, result.MessageDateTime.Date);
                Assert.AreEqual("TestMessage", result.MessageText);
            }
        }

        [TestClass]
        public class UpdateMessageAsync : MessageServiceTests
        {
            private Mock<IGametekiDbContext> DbContextMock { get; set; }

            [TestInitialize]
            public new void SetupTest()
            {
                DbContextMock = new Mock<IGametekiDbContext>();
                LoggerMock = new Mock<ILogger<MessageService>>();

                DbContextMock.Setup(c => c.LobbyMessage).Returns(new List<LobbyMessage>().ToMockDbSet().Object);

                Service = new MessageService(DbContextMock.Object, LoggerMock.Object);
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenMessageIsNullThrowsException()
            {
                await Service.UpdateMessageAsync(null);
            }

            [TestMethod]
            public async Task WhenUpdateFailedReturnsFalse()
            {
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.UpdateMessageAsync(new LobbyMessage());

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenUpdateSucceedsReturnsTrue()
            {
                var result = await Service.UpdateMessageAsync(new LobbyMessage());

                Assert.IsTrue(result);
            }
        }
    }
}
