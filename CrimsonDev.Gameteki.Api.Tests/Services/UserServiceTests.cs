﻿namespace CrimsonDev.Gameteki.Api.Tests.Services
{
    using System;
    using System.Collections.Generic;
    using System.Data;
    using System.Diagnostics.CodeAnalysis;
    using System.IdentityModel.Tokens.Jwt;
    using System.Linq;
    using System.Security.Claims;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Api.Tests.Helpers;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models;
    using CrimsonDev.Gameteki.Data.Models.Config;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.IdentityModel.Tokens;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    [TestClass]
    [ExcludeFromCodeCoverage]
    public class UserServiceTests
    {
        private Mock<IGametekiDbContext> DbContextMock { get; set; }
        private Mock<IUserStore<GametekiUser>> UserStoreMock { get; set; }
        private Mock<UserManager<GametekiUser>> UserManagerMock { get; set; }
        private Mock<IOptions<AuthTokenOptions>> AuthTokenOptionsMock { get; set; }
        private Mock<IOptions<GametekiApiOptions>> GametekiOptionsMock { get; set; }
        private Mock<IEmailSender> EmailSenderMock { get; set; }
        private Mock<IViewRenderService> ViewRenderServiceMock { get; set; }
        private Mock<ILogger<UserService>> LoggerMock { get; set; }

        private List<GametekiUser> TestUsers { get; set; }

        private IUserService Service { get; set; }

        [TestInitialize]
        public void SetupTest()
        {
            DbContextMock = new Mock<IGametekiDbContext>();
            UserStoreMock = new Mock<IUserStore<GametekiUser>>();
            UserManagerMock = new Mock<UserManager<GametekiUser>>(UserStoreMock.Object, null, null, null, null, null, null, null, null);
            AuthTokenOptionsMock = new Mock<IOptions<AuthTokenOptions>>();
            GametekiOptionsMock = new Mock<IOptions<GametekiApiOptions>>();
            EmailSenderMock = new Mock<IEmailSender>();
            ViewRenderServiceMock = new Mock<IViewRenderService>();
            LoggerMock = new Mock<ILogger<UserService>>();

            AuthTokenOptionsMock.Setup(at => at.Value).Returns(new AuthTokenOptions
            {
                Issuer = "http://test.com",
                Key = "really super awesome key of testing"
            });
            GametekiOptionsMock.Setup(lo => lo.Value).Returns(new GametekiApiOptions { ApplicationName = "TestApp" });

            TestUsers = new List<GametekiUser>();
            for (var i = 0; i < 10; i++)
            {
                TestUsers.Add(TestUtils.GetRandomUser());
            }

            DbContextMock.Setup(context => context.Users).Returns(TestUsers.ToMockDbSet().Object);

            Service = new UserService(
                DbContextMock.Object,
                UserManagerMock.Object,
                AuthTokenOptionsMock.Object,
                GametekiOptionsMock.Object,
                EmailSenderMock.Object,
                ViewRenderServiceMock.Object,
                LoggerMock.Object);
        }

        private static string GenerateTokenForUser(string username, string issuer, string keySeed)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keySeed));

            var jwt = new JwtSecurityToken(
                issuer,
                audience: issuer,
                claims: new[] { new Claim(ClaimTypes.Name, username) },
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddMinutes(value: 5),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256));

            return new JwtSecurityTokenHandler().WriteToken(jwt);
        }

        [TestClass]
        public class RegisterUserAsync : UserServiceTests
        {
            [TestMethod]
            public async Task WhenUsernameAlreadyInUseReturnsFailure()
            {
                var account = TestUtils.GetRandomAccount();
                account.Username = TestUsers.First().UserName;
                var result = await Service.RegisterUserAsync(account, "password");

                Assert.IsFalse(result.Success);
            }

            [TestMethod]
            public async Task WhenEmailAlreadyInUseReturnsFailure()
            {
                var account = TestUtils.GetRandomAccount();
                account.Email = TestUsers.First().Email;
                var result = await Service.RegisterUserAsync(account, "password");

                Assert.IsFalse(result.Success);
            }

            [TestMethod]
            public async Task WhenCreateUserFailsReturnsFalse()
            {
                UserManagerMock.Setup(um => um.CreateAsync(It.IsAny<GametekiUser>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Failed(new IdentityError()));

                var result = await Service.RegisterUserAsync(TestUtils.GetRandomAccount(), "password");

                Assert.IsFalse(result.Success);
            }

            [TestMethod]
            public async Task WhenCreateThrowsExceptionReturnsFalse()
            {
                UserManagerMock.Setup(um => um.CreateAsync(It.IsAny<GametekiUser>(), It.IsAny<string>())).ThrowsAsync(new Exception());

                var result = await Service.RegisterUserAsync(TestUtils.GetRandomAccount(), "password");

                Assert.IsFalse(result.Success);
            }

            [TestMethod]
            public async Task WhenCreateReturnsSuccessReturnsTrue()
            {
                UserManagerMock.Setup(um => um.CreateAsync(It.IsAny<GametekiUser>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);

                var result = await Service.RegisterUserAsync(TestUtils.GetRandomAccount(), "password");

                Assert.IsTrue(result.Success);
            }
        }

        [TestClass]
        public class SendActivationEmailAsync : UserServiceTests
        {
            [TestMethod]
            public async Task WhenTokenGenerateFailsReturnsFalse()
            {
                UserManagerMock.Setup(um => um.GenerateEmailConfirmationTokenAsync(It.IsAny<GametekiUser>())).ThrowsAsync(new Exception());

                var result = await Service.SendActivationEmailAsync(TestUtils.GetRandomUser(), new AccountVerificationModel());

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenRenderFailsReturnsFalse()
            {
                UserManagerMock.Setup(um => um.GenerateEmailConfirmationTokenAsync(It.IsAny<GametekiUser>())).ReturnsAsync("Code");
                ViewRenderServiceMock.Setup(vr => vr.RenderToStringAsync(It.IsAny<string>(), It.IsAny<AccountVerificationModel>())).ThrowsAsync(new Exception());

                var result = await Service.SendActivationEmailAsync(TestUtils.GetRandomUser(), new AccountVerificationModel());

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenSendEmailFailsReturnsFalse()
            {
                UserManagerMock.Setup(um => um.GenerateEmailConfirmationTokenAsync(It.IsAny<GametekiUser>())).ReturnsAsync("Code");
                EmailSenderMock.Setup(es => es.SendEmailAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>())).ThrowsAsync(new Exception());

                var result = await Service.SendActivationEmailAsync(TestUtils.GetRandomUser(), new AccountVerificationModel());

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenSuccessfulReturnsTrue()
            {
                UserManagerMock.Setup(um => um.GenerateEmailConfirmationTokenAsync(It.IsAny<GametekiUser>())).ReturnsAsync("Code");
                var result = await Service.SendActivationEmailAsync(TestUtils.GetRandomUser(), new AccountVerificationModel());

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class ValidateUserAsync : UserServiceTests
        {
            [TestMethod]
            public async Task WhenUserIdIsNullReturnsFalse()
            {
                var result = await Service.ValidateUserAsync(null, "token");

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenTokenIsNullReturnsFalse()
            {
                var result = await Service.ValidateUserAsync("UserId", null);

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenUserNotFoundReturnsFalse()
            {
                var result = await Service.ValidateUserAsync("NotFound", "token");

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenConfirmEmailFailsReturnsFalse()
            {
                UserManagerMock.Setup(um => um.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                UserManagerMock.Setup(um => um.ConfirmEmailAsync(It.IsAny<GametekiUser>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Failed());

                var result = await Service.ValidateUserAsync("UserId", "token");

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenConfirmEmailSucceedsReturnsTrue()
            {
                UserManagerMock.Setup(um => um.FindByIdAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                UserManagerMock.Setup(um => um.ConfirmEmailAsync(It.IsAny<GametekiUser>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);

                var result = await Service.ValidateUserAsync("UserId", "token");

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class LoginUserAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUsernameIsNullThrows()
            {
                var result = await Service.LoginUserAsync(null, "password", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenPasswordIsNullThrows()
            {
                var result = await Service.LoginUserAsync("TestUser", null, "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenUserNotFoundReturnsNull()
            {
                var result = await Service.LoginUserAsync("TestUser", "password", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenIncorrectPasswordReturnsNull()
            {
                var user = TestUsers.First();

                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>().ToMockDbSet().Object);
                DbContextMock.Setup(c => c.BlockListEntry).Returns(new List<BlockListEntry>().ToMockDbSet().Object);
                DbContextMock.Setup(c => c.Users).Returns(new List<GametekiUser> { user }.ToMockDbSet().Object);

                UserManagerMock.Setup(um => um.CheckPasswordAsync(It.IsAny<GametekiUser>(), It.IsAny<string>())).ReturnsAsync(false);

                var result = await Service.LoginUserAsync(user.UserName, "password", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenUserIsDisabledReturnsNull()
            {
                var user = TestUsers.First();
                user.Disabled = true;

                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>().ToMockDbSet().Object);
                DbContextMock.Setup(c => c.Users).Returns(new List<GametekiUser> { user }.ToMockDbSet().Object);
                DbContextMock.Setup(c => c.BlockListEntry).Returns(new List<BlockListEntry>().ToMockDbSet().Object);

                UserManagerMock.Setup(um => um.CheckPasswordAsync(It.IsAny<GametekiUser>(), It.IsAny<string>())).ReturnsAsync(true);

                var result = await Service.LoginUserAsync(user.UserName, "password", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenCorrectPasswordReturnsResult()
            {
                var user = TestUsers.First();

                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>().ToMockDbSet().Object);
                DbContextMock.Setup(c => c.BlockListEntry).Returns(new List<BlockListEntry>().ToMockDbSet().Object);

                UserManagerMock.Setup(um => um.CheckPasswordAsync(It.IsAny<GametekiUser>(), It.IsAny<string>())).ReturnsAsync(true);

                var result = await Service.LoginUserAsync(user.UserName, "password", "127.0.0.1");

                Assert.IsNotNull(result);
                Assert.AreEqual(user, result.User);
                Assert.IsNotNull(result.Token);
                Assert.IsNotNull(result.RefreshToken);
            }
        }

        [TestClass]
        public class CreateResetTokenAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUserIsNullThrows()
            {
                var result = await Service.CreateRefreshTokenAsync(null, "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenIpAddressIsNullThrows()
            {
                var result = await Service.CreateRefreshTokenAsync(TestUtils.GetRandomUser(), null);

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenDatabaseExceptionReturnsNull()
            {
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new DBConcurrencyException());

                var result = await Service.CreateRefreshTokenAsync(TestUtils.GetRandomUser(), "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenSuccessfulReturnsToken()
            {
                var user = TestUsers.First();
                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>().ToMockDbSet().Object);

                var result = await Service.CreateRefreshTokenAsync(user, "127.0.0.1");

                Assert.IsNotNull(result);
                Assert.AreEqual("127.0.0.1", result.IpAddress);
                Assert.IsNotNull(result.Token);
                Assert.AreEqual(user.Id, result.UserId);
            }
        }

        [TestClass]
        public class GetUserFromUsernameAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUsernameIsNullThrows()
            {
                var result = await Service.GetUserFromUsernameAsync(null);

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenUserNotFoundReturnsNull()
            {
                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>().ToMockDbSet().Object);
                DbContextMock.Setup(c => c.BlockListEntry).Returns(new List<BlockListEntry>().ToMockDbSet().Object);

                var result = await Service.GetUserFromUsernameAsync("NotFound");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenUserFoundReturnsUser()
            {
                var user = TestUsers.First();

                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>().ToMockDbSet().Object);
                DbContextMock.Setup(c => c.BlockListEntry).Returns(new List<BlockListEntry>().ToMockDbSet().Object);

                var result = await Service.GetUserFromUsernameAsync(user.UserName);

                Assert.IsNotNull(result);
                Assert.AreEqual(user, result);
            }
        }

        [TestClass]
        public class RefreshTokenAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenTokenIsNullThrows()
            {
                var result = await Service.RefreshTokenAsync(null, "RefreshToken", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenRefreshTokenIsNullThrows()
            {
                var result = await Service.RefreshTokenAsync("Token", null, "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenInvalidTokenReturnsNull()
            {
                var result = await Service.RefreshTokenAsync("InvalidToken", "RefreshToken", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenIncorrectTokenReturnsNull()
            {
                var token = GenerateTokenForUser("TestUser", AuthTokenOptionsMock.Object.Value.Issuer, "WrongKeyThatIsStillLongEnoughToBeValid");
                var result = await Service.RefreshTokenAsync(token, "RefreshToken", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenNoTokensForUserReturnsNull()
            {
                var tokens = new List<RefreshToken>
                    { new RefreshToken { Token = "RefreshToken", User = TestUtils.GetRandomUser() } };
                var token = GenerateTokenForUser("TestUser", AuthTokenOptionsMock.Object.Value.Issuer, AuthTokenOptionsMock.Object.Value.Key);

                DbContextMock.Setup(c => c.RefreshToken).Returns(tokens.ToMockDbSet().Object);

                var result = await Service.RefreshTokenAsync(token, "RefreshToken", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenNoMatchingTokenReturnsNull()
            {
                var tokens = new List<RefreshToken>
                    { new RefreshToken { Token = "SomeRandomString", User = TestUtils.GetRandomUser() } };
                var token = GenerateTokenForUser("TestUser", AuthTokenOptionsMock.Object.Value.Issuer, AuthTokenOptionsMock.Object.Value.Key);
                DbContextMock.Setup(c => c.RefreshToken).Returns(tokens.ToMockDbSet().Object);

                var result = await Service.RefreshTokenAsync(token, "RefreshToken", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenRefreshTokenUpdateFailsReturnsNull()
            {
                var user = TestUtils.GetRandomUser();
                var tokens = new List<RefreshToken>
                {
                    new RefreshToken
                    {
                        Token = "RefreshToken",
                        User = user
                    }
                };
                var token = GenerateTokenForUser(user.UserName, AuthTokenOptionsMock.Object.Value.Issuer, AuthTokenOptionsMock.Object.Value.Key);

                DbContextMock.Setup(c => c.RefreshToken).Returns(tokens.ToMockDbSet().Object);
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new DBConcurrencyException());

                var result = await Service.RefreshTokenAsync(token, "RefreshToken", "127.0.0.1");

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenTokensRefreshesSuccessfullyReturnsResult()
            {
                var user = TestUsers.First();
                user.UserRoles.Add(new GametekiUserRole { Role = new GametekiRole { Name = "Role" }, User = user });
                var tokens = new List<RefreshToken> { new RefreshToken { Token = "RefreshToken", User = user } };
                var token = GenerateTokenForUser(user.UserName, AuthTokenOptionsMock.Object.Value.Issuer, AuthTokenOptionsMock.Object.Value.Key);

                DbContextMock.Setup(c => c.RefreshToken).Returns(tokens.ToMockDbSet().Object);

                var result = await Service.RefreshTokenAsync(token, "RefreshToken", "127.0.0.1");

                Assert.IsNotNull(result);
                Assert.IsNotNull(result.RefreshToken);
                Assert.IsNotNull(result.Token);
            }
        }

        [TestClass]
        public class UpdatePermissionsAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUserIsNullThrowsException()
            {
                await Service.UpdatePermissionsAsync(null, new Permissions());
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenPermissionsIsNullThrowsException()
            {
                await Service.UpdatePermissionsAsync(new GametekiUser(), null);
            }

            [TestMethod]
            public async Task WhenSaveChangesFailsReturnsFalse()
            {
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.UpdatePermissionsAsync(TestUtils.GetRandomUser(), new Permissions());

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenPermissionsAddedCallsAdd()
            {
                var user = TestUtils.GetRandomUser();
                var newPermissions = new Permissions
                {
                    CanEditNews = true,
                    CanManageUsers = true,
                    CanManageGames = true
                };

                DbContextMock.Setup(c => c.Roles).Returns(new List<GametekiRole>
                {
                    new GametekiRole { Name = Roles.NewsManager },
                    new GametekiRole { Name = Roles.UserManager }
                }.ToMockDbSet().Object);

                var result = await Service.UpdatePermissionsAsync(user, newPermissions);

                Assert.IsTrue(result);
                Assert.AreEqual(2, user.UserRoles.Count);
            }

            [TestMethod]
            public async Task WhenPermissionsRemovedCallsRemove()
            {
                var user = TestUtils.GetRandomUser();
                user.UserRoles = new List<GametekiUserRole>
                {
                    new GametekiUserRole { Role = new GametekiRole(Roles.NewsManager) },
                    new GametekiUserRole { Role = new GametekiRole(Roles.UserManager) },
                    new GametekiUserRole { Role = new GametekiRole(Roles.ChatManager) }
                };

                DbContextMock.Setup(c => c.Roles).Returns(new List<GametekiRole>
                {
                    new GametekiRole { Name = Roles.NewsManager },
                    new GametekiRole { Name = Roles.UserManager }
                }.ToMockDbSet().Object);

                var result = await Service.UpdatePermissionsAsync(user, new Permissions());

                Assert.IsTrue(result);
                Assert.AreEqual(0, user.UserRoles.Count);
            }
        }

        [TestClass]
        public class LogoutUserAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenTokenIsNullThrowsException()
            {
                await Service.LogoutUserAsync(null, "Refresh");
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenRefreshTokenIsNullThrowsException()
            {
                await Service.LogoutUserAsync("Token", null);
            }

            [TestMethod]
            public async Task WhenTokenIsInvalidReturnsFalse()
            {
                var result = await Service.LogoutUserAsync("InvalidToken", "RefreshToken");

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenRefreshTokenNotFoundReturnsFalse()
            {
                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>
                {
                    new RefreshToken { Token = "RefreshToken", User = new GametekiUser { UserName = "NotFound" } }
                }.ToMockDbSet().Object);

                var result = await Service.LogoutUserAsync(
                    GenerateTokenForUser("TestUser", AuthTokenOptionsMock.Object.Value.Issuer, AuthTokenOptionsMock.Object.Value.Key),
                    "RefreshToken");

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenSaveChangesFailsReturnsFalse()
            {
                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>
                {
                    new RefreshToken { Token = "RefreshToken", User = new GametekiUser { UserName = "TestUser" } }
                }.ToMockDbSet().Object);
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.LogoutUserAsync(
                    GenerateTokenForUser("TestUser", AuthTokenOptionsMock.Object.Value.Issuer, AuthTokenOptionsMock.Object.Value.Key),
                    "RefreshToken");

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenSucceedsReturnsTrue()
            {
                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>
                {
                    new RefreshToken { Token = "RefreshToken", User = new GametekiUser { UserName = "TestUser" } }
                }.ToMockDbSet().Object);

                var result = await Service.LogoutUserAsync(
                    GenerateTokenForUser("TestUser", AuthTokenOptionsMock.Object.Value.Issuer, AuthTokenOptionsMock.Object.Value.Key),
                    "RefreshToken");

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class UpdateUserAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUserIsNullThrowsException()
            {
                await Service.UpdateUserAsync(null);
            }

            [TestMethod]
            public async Task WhenUpdateFailsReturnsFalse()
            {
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.UpdateUserAsync(new GametekiUser());

                Assert.IsFalse(result.Succeeded);
            }

            [TestMethod]
            public async Task WhenUpdateSucceedsAndNoPasswordChangeReturnsTrue()
            {
                var result = await Service.UpdateUserAsync(new GametekiUser());

                Assert.IsTrue(result.Succeeded);
            }

            [TestMethod]
            public async Task WhenPasswordChangeFailsReturnsFalse()
            {
                UserManagerMock.Setup(um => um.ChangePasswordAsync(It.IsAny<GametekiUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Failed());

                var result = await Service.UpdateUserAsync(new GametekiUser(), "old", "new");

                Assert.IsFalse(result.Succeeded);
            }

            [TestMethod]
            public async Task WhenPasswordChangeSucceedsReturnsTrue()
            {
                UserManagerMock.Setup(um => um.ChangePasswordAsync(It.IsAny<GametekiUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);

                var result = await Service.UpdateUserAsync(new GametekiUser(), "old", "new");

                Assert.IsTrue(result.Succeeded);
            }
        }

        [TestClass]
        public class AddBlockListEntryAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUserIsNullThrowsException()
            {
                await Service.AddBlockListEntryAsync(null, "Test");
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUsernameIsNullThrowsException()
            {
                await Service.AddBlockListEntryAsync(new GametekiUser(), null);
            }

            [TestMethod]
            public async Task WhenAddFailsReturnsFalse()
            {
                DbContextMock.Setup(c => c.BlockListEntry).Returns(new List<BlockListEntry>().ToMockDbSet().Object);
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.AddBlockListEntryAsync(new GametekiUser(), "Test");

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenAddSucceedsReturnsTrue()
            {
                DbContextMock.Setup(c => c.BlockListEntry).Returns(new List<BlockListEntry>().ToMockDbSet().Object);

                var result = await Service.AddBlockListEntryAsync(new GametekiUser(), "Test");

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class RemoveBlockListEntryAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUserIsNullThrowsException()
            {
                await Service.RemoveBlockListEntryAsync(null, "Test");
            }

            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUsernameIsNullThrowsException()
            {
                await Service.RemoveBlockListEntryAsync(new GametekiUser(), null);
            }

            [TestMethod]
            public async Task WhenDeleteFailsReturnsFalse()
            {
                DbContextMock.Setup(c => c.BlockListEntry).Returns(new List<BlockListEntry>().ToMockDbSet().Object);
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.RemoveBlockListEntryAsync(new GametekiUser(), "Test");

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenDeleteSucceedsReturnsTrue()
            {
                DbContextMock.Setup(c => c.BlockListEntry).Returns(new List<BlockListEntry>().ToMockDbSet().Object);

                var result = await Service.RemoveBlockListEntryAsync(new GametekiUser(), "Test");

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class ClearRefreshTokensAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUserIsNullThrowsException()
            {
                await Service.ClearRefreshTokensAsync(null);
            }

            [TestMethod]
            public async Task WhenSaveFailsReturnsFalse()
            {
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.ClearRefreshTokensAsync(new GametekiUser { RefreshTokens = new List<RefreshToken>() });

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenSaveSucceedsReturnsTrue()
            {
                var result = await Service.ClearRefreshTokensAsync(new GametekiUser { RefreshTokens = new List<RefreshToken>() });

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class DeleteRefreshTokenAsync : UserServiceTests
        {
            [TestMethod]
            [ExpectedException(typeof(ArgumentNullException))]
            public async Task WhenUserIsNullThrowsException()
            {
                await Service.DeleteRefreshTokenAsync(null);
            }

            [TestMethod]
            public async Task WhenSaveFailsReturnsFalse()
            {
                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>().ToMockDbSet().Object);
                DbContextMock.Setup(c => c.SaveChangesAsync(It.IsAny<CancellationToken>())).ThrowsAsync(new Exception());

                var result = await Service.DeleteRefreshTokenAsync(new RefreshToken());

                Assert.IsFalse(result);
            }

            [TestMethod]
            public async Task WhenSaveSucceedsReturnsTrue()
            {
                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken>().ToMockDbSet().Object);

                var result = await Service.DeleteRefreshTokenAsync(new RefreshToken());

                Assert.IsTrue(result);
            }
        }

        [TestClass]
        public class GetRefreshTokenByIdAsync : UserServiceTests
        {
            [TestMethod]
            public async Task WhenTokenNotFoundReturnsNull()
            {
                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken> { new RefreshToken { Id = 1 } }.ToMockDbSet().Object);

                var result = await Service.GetRefreshTokenByIdAsync(2);

                Assert.IsNull(result);
            }

            [TestMethod]
            public async Task WhenTokenFoundReturnsToken()
            {
                var userId = Guid.NewGuid().ToString();

                DbContextMock.Setup(c => c.RefreshToken).Returns(new List<RefreshToken> { new RefreshToken { Id = 1, UserId = userId } }.ToMockDbSet().Object);

                var result = await Service.GetRefreshTokenByIdAsync(1);

                Assert.IsNotNull(result);
                Assert.AreEqual(userId, result.UserId);
            }
        }
    }
}
