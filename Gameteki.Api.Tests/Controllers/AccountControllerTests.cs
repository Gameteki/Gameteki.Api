namespace CrimsonDev.Gameteki.Api.Tests.Controllers
{
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Linq;
    using System.Net;
    using System.Security.Claims;
    using System.Security.Principal;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.ApiControllers;
    using CrimsonDev.Gameteki.Api.Helpers;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Api.Tests.Helpers;
    using CrimsonDev.Gameteki.Data.Models;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using CrimsonDev.Gameteki.Data.Models.Config;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    [TestClass]
    [ExcludeFromCodeCoverage]
    public class AccountControllerTests
    {
        private const string TestUser = "TestUser";

        private Mock<IUserService> UserServiceMock { get; set; }
        private Mock<ILogger<AccountController>> LoggerMock { get; set; }
        private Mock<IHttpClient> HttpClientMock { get; set; }

        private IOptions<GametekiApiOptions> ApiOptions { get; set; }
        private AccountController Controller { get; set; }

        [TestInitialize]
        public void SetupTest()
        {
            UserServiceMock = new Mock<IUserService>();
            LoggerMock = new Mock<ILogger<AccountController>>();
            HttpClientMock = new Mock<IHttpClient>();

            ApiOptions = new OptionsWrapper<GametekiApiOptions>(new GametekiApiOptions { ImagePath = Path.DirectorySeparatorChar.ToString() });

            Controller = new AccountController(UserServiceMock.Object, HttpClientMock.Object, ApiOptions, LoggerMock.Object)
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
        public class RegisterAccount : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenRegisterReturnsFailedReturnsError()
            {
                var request = new RegisterAccountRequest
                {
                    Email = "test@example.com"
                };

                UserServiceMock
                    .Setup(us => us.RegisterUserAsync(It.IsAny<RegisterAccountRequest>(), It.IsAny<string>()))
                    .ReturnsAsync(RegisterAccountResult.Failed("Test Error"));

                var result = await Controller.RegisterAccount(request);
                var errorValue = TestUtils.GetValueFromResultObject<BadRequestObjectResult, SerializableError>(result);

                CollectionAssert.Contains(errorValue.Keys, string.Empty);
            }

            [TestMethod]
            public async Task WhenRegisterSucceedsReturnsSuccess()
            {
                var request = new RegisterAccountRequest
                {
                    Email = "test@example.com"
                };

                UserServiceMock
                    .Setup(us => us.RegisterUserAsync(It.IsAny<RegisterAccountRequest>(), It.IsAny<string>()))
                    .ReturnsAsync(RegisterAccountResult.Succeeded(new GametekiUser { Settings = new UserSettings() }));

                var result = await Controller.RegisterAccount(request);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }

            [TestMethod]
            public async Task WhenActivationDisabledDontSendVerificationEmail()
            {
                var request = new RegisterAccountRequest
                {
                    Email = "test@example.com"
                };

                ApiOptions.Value.AccountVerification = false;

                UserServiceMock
                    .Setup(us => us.RegisterUserAsync(It.IsAny<RegisterAccountRequest>(), It.IsAny<string>()))
                    .ReturnsAsync(RegisterAccountResult.Succeeded(new GametekiUser { Settings = new UserSettings() }));

                var result = await Controller.RegisterAccount(request);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsTrue(response.Success);
                UserServiceMock.Verify(
                    us => us.SendActivationEmailAsync(It.IsAny<GametekiUser>(), It.IsAny<AccountVerificationModel>()),
                    Times.Never);
            }

            [TestMethod]
            public async Task WhenActivationEnabledSendVerificationEmail()
            {
                var request = new RegisterAccountRequest
                {
                    Email = "test@example.com"
                };

                ApiOptions.Value.AccountVerification = true;

                UserServiceMock
                    .Setup(us => us.RegisterUserAsync(It.IsAny<RegisterAccountRequest>(), It.IsAny<string>()))
                    .ReturnsAsync(RegisterAccountResult.Succeeded(new GametekiUser { Settings = new UserSettings() }));

                var result = await Controller.RegisterAccount(request);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsTrue(response.Success);
                UserServiceMock.Verify(
                    us => us.SendActivationEmailAsync(It.IsAny<GametekiUser>(), It.IsAny<AccountVerificationModel>()),
                    Times.Once);
            }
        }

        [TestClass]
        public class ActivateAccount : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenValidateFailsReturnsFailureResponse()
            {
                UserServiceMock.Setup(us => us.ValidateUserAsync(It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(false);

                var result = await Controller.ActivateAccount(new VerifyAccountRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenValidateSucceedsReturnsSuccessResponse()
            {
                UserServiceMock.Setup(us => us.ValidateUserAsync(It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(true);

                var result = await Controller.ActivateAccount(new VerifyAccountRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }

        [TestClass]
        public class Login : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenLoginFailsReturnsUnauthorised()
            {
                UserServiceMock
                    .Setup(us => us.LoginUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync((LoginResult)null);

                var result = await Controller.Login(new LoginRequest());

                Assert.IsInstanceOfType(result, typeof(UnauthorizedResult));
            }

            [TestMethod]
            public async Task WhenUserIsDisabledReturnsFailureResponse()
            {
                UserServiceMock
                    .Setup(us => us.LoginUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(new LoginResult
                    {
                        User = new GametekiUser
                        {
                            EmailConfirmed = false
                        }
                    });

                var result = await Controller.Login(new LoginRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenLoginSucceedsReturnsSuccess()
            {
                var returnedUser = TestUtils.GetRandomUser();
                UserServiceMock
                    .Setup(us => us.LoginUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(new LoginResult { User = returnedUser });

                var result = await Controller.Login(new LoginRequest());
                var response = TestUtils.GetResponseFromResult<LoginResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(response.User.Username, returnedUser.UserName);
            }
        }

        [TestClass]
        public class Logout : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenLogoutFailsReturnsFailureResponse()
            {
                UserServiceMock.Setup(us => us.LogoutUserAsync(It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(false);

                var result = await Controller.Logout(new RefreshTokenRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenLogoutSucceedsReturnsSuccessResponse()
            {
                UserServiceMock.Setup(us => us.LogoutUserAsync(It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(true);

                var result = await Controller.Logout(new RefreshTokenRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }

        [TestClass]
        public class CheckAuth : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenGetUsernameFailsReturnsFailureResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((GametekiUser)null);

                var result = await Controller.CheckAuth();
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenGetUsernameSucceedsReturnsSuccessResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());

                var result = await Controller.CheckAuth();
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }

        [TestClass]
        public class GetNewToken : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenRefreshTokenFailsReturnsFailureResponse()
            {
                UserServiceMock
                    .Setup(us => us.RefreshTokenAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync((LoginResult)null);

                var result = await Controller.GetNewToken(new RefreshTokenRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenRefreshTokenSucceedsReturnsSuccessResponse()
            {
                var loginResult = new LoginResult
                {
                    User = TestUtils.GetRandomUser(),
                    RefreshToken = "refresh",
                    Token = "token"
                };

                UserServiceMock
                    .Setup(us => us.RefreshTokenAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(loginResult);

                var result = await Controller.GetNewToken(new RefreshTokenRequest());
                var response = TestUtils.GetResponseFromResult<LoginResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(loginResult.Token, response.Token);
                Assert.AreEqual(loginResult.RefreshToken, response.RefreshToken);
                Assert.AreEqual(loginResult.User.UserName, response.User.Username);
            }
        }

        [TestClass]
        public class UpdateProfile : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenUsernameDoesNotMatchLoggedInUserReturnsNotFound()
            {
                var result = await Controller.UpdateProfile("NotFound", new UpdateProfileRequest());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((GametekiUser)null);

                var result = await Controller.UpdateProfile(TestUser, new UpdateProfileRequest());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUpdateUserFailedReturnsFailureResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(
                        IdentityResult.Failed(new IdentityError { Code = "Test", Description = "Test Error" }));

                var result = await Controller.UpdateProfile(
                    TestUser,
                    new UpdateProfileRequest { Settings = new ApiSettings(), Email = "Test@example.com" });
                var response = TestUtils.GetValueFromResultObject<BadRequestObjectResult, SerializableError>(result);

                Assert.IsTrue(response.Any());
            }

            [TestMethod]
            public async Task WhenNewPasswordSpecifiedAndClearTokensFailsReturnsFailureResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(IdentityResult.Success);
                UserServiceMock.Setup(us => us.ClearRefreshTokensAsync(It.IsAny<GametekiUser>())).ReturnsAsync(false);

                var request = new UpdateProfileRequest
                {
                    CurrentPassword = "current",
                    NewPassword = "new",
                    Settings = new ApiSettings(),
                    Email = "Test@example.com"
                };
                var result = await Controller.UpdateProfile(TestUser, request);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenNewPasswordSpecifiedAndCreateTokenFailsReturnsFailureResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(IdentityResult.Success);
                UserServiceMock.Setup(us => us.ClearRefreshTokensAsync(It.IsAny<GametekiUser>())).ReturnsAsync(true);
                UserServiceMock.Setup(us => us.CreateRefreshTokenAsync(It.IsAny<GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync((RefreshToken)null);

                var request = new UpdateProfileRequest
                {
                    CurrentPassword = "current",
                    NewPassword = "new",
                    Settings = new ApiSettings(),
                    Email = "Test@example.com"
                };
                var result = await Controller.UpdateProfile(TestUser, request);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenUpdateSucceedsReturnsUpdateResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(IdentityResult.Success);

                var result = await Controller.UpdateProfile(
                    TestUser,
                    new UpdateProfileRequest { Settings = new ApiSettings(), Email = "Test@example.com" });
                var response = TestUtils.GetResponseFromResult<UpdateProfileResponse>(result);

                Assert.IsTrue(response.Success);
            }

            [TestMethod]
            public async Task WhenNewPasswordSpecifiedAndSucceedsReturnsUpdateResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(IdentityResult.Success);
                UserServiceMock.Setup(us => us.ClearRefreshTokensAsync(It.IsAny<GametekiUser>())).ReturnsAsync(true);
                UserServiceMock.Setup(us => us.CreateRefreshTokenAsync(It.IsAny<GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(new RefreshToken());

                var request = new UpdateProfileRequest
                {
                    CurrentPassword = "current",
                    NewPassword = "new",
                    Settings = new ApiSettings(),
                    Email = "Test@example.com"
                };
                var result = await Controller.UpdateProfile(TestUser, request);
                var response = TestUtils.GetResponseFromResult<UpdateProfileResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }

        [TestClass]
        public class GetUserSessions : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenUsernameDoesNotMatchLoggedInUserReturnsNotFound()
            {
                var result = await Controller.GetUserSessions("NotFound");

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((GametekiUser)null);

                var result = await Controller.GetUserSessions(TestUser);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameFoundReturnsSessionList()
            {
                var user = TestUtils.GetRandomUser();
                user.RefreshTokens = new List<RefreshToken>
                {
                    new RefreshToken
                    {
                        IpAddress = "127.0.0.1",
                        Token = "token1"
                    }
                };

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(user);

                var result = await Controller.GetUserSessions(TestUser);
                var response = TestUtils.GetResponseFromResult<GetUserSessionsResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(user.RefreshTokens.First().IpAddress, response.Tokens.First().Ip);
            }
        }

        [TestClass]
        public class DeleteUserSession : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenUsernameDoesNotMatchLoggedInUserReturnsNotFound()
            {
                var result = await Controller.DeleteUserSession("NotFound", 1);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenTokenNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetRefreshTokenByIdAsync(It.IsAny<int>()))
                    .ReturnsAsync((RefreshToken)null);

                var result = await Controller.DeleteUserSession(TestUser, 1);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenDeleteTokenFailsReturnsFailure()
            {
                UserServiceMock.Setup(us => us.GetRefreshTokenByIdAsync(It.IsAny<int>()))
                    .ReturnsAsync(new RefreshToken());
                UserServiceMock.Setup(us => us.DeleteRefreshTokenAsync(It.IsAny<RefreshToken>())).ReturnsAsync(false);

                var result = await Controller.DeleteUserSession(TestUser, 1);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenDeleteTokenSucceedsReturnsDeleteResponse()
            {
                UserServiceMock.Setup(us => us.GetRefreshTokenByIdAsync(It.IsAny<int>()))
                    .ReturnsAsync(new RefreshToken { Id = 1 });
                UserServiceMock.Setup(us => us.DeleteRefreshTokenAsync(It.IsAny<RefreshToken>())).ReturnsAsync(true);

                var result = await Controller.DeleteUserSession(TestUser, 1);
                var response = TestUtils.GetResponseFromResult<DeleteSessionResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(1, response.TokenId);
            }
        }

        [TestClass]
        public class GetBlockList : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenUsernameDoesNotMatchLoggedInUserReturnsNotFound()
            {
                var result = await Controller.GetBlockList("NotFound");

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((GametekiUser)null);

                var result = await Controller.GetBlockList(TestUser);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameFoundReturnsBlockListResponse()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<BlockListEntry>
                {
                    new BlockListEntry { BlockedUser = "Test" },
                    new BlockListEntry { BlockedUser = "Test2" }
                };

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                var result = await Controller.GetBlockList(TestUser);
                var response = TestUtils.GetResponseFromResult<GetBlockListResponse>(result);

                Assert.IsTrue(response.Success);
                CollectionAssert.Contains(response.BlockList, "Test");
            }
        }

        [TestClass]
        public class AddBlockListEntry : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenUsernameDoesNotMatchLoggedInUserReturnsNotFound()
            {
                var result = await Controller.AddBlockListEntry("NotFound", new BlockListEntryRequest());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((GametekiUser)null);

                var result = await Controller.AddBlockListEntry(TestUser, new BlockListEntryRequest());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenEntryAlreadyOnListReturnsFailureResponse()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<BlockListEntry> { new BlockListEntry { BlockedUser = "Test" } };

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                var result =
                    await Controller.AddBlockListEntry(TestUser, new BlockListEntryRequest { Username = "test" });
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenAddingEntryFailsReturnsFailureResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us => us.AddBlockListEntryAsync(It.IsAny<GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(false);

                var result = await Controller.AddBlockListEntry(TestUser, new BlockListEntryRequest());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenAddingEntrySucceedsReturnsSuccessResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us => us.AddBlockListEntryAsync(It.IsAny<GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(true);

                var result =
                    await Controller.AddBlockListEntry(TestUser, new BlockListEntryRequest { Username = "Test" });
                var response = TestUtils.GetResponseFromResult<BlockListEntryResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual("Test", response.Username);
            }
        }

        [TestClass]
        public class RemoveBlockListEntry : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenUsernameDoesNotMatchLoggedInUserReturnsNotFound()
            {
                var result = await Controller.RemoveBlockListEntry("NotFound", "Blocked");

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((GametekiUser)null);

                var result = await Controller.RemoveBlockListEntry(TestUser, "Blocked");

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenEntryNotOnListReturnsNotFound()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<BlockListEntry> { new BlockListEntry { BlockedUser = "Test" } };

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                var result = await Controller.RemoveBlockListEntry(TestUser, "notfound");
                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenBlockListRemoveFailsReturnsFailureResponse()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<BlockListEntry> { new BlockListEntry { BlockedUser = "Test" } };

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);
                UserServiceMock.Setup(us => us.RemoveBlockListEntryAsync(It.IsAny<GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(false);

                var result = await Controller.RemoveBlockListEntry(TestUser, "Test");
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenBlockListSucceedsReturnsSuccessResponse()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<BlockListEntry> { new BlockListEntry { BlockedUser = "Test" } };

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);
                UserServiceMock.Setup(us => us.RemoveBlockListEntryAsync(It.IsAny<GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(true);

                var result = await Controller.RemoveBlockListEntry(TestUser, "Test");
                var response = TestUtils.GetResponseFromResult<BlockListEntryResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual("Test", response.Username);
            }
        }

        [TestClass]
        public class UpdateAvatar : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenUserNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync((GametekiUser)null);

                var result = await Controller.UpdateAvatar("NotFound");

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenGravatarDisabledReturnsRandomAvatar()
            {
                var user = TestUtils.GetRandomUser();

                user.EmailHash = user.Email.Md5Hash();
                user.Settings.EnableGravatar = false;

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                await Controller.UpdateAvatar(user.UserName);

                HttpClientMock.Verify(hc => hc.DownloadFileAsync($"https://www.gravatar.com/avatar/{user.EmailHash}?d=identicon&s=24", It.IsAny<string>()), Times.Never);
                HttpClientMock.Verify(hc => hc.DownloadFileAsync(It.IsAny<string>(), It.IsAny<string>()), Times.Once);
            }

            [TestMethod]
            public async Task WhenGravatarEnabledReturnsAvatar()
            {
                var user = TestUtils.GetRandomUser();

                user.EmailHash = user.Email.Md5Hash();
                user.Settings.EnableGravatar = true;

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                await Controller.UpdateAvatar(user.UserName);

                HttpClientMock.Verify(hc => hc.DownloadFileAsync($"https://www.gravatar.com/avatar/{user.EmailHash.ToLower()}?d=identicon&s=24", It.IsAny<string>()), Times.Once);
            }

            [TestMethod]
            public async Task WhenDownloadFailsReturnsFailure()
            {
                var user = TestUtils.GetRandomUser();

                user.Settings.EnableGravatar = false;

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                var result = await Controller.UpdateAvatar(user.UserName);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenDownloadSucceedsReturnsSuccess()
            {
                var user = TestUtils.GetRandomUser();

                user.Settings.EnableGravatar = false;

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);
                HttpClientMock.Setup(hc => hc.DownloadFileAsync(It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(true);

                var result = await Controller.UpdateAvatar(user.UserName);
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }
    }
}
