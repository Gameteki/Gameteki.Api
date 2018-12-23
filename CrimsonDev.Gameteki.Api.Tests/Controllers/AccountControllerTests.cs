namespace CrimsonDev.Gameteki.Api.Tests.Controllers
{
    using System.Collections.Generic;
    using System.Diagnostics.CodeAnalysis;
    using System.Linq;
    using System.Net;
    using System.Security.Claims;
    using System.Security.Principal;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.ApiControllers;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Api.Tests.Helpers;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Logging;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    [TestClass]
    [ExcludeFromCodeCoverage]
    public class AccountControllerTests
    {
        private const string TestUser = "TestUser";

        private Mock<IUserService> MockUserService { get; set; }
        private Mock<ILogger<AccountController>> MockLogger { get; set; }

        private AccountController Controller { get; set; }

        [TestInitialize]
        public void SetupTest()
        {
            MockUserService = new Mock<IUserService>();
            MockLogger = new Mock<ILogger<AccountController>>();

            Controller = new AccountController(MockUserService.Object, MockLogger.Object)
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
            public async Task WhenEmailIsInUseThenReturnsError()
            {
                MockUserService.Setup(us => us.IsEmailInUseAsync(It.IsAny<string>())).ReturnsAsync(true);

                var result = await Controller.RegisterAccount(new Models.Api.Request.RegisterAccountRequest());
                var errorValue = TestUtils.GetValueFromResultObject<BadRequestObjectResult, SerializableError>(result);

                CollectionAssert.Contains(errorValue.Keys, "email");
            }

            [TestMethod]
            public async Task WhenUsernameIsInUseReturnsError()
            {
                MockUserService.Setup(us => us.IsUsernameInUseAsync(It.IsAny<string>())).ReturnsAsync(true);

                var result = await Controller.RegisterAccount(new Models.Api.Request.RegisterAccountRequest());
                var errorValue = TestUtils.GetValueFromResultObject<BadRequestObjectResult, SerializableError>(result);

                CollectionAssert.Contains(errorValue.Keys, "username");
            }

            [TestMethod]
            public async Task WhenRegisterReturnsFailedReturnsError()
            {
                var request = new Models.Api.Request.RegisterAccountRequest
                {
                    Email = "test@example.com"
                };

                MockUserService.Setup(us => us.RegisterUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(
                        IdentityResult.Failed(new IdentityError { Code = "Test", Description = "Test Error" }));

                var result = await Controller.RegisterAccount(request);
                var errorValue = TestUtils.GetValueFromResultObject<BadRequestObjectResult, SerializableError>(result);

                CollectionAssert.Contains(errorValue.Keys, string.Empty);
            }

            [TestMethod]
            public async Task WhenRegisterSucceedsReturnsSuccess()
            {
                var request = new Models.Api.Request.RegisterAccountRequest
                {
                    Email = "test@example.com"
                };

                MockUserService.Setup(us => us.RegisterUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(IdentityResult.Success);

                var result = await Controller.RegisterAccount(request);
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }

        [TestClass]
        public class ActivateAccount : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenValidateFailsReturnsFailureResponse()
            {
                MockUserService.Setup(us => us.ValidateUserAsync(It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(false);

                var result = await Controller.ActivateAccount(new Models.Api.Request.VerifyAccountRequest());
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenValidateSucceedsReturnsSuccessResponse()
            {
                MockUserService.Setup(us => us.ValidateUserAsync(It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(true);

                var result = await Controller.ActivateAccount(new Models.Api.Request.VerifyAccountRequest());
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }

        [TestClass]
        public class Login : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenLoginFailsReturnsUnauthorised()
            {
                MockUserService
                    .Setup(us => us.LoginUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync((LoginResult)null);

                var result = await Controller.Login(new Models.Api.Request.LoginRequest());

                Assert.IsInstanceOfType(result, typeof(UnauthorizedResult));
            }

            [TestMethod]
            public async Task WhenUserIsDisabledReturnsFailureResponse()
            {
                MockUserService
                    .Setup(us => us.LoginUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(new LoginResult
                    {
                        User = new Data.Models.GametekiUser
                        {
                            EmailConfirmed = false
                        }
                    });

                var result = await Controller.Login(new Models.Api.Request.LoginRequest());
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenLoginSucceedsReturnsSuccess()
            {
                var returnedUser = TestUtils.GetRandomUser();
                MockUserService
                    .Setup(us => us.LoginUserAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(new LoginResult { User = returnedUser });

                var result = await Controller.Login(new Models.Api.Request.LoginRequest());
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.LoginResponse>(result);

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
                MockUserService.Setup(us => us.LogoutUserAsync(It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(false);

                var result = await Controller.Logout(new Models.Api.Request.RefreshTokenRequest());
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenLogoutSucceedsReturnsSuccessResponse()
            {
                MockUserService.Setup(us => us.LogoutUserAsync(It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(true);

                var result = await Controller.Logout(new Models.Api.Request.RefreshTokenRequest());
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }

        [TestClass]
        public class CheckAuth : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenGetUsernameFailsReturnsFailureResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((Data.Models.GametekiUser)null);

                var result = await Controller.CheckAuth();
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenGetUsernameSucceedsReturnsSuccessResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());

                var result = await Controller.CheckAuth();
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }

        [TestClass]
        public class GetNewToken : AccountControllerTests
        {
            [TestMethod]
            public async Task WhenRefreshTokenFailsReturnsFailureResponse()
            {
                MockUserService
                    .Setup(us => us.RefreshTokenAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync((LoginResult)null);

                var result = await Controller.GetNewToken(new Models.Api.Request.RefreshTokenRequest());
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

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

                MockUserService
                    .Setup(us => us.RefreshTokenAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(loginResult);

                var result = await Controller.GetNewToken(new Models.Api.Request.RefreshTokenRequest());
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.LoginResponse>(result);

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
                var result = await Controller.UpdateProfile("NotFound", new Models.Api.Request.UpdateProfileRequest());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameNotFoundReturnsNotFound()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((Data.Models.GametekiUser)null);

                var result = await Controller.UpdateProfile(TestUser, new Models.Api.Request.UpdateProfileRequest());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUpdateUserFailedReturnsFailureResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                MockUserService.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(
                        IdentityResult.Failed(new IdentityError { Code = "Test", Description = "Test Error" }));

                var result = await Controller.UpdateProfile(
                    TestUser,
                    new Models.Api.Request.UpdateProfileRequest { Settings = new Models.Api.ApiSettings() });
                var response = TestUtils.GetValueFromResultObject<BadRequestObjectResult, SerializableError>(result);

                Assert.IsTrue(response.Any());
            }

            [TestMethod]
            public async Task WhenNewPasswordSpecifiedAndClearTokensFailsReturnsFailureResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                MockUserService.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(IdentityResult.Success);
                MockUserService.Setup(us => us.ClearRefreshTokensAsync(It.IsAny<Data.Models.GametekiUser>())).ReturnsAsync(false);

                var request = new Models.Api.Request.UpdateProfileRequest
                {
                    CurrentPassword = "current",
                    NewPassword = "new",
                    Settings = new Models.Api.ApiSettings()
                };
                var result = await Controller.UpdateProfile(TestUser, request);
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenNewPasswordSpecifiedAndCreateTokenFailsReturnsFailureResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                MockUserService.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(IdentityResult.Success);
                MockUserService.Setup(us => us.ClearRefreshTokensAsync(It.IsAny<Data.Models.GametekiUser>())).ReturnsAsync(true);
                MockUserService.Setup(us => us.CreateRefreshTokenAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync((Data.Models.RefreshToken)null);

                var request = new Models.Api.Request.UpdateProfileRequest
                {
                    CurrentPassword = "current",
                    NewPassword = "new",
                    Settings = new Models.Api.ApiSettings()
                };
                var result = await Controller.UpdateProfile(TestUser, request);
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenUpdateSucceedsReturnsUpdateResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                MockUserService.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(IdentityResult.Success);

                var result = await Controller.UpdateProfile(
                    TestUser,
                    new Models.Api.Request.UpdateProfileRequest { Settings = new Models.Api.ApiSettings() });
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.UpdateProfileResponse>(result);

                Assert.IsTrue(response.Success);
            }

            [TestMethod]
            public async Task WhenNewPasswordSpecifiedAndSucceedsReturnsUpdateResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                MockUserService.Setup(us =>
                        us.UpdateUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>(), It.IsAny<string>()))
                    .ReturnsAsync(IdentityResult.Success);
                MockUserService.Setup(us => us.ClearRefreshTokensAsync(It.IsAny<Data.Models.GametekiUser>())).ReturnsAsync(true);
                MockUserService.Setup(us => us.CreateRefreshTokenAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(new Data.Models.RefreshToken());

                var request = new Models.Api.Request.UpdateProfileRequest
                {
                    CurrentPassword = "current",
                    NewPassword = "new",
                    Settings = new Models.Api.ApiSettings()
                };
                var result = await Controller.UpdateProfile(TestUser, request);
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.UpdateProfileResponse>(result);

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
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((Data.Models.GametekiUser)null);

                var result = await Controller.GetUserSessions(TestUser);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameFoundReturnsSessionList()
            {
                var user = TestUtils.GetRandomUser();
                user.RefreshTokens = new List<Data.Models.RefreshToken>
                {
                    new Data.Models.RefreshToken
                    {
                        IpAddress = "127.0.0.1",
                        Token = "token1"
                    }
                };

                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(user);

                var result = await Controller.GetUserSessions(TestUser);
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.GetUserSessionsResponse>(result);

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
                MockUserService.Setup(us => us.GetRefreshTokenByIdAsync(It.IsAny<int>()))
                    .ReturnsAsync((Data.Models.RefreshToken)null);

                var result = await Controller.DeleteUserSession(TestUser, 1);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenDeleteTokenFailsReturnsFailure()
            {
                MockUserService.Setup(us => us.GetRefreshTokenByIdAsync(It.IsAny<int>()))
                    .ReturnsAsync(new Data.Models.RefreshToken());
                MockUserService.Setup(us => us.DeleteRefreshTokenAsync(It.IsAny<Data.Models.RefreshToken>())).ReturnsAsync(false);

                var result = await Controller.DeleteUserSession(TestUser, 1);
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenDeleteTokenSucceedsReturnsDeleteResponse()
            {
                MockUserService.Setup(us => us.GetRefreshTokenByIdAsync(It.IsAny<int>()))
                    .ReturnsAsync(new Data.Models.RefreshToken { Id = 1 });
                MockUserService.Setup(us => us.DeleteRefreshTokenAsync(It.IsAny<Data.Models.RefreshToken>())).ReturnsAsync(true);

                var result = await Controller.DeleteUserSession(TestUser, 1);
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.DeleteSessionResponse>(result);

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
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((Data.Models.GametekiUser)null);

                var result = await Controller.GetBlockList(TestUser);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameFoundReturnsBlockListResponse()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<Data.Models.BlockListEntry>
                {
                    new Data.Models.BlockListEntry { BlockedUser = "Test" },
                    new Data.Models.BlockListEntry { BlockedUser = "Test2" }
                };

                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                var result = await Controller.GetBlockList(TestUser);
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.GetBlockListResponse>(result);

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
                var result = await Controller.AddBlockListEntry("NotFound", new Models.Api.Request.BlockListEntryRequest());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUsernameNotFoundReturnsNotFound()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((Data.Models.GametekiUser)null);

                var result = await Controller.AddBlockListEntry(TestUser, new Models.Api.Request.BlockListEntryRequest());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenEntryAlreadyOnListReturnsFailureResponse()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<Data.Models.BlockListEntry> { new Data.Models.BlockListEntry { BlockedUser = "Test" } };

                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                var result =
                    await Controller.AddBlockListEntry(TestUser, new Models.Api.Request.BlockListEntryRequest { Username = "test" });
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenAddingEntryFailsReturnsFailureResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                MockUserService.Setup(us => us.AddBlockListEntryAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(false);

                var result = await Controller.AddBlockListEntry(TestUser, new Models.Api.Request.BlockListEntryRequest());
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenAddingEntrySucceedsReturnsSuccessResponse()
            {
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync(TestUtils.GetRandomUser());
                MockUserService.Setup(us => us.AddBlockListEntryAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(true);

                var result =
                    await Controller.AddBlockListEntry(TestUser, new Models.Api.Request.BlockListEntryRequest { Username = "Test" });
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.BlockListEntryResponse>(result);

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
                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>()))
                    .ReturnsAsync((Data.Models.GametekiUser)null);

                var result = await Controller.RemoveBlockListEntry(TestUser, "Blocked");

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenEntryNotOnListReturnsNotFound()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<Data.Models.BlockListEntry> { new Data.Models.BlockListEntry { BlockedUser = "Test" } };

                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                var result = await Controller.RemoveBlockListEntry(TestUser, "notfound");
                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenBlockListRemoveFailsReturnsFailureResponse()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<Data.Models.BlockListEntry> { new Data.Models.BlockListEntry { BlockedUser = "Test" } };

                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);
                MockUserService.Setup(us => us.RemoveBlockListEntryAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(false);

                var result = await Controller.RemoveBlockListEntry(TestUser, "Test");
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenBlockListSucceedsReturnsSuccessResponse()
            {
                var user = TestUtils.GetRandomUser();
                user.BlockList = new List<Data.Models.BlockListEntry> { new Data.Models.BlockListEntry { BlockedUser = "Test" } };

                MockUserService.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);
                MockUserService.Setup(us => us.RemoveBlockListEntryAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>()))
                    .ReturnsAsync(true);

                var result = await Controller.RemoveBlockListEntry(TestUser, "Test");
                var response = TestUtils.GetResponseFromResult<Models.Api.Response.BlockListEntryResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual("Test", response.Username);
            }
        }
    }
}
