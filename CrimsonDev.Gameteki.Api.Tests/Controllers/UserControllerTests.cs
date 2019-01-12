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
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Moq;

    [TestClass]
    public class UserControllerTests
    {
        private const string TestUser = "TestUser";

        private Mock<IUserService> UserServiceMock { get; set; }

        private UserController Controller { get; set; }

        [TestInitialize]
        public void SetupTest()
        {
            UserServiceMock = new Mock<IUserService>();

            Controller = new UserController(UserServiceMock.Object)
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
        public class FindUser : UserControllerTests
        {
            [TestMethod]
            public async Task WhenUserNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync((Data.Models.GametekiUser)null);

                var result = await Controller.FindUser(TestUser);

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUserFoundReturnsUser()
            {
                var user = TestUtils.GetRandomUser();
                user.EmailConfirmed = true;
                user.Disabled = true;

                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(user);

                var result = await Controller.FindUser(user.UserName);
                var response = TestUtils.GetResponseFromResult<FindUserResponse>(result);

                Assert.IsTrue(response.Success);
                Assert.AreEqual(user.EmailConfirmed, response.User.Verified);
                Assert.AreEqual(user.Disabled, response.User.Disabled);
            }
        }

        [TestClass]
        public class UpdateUser : UserControllerTests
        {
            [TestMethod]
            public async Task WhenUserNotFoundReturnsNotFound()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync((Data.Models.GametekiUser)null);

                var result = await Controller.UpdateUser(TestUser, new ApiUserAdmin());

                Assert.IsInstanceOfType(result, typeof(NotFoundResult));
            }

            [TestMethod]
            public async Task WhenUpdateFailsReturnsFailureResponse()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us => us.UpdateUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Failed());

                var result = await Controller.UpdateUser(TestUser, new ApiUserAdmin());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenUserCannotManagePermissionsDoesNotSetPermissions()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us => us.UpdateUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);

                var result = await Controller.UpdateUser(TestUser, new ApiUserAdmin());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsTrue(response.Success);

                UserServiceMock.Verify(us => us.UpdatePermissionsAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<Data.Models.Permissions>()), Times.Never);
            }

            [TestMethod]
            public async Task WhenUserCanManagePermissionsAndSettingFailsReturnsFailure()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us => us.UpdateUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);
                UserServiceMock.Setup(us => us.UpdatePermissionsAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<Data.Models.Permissions>())).ReturnsAsync(false);

                Controller.HttpContext.User.AddIdentity(new ClaimsIdentity(new List<Claim> { new Claim(ClaimTypes.Role, Roles.PermissionsManager) }));

                var result = await Controller.UpdateUser(TestUser, new ApiUserAdmin());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsFalse(response.Success);
            }

            [TestMethod]
            public async Task WhenUserCanManagePermissionsAndSettingSucceedsReturnsSuccess()
            {
                UserServiceMock.Setup(us => us.GetUserFromUsernameAsync(It.IsAny<string>())).ReturnsAsync(TestUtils.GetRandomUser());
                UserServiceMock.Setup(us => us.UpdateUserAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<string>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);
                UserServiceMock.Setup(us => us.UpdatePermissionsAsync(It.IsAny<Data.Models.GametekiUser>(), It.IsAny<Data.Models.Permissions>())).ReturnsAsync(true);

                Controller.HttpContext.User.AddIdentity(new ClaimsIdentity(new List<Claim> { new Claim(ClaimTypes.Role, Roles.PermissionsManager) }));

                var result = await Controller.UpdateUser(TestUser, new ApiUserAdmin());
                var response = TestUtils.GetResponseFromResult<ApiResponse>(result);

                Assert.IsTrue(response.Success);
            }
        }
    }
}
