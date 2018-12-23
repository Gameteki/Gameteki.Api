namespace CrimsonDev.Gameteki.Api.Tests.Helpers
{
    using System;
    using System.Collections.Generic;
    using Bogus;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public static class TestUtils
    {
        public static Data.Models.GametekiUser GetRandomUser()
        {
            var faker = new Faker();
            return new Data.Models.GametekiUser
            {
                RefreshTokens = new List<Data.Models.RefreshToken>(),
                UserRoles = new List<Data.Models.GametekiUserRole>(),
                BlockList = new List<Data.Models.BlockListEntry>(),
                Id = Guid.NewGuid().ToString(),
                UserName = faker.Person.UserName,
                Email = faker.Person.Email,
                EmailConfirmed = true,

                Settings = new Data.Models.UserSettings()
            };
        }

        public static Data.Models.News GetRandomNews()
        {
            var faker = new Faker();

            return new Data.Models.News
            {
                Id = faker.Random.Int(min: 0),
                PosterId = Guid.NewGuid().ToString(),
                Text = faker.Lorem.Text(),
                DatePublished = faker.Date.Recent()
            };
        }

        public static TValue GetValueFromResultObject<TResult, TValue>(IActionResult result)
            where TResult : ObjectResult
            where TValue : class
        {
            Assert.IsInstanceOfType(result, typeof(TResult));

            var badRequestResult = result as TResult;
            Assert.IsNotNull(badRequestResult);

            Assert.IsInstanceOfType(badRequestResult.Value, typeof(TValue));
            var value = badRequestResult.Value as TValue;
            Assert.IsNotNull(value);

            return value;
        }

        public static TResponse GetResponseFromResult<TResponse>(IActionResult result)
            where TResponse : Models.Api.Response.ApiResponse
        {
            Assert.IsInstanceOfType(result, typeof(JsonResult));

            var jsonResult = result as JsonResult;
            Assert.IsNotNull(jsonResult);

            var response = jsonResult.Value as TResponse;
            Assert.IsNotNull(response);

            return response;
        }
    }
}
