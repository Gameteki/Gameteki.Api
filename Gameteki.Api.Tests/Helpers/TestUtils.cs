namespace CrimsonDev.Gameteki.Api.Tests.Helpers
{
    using System;
    using System.Collections.Generic;
    using Bogus;
    using CrimsonDev.Gameteki.Data.Models;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.VisualStudio.TestTools.UnitTesting;

    public static class TestUtils
    {
        public static RegisterAccountRequest GetRandomAccount()
        {
            var faker = new Faker();
            return new RegisterAccountRequest
            {
                Email = faker.Person.Email,
                Password = faker.Internet.Password(),
                Username = faker.Internet.UserName()
            };
        }

        public static GametekiUser GetRandomUser()
        {
            var faker = new Faker();
            return new GametekiUser
            {
                RefreshTokens = new List<RefreshToken>(),
                UserRoles = new List<GametekiUserRole>(),
                BlockList = new List<BlockListEntry>(),
                Id = Guid.NewGuid().ToString(),
                UserName = faker.Person.UserName,
                Email = faker.Person.Email,
                EmailConfirmed = true,

                Settings = new UserSettings()
            };
        }

        public static News GetRandomNews()
        {
            var faker = new Faker();

            return new News
            {
                Id = faker.Random.Int(min: 0),
                PosterId = Guid.NewGuid().ToString(),
                Text = faker.Lorem.Text(),
                DatePublished = faker.Date.Recent()
            };
        }

        public static LobbyMessage GetRandomLobbyMessage()
        {
            var faker = new Faker();

            return new LobbyMessage
            {
                Id = faker.Random.Int(min: 0),
                Removed = false,
                MessageDateTime = faker.Date.Recent(),
                MessageText = faker.Lorem.Text(),
                SenderId = Guid.NewGuid().ToString()
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
            where TResponse : ApiResponse
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
