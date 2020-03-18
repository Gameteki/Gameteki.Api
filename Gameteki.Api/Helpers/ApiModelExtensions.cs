namespace CrimsonDev.Gameteki.Api.Helpers
{
    using System;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models;
    using CrimsonDev.Gameteki.Data.Models.Api;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

    public static class ApiModelExtensions
    {
        public static ApiUser ToApiUser(this GametekiUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var apiUser = new ApiUser();

            PopulateApiUser(user, apiUser);

            return apiUser;
        }

        public static ApiUserAdmin ToApiUserAdmin(this GametekiUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var adminUser = new ApiUserAdmin();

            PopulateApiUser(user, adminUser);

            adminUser.Disabled = user.Disabled;

            // adminUser.Verified = user.EmailConfirmed;
            return adminUser;
        }

        public static ApiLobbyMessage ToApiLobbyMessage(this LobbyMessage message)
        {
            if (message == null)
            {
                throw new ArgumentNullException(nameof(message));
            }

            return new ApiLobbyMessage
            {
                Id = message.Id,
                User = message.Sender.UserName,
                Message = message.MessageText,
                Time = message.MessageDateTime
            };
        }

        private static void PopulateApiUser(GametekiUser user, ApiUser apiUser)
        {
            apiUser.Id = user.Id;
            apiUser.Username = user.UserName;
            apiUser.Email = user.Email;
            apiUser.Settings = new ApiSettings
            {
                Background = user.Settings.Background,
                CardSize = user.Settings.CardSize
            };
            apiUser.Permissions = new GametekiPermissions();
            apiUser.CustomData = user.CustomData;

            foreach (var userRole in user.UserRoles)
            {
                switch (userRole.Role.Name)
                {
                    case Roles.UserManager:
                        apiUser.Permissions.CanManageUsers = true;
                        break;
                    case Roles.PermissionsManager:
                        apiUser.Permissions.CanManagePermissions = true;
                        break;
                    case Roles.ChatManager:
                        apiUser.Permissions.CanModerateChat = true;
                        break;
                    case Roles.GameManager:
                        apiUser.Permissions.CanManageGames = true;
                        break;
                    case Roles.NewsManager:
                        apiUser.Permissions.CanEditNews = true;
                        break;
                    case Roles.NodeManager:
                        apiUser.Permissions.CanManageNodes = true;
                        break;
                    case Roles.Admin:
                        apiUser.Permissions.IsAdmin = true;
                        break;
                    case Roles.Contributor:
                        apiUser.Permissions.IsContributor = true;
                        break;
                    case Roles.Supporter:
                        apiUser.Permissions.IsSupporter = true;
                        break;
                }
            }
        }
    }
}
