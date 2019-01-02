namespace CrimsonDev.Gameteki.Api.Helpers
{
    using CrimsonDev.Gameteki.Api.Models.Api;
    using CrimsonDev.Gameteki.Data.Constants;
    using CrimsonDev.Gameteki.Data.Models;

    public static class ApiModelExtensions
    {
        public static ApiUser ToApiUser(this GametekiUser user)
        {
            var apiUser = new ApiUser();

            PopulateApiUser(user, apiUser);

            return apiUser;
        }

        public static ApiUserAdmin ToApiUserAdmin(this GametekiUser user)
        {
            var adminUser = new ApiUserAdmin();

            PopulateApiUser(user, adminUser);

            adminUser.Disabled = user.Disabled;
            adminUser.Verified = user.EmailConfirmed;

            return adminUser;
        }

        public static ApiToken ToApiToken(this RefreshToken token)
        {
            return new ApiToken
            {
                Id = token.Id,
                Ip = token.IpAddress,
                LastUsed = token.LastUsed
            };
        }

        public static ApiLobbyMessage ToApiLobbyMessage(this LobbyMessage message)
        {
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
            apiUser.EnableGravatar = user.Settings.EnableGravatar;
            apiUser.Settings = new ApiSettings
            {
                Background = user.Settings.Background,
                CardSize = user.Settings.CardSize
            };
            apiUser.Permissions = new Permissions();
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
                }
            }
        }
    }
}
