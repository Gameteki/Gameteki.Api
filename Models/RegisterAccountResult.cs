namespace CrimsonDev.Gameteki.Api.Models
{
    using System.Collections.Generic;
    using CrimsonDev.Gameteki.Data.Models;

    public class RegisterAccountResult
    {
        public RegisterAccountResult()
        {
            Errors = new Dictionary<string, string>();
        }

        public GametekiUser User { get; set; }
        public bool Success { get; set; }
        public IDictionary<string, string> Errors { get; private set; }

        public static RegisterAccountResult Failed(string error, string field = "")
        {
            var result = new RegisterAccountResult
            {
                Success = false
            };

            result.Errors.Add(field, error);

            return result;
        }

        public static RegisterAccountResult Succeeded(GametekiUser newUser)
        {
            return new RegisterAccountResult
            {
                Success = true,
                User = newUser
            };
        }
    }
}
