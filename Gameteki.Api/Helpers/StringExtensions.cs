namespace CrimsonDev.Gameteki.Api.Helpers
{
    using System.Security.Cryptography;
    using System.Text;

    internal static class StringExtensions
    {
        public static string Md5Hash(this string source)
        {
            using (var md5 = MD5.Create())
            {
                var result = md5.ComputeHash(Encoding.ASCII.GetBytes(source));

                var builder = new StringBuilder();

                foreach (var character in result)
                {
                    builder.Append(character.ToString("X2"));
                }

                return builder.ToString();
            }
        }
    }
}