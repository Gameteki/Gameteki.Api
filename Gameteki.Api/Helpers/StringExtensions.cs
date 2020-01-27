namespace CrimsonDev.Gameteki.Api.Helpers
{
    using System.Globalization;
    using System.Security.Cryptography;
    using System.Text;

    internal static class StringExtensions
    {
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA5351:Do Not Use Broken Cryptographic Algorithms", Justification = "MD5 is rubbish, but gravatar still uses it")]
        public static string Md5Hash(this string source)
        {
            using var md5 = MD5.Create();
            var result = md5.ComputeHash(Encoding.ASCII.GetBytes(source));

            var builder = new StringBuilder();

            foreach (var character in result)
            {
                builder.Append(character.ToString("X2", CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }
    }
}