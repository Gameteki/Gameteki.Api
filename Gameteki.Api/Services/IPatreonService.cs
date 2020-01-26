namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Threading.Tasks;

    public interface IPatreonService
    {
        Task LinkAccountAsync(string code, string redirectUrl);
    }
}
