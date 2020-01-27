namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Models.Patreon;

    public interface IPatreonService
    {
        Task<TokenResponse> LinkAccountAsync(string code, string redirectUrl);
        Task<TokenResponse> LinkAccountAsync(string code, Uri redirectUrl);
    }
}
