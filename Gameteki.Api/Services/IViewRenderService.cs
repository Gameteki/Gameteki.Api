namespace CrimsonDev.Gameteki.Api.Services
{
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc.RazorPages;

    public interface IViewRenderService
    {
        Task<string> RenderToStringAsync<T>(string pageName, T model)
            where T : PageModel;
    }
}
