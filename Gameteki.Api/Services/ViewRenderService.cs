namespace CrimsonDev.Gameteki.Api.Services
{
    using System;
    using System.Collections.Generic;
    using System.Diagnostics;
    using System.Diagnostics.CodeAnalysis;
    using System.IO;
    using System.Text.Encodings.Web;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Infrastructure;
    using Microsoft.AspNetCore.Mvc.ModelBinding;
    using Microsoft.AspNetCore.Mvc.Razor;
    using Microsoft.AspNetCore.Mvc.RazorPages;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
    using Microsoft.AspNetCore.Routing;

    [ExcludeFromCodeCoverage]
    internal class ViewRenderService : IViewRenderService
    {
        private readonly IRazorViewEngine razorViewEngine;
        private readonly ITempDataProvider tempDataProvider;
        private readonly IHttpContextAccessor httpContext;
        private readonly IActionContextAccessor actionContextAccessor;
        private readonly IRazorPageActivator activator;

        public ViewRenderService(
            IRazorViewEngine razorViewEngine,
            ITempDataProvider tempDataProvider,
            IHttpContextAccessor httpContext,
            IRazorPageActivator activator,
            IActionContextAccessor actionContextAccessor)
        {
            this.razorViewEngine = razorViewEngine;
            this.tempDataProvider = tempDataProvider;

            this.httpContext = httpContext;
            this.actionContextAccessor = actionContextAccessor;
            this.activator = activator;
        }

        public async Task<string> RenderToStringAsync<T>(string pageName, T model)
            where T : PageModel
        {
            var actionContext = new ActionContext(httpContext.HttpContext, httpContext.HttpContext.GetRouteData(), this.actionContextAccessor.ActionContext.ActionDescriptor);

            await using var writer = new StringWriter();
            var result = razorViewEngine.FindPage(actionContext, pageName);

            if (result.Page == null)
            {
                throw new ArgumentNullException($"The page {pageName} cannot be found.");
            }

            using var listener = new DiagnosticListener("ViewRenderService");
            var view = new RazorView(razorViewEngine, activator, new List<IRazorPage>(), result.Page, HtmlEncoder.Default, listener);
            var viewDataDictionary =
                new ViewDataDictionary<T>(new EmptyModelMetadataProvider(), new ModelStateDictionary())
                {
                    Model = model
                };
            var viewContext = new ViewContext(
                actionContext,
                view,
                viewDataDictionary,
                new TempDataDictionary(httpContext.HttpContext, tempDataProvider),
                writer,
                new HtmlHelperOptions());

            var page = (Page)result.Page;

            page.PageContext = new PageContext
            {
                ViewData = viewContext.ViewData
            };

            page.ViewContext = viewContext;

            activator.Activate(page, viewContext);

            await page.ExecuteAsync().ConfigureAwait(false);

            return writer.ToString();
        }
    }
}
