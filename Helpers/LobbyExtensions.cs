namespace CrimsonDev.Gameteki.Api.Helpers
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Reflection;
    using CrimsonDev.Gameteki.Api.ApiControllers;
    using CrimsonDev.Gameteki.Api.Config;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.DependencyInjection;

    public static class LobbyExtensions
    {
        [ExcludeFromCodeCoverage]
        public static void AddGametekiBase(this IServiceCollection services, Action<GametekiApiOptions> action)
        {
            var lobbyAssembly = typeof(AccountController).GetTypeInfo().Assembly;

            var options = new GametekiApiOptions();
            action(options);

            services.AddMvc().AddApplicationPart(lobbyAssembly);
            if (options.UseMsSql)
            {
                services.AddDbContext<GametekiDbContext>(settings => settings.UseSqlServer(options.ConnectionString));
            }
            else
            {
                services.AddDbContext<GametekiDbContext>(settings => settings.UseNpgsql(options.ConnectionString));
            }

            services.AddIdentityCore<GametekiUser>(settings =>
            {
                settings.User.RequireUniqueEmail = true;
            }).AddEntityFrameworkStores<GametekiDbContext>().AddDefaultTokenProviders();

            services.AddScoped<DbContext, GametekiDbContext>();
            services.AddTransient<UserManager<GametekiUser>>();
            services.AddTransient<IRoleStore<GametekiRole>, RoleStore<GametekiRole>>();
            services.AddTransient<RoleManager<GametekiRole>>();
            services.AddTransient<IGametekiDbContext, GametekiDbContext>();
            services.AddTransient<INewsService, NewsService>();
        }
    }
}