namespace CrimsonDev.Gameteki.Api.Helpers
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Text;
    using System.Text.Json;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Models;
    using CrimsonDev.Gameteki.Api.Scheduler;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Models;
    using CrimsonDev.Gameteki.Data.Models.Config;
    using I18Next.Net.AspNetCore;
    using I18Next.Net.Backends;
    using I18Next.Net.Extensions;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.AspNetCore.Http;
    using Microsoft.AspNetCore.Identity;
    using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
    using Microsoft.AspNetCore.Identity.UI.Services;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Infrastructure;
    using Microsoft.EntityFrameworkCore;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.IdentityModel.Tokens;
    using Quartz.Spi;
    using StackExchange.Redis;

    [ExcludeFromCodeCoverage]
    public static class ApiExtensions
    {
        private static readonly GametekiApiOptions DefaultConfig = new GametekiApiOptions
        {
            AccountVerification = true,
            ApplicationName = "Gameteki Hosted Application",
            DatabaseProvider = "mssql",
            RedisUrl = "localhost:6379"
        };

        public static void AddGameteki(this IServiceCollection services, IConfiguration configuration)
        {
            ConfigureMvc(services, configuration);
            ConfigureServices(services, configuration);
        }

        public static IApplicationBuilder UseGameteki(this IApplicationBuilder app)
        {
            app.UseRequestLocalization(options => options.AddSupportedCultures(
                "de", "en", "es", "fr", "it", "pl", "pt", "th", "zh-CN", "zh-TW"));

            app.UseRouting();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });

            return app;
        }

        private static void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            var generalSection = configuration.GetSection("General");
            var generalConfig = generalSection.Get<GametekiApiOptions>() ?? DefaultConfig;

            services.AddScoped<DbContext, GametekiDbContext>();

            services.AddTransient<UserManager<GametekiUser>>();
            services.AddTransient<IRoleStore<GametekiRole>, RoleStore<GametekiRole>>();
            services.AddTransient<RoleManager<GametekiRole>>();
            services.AddTransient<IGametekiDbContext, GametekiDbContext>();
            services.AddTransient<INewsService, NewsService>();
            services.AddTransient<IEmailSender, EmailSender>();
            services.AddTransient<IMessageService, MessageService>();
            services.AddTransient<IViewRenderService, ViewRenderService>();

            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddSingleton<IActionContextAccessor, ActionContextAccessor>();
            services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect(generalConfig.RedisUrl));
            services.AddSingleton<IJobFactory, JobFactory>();
            services.AddSingleton<IHttpClient, HttpClientWrapper>();
            services.AddSingleton<NodeMonitor>();

            services.Configure<AuthMessageSenderOptions>(configuration);
            services.Configure<AuthTokenOptions>(configuration.GetSection("Tokens"));
            services.Configure<GametekiApiOptions>(generalSection);

            services.AddControllers();

            services.AddI18NextLocalization(i18n => i18n.IntegrateToAspNetCore()
                .AddBackend(new JsonFileBackend("wwwroot/locales"))
                .UseDefaultLanguage("en"));
        }

        private static void ConfigureMvc(IServiceCollection services, IConfiguration configuration)
        {
            var tokens = configuration.GetSection("Tokens").Get<AuthTokenOptions>();
            var generalOptions = configuration.GetSection("General").Get<GametekiApiOptions>() ?? DefaultConfig;

            if (generalOptions.DatabaseProvider.ToLower() == "mssql")
            {
                services.AddDbContext<GametekiDbContext>(settings => settings.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));
            }
            else
            {
                services.AddDbContext<GametekiDbContext>(settings => settings.UseNpgsql(configuration.GetConnectionString("DefaultConnection")));
            }

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Latest).AddJsonOptions(
                options =>
                {
                    options.JsonSerializerOptions.IgnoreNullValues = true;
                    options.JsonSerializerOptions.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;
                });
            services.AddIdentityCore<GametekiUser>(settings => { settings.User.RequireUniqueEmail = true; })
                .AddEntityFrameworkStores<GametekiDbContext>()
                .AddDefaultTokenProviders();

            services.AddAuthentication(
                settings =>
                {
                    settings.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    settings.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                }).AddJwtBearer(
                options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = tokens.Issuer,
                        ValidateAudience = true,
                        ValidAudience = tokens.Issuer,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(tokens.Key)),
                        ClockSkew = TimeSpan.Zero
                    };
                    options.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                            {
                                context.Response.Headers.Add("Token-Expired", "true");
                            }

                            return Task.CompletedTask;
                        }
                    };
                });
        }
    }
}
