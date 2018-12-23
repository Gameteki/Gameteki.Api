namespace CrimsonDev.Gameteki.Api.Helpers
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Reflection;
    using System.Text;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.ApiControllers;
    using CrimsonDev.Gameteki.Api.Config;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Models;
    using Microsoft.AspNetCore.Authentication.JwtBearer;
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
    using Newtonsoft.Json;
    using Newtonsoft.Json.Serialization;

    public static class ApiExtensions
    {
        [ExcludeFromCodeCoverage]
        public static void AddGametekiBase(this IServiceCollection services, IConfiguration configuration)
        {
            var apiAssembly = typeof(AccountController).GetTypeInfo().Assembly;
            var generalOptions = new GametekiApiOptions();
            var tokens = configuration.GetSection("Tokens").Get<AuthTokenOptions>();

            configuration.GetSection("General").Bind(generalOptions);

            if (generalOptions.DatabaseProvider.ToLower() == "mssql")
            {
                services.AddDbContext<GametekiDbContext>(settings => settings.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));
            }
            else
            {
                services.AddDbContext<GametekiDbContext>(settings => settings.UseNpgsql(configuration.GetConnectionString("DefaultConnection")));
            }

            services.AddMvc().AddApplicationPart(apiAssembly);
            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1).AddJsonOptions(
                options =>
                {
                    options.SerializerSettings.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;
                    options.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
                    options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
                });
            services.AddIdentityCore<GametekiUser>(settings =>
            {
                settings.User.RequireUniqueEmail = true;
            }).AddEntityFrameworkStores<GametekiDbContext>().AddDefaultTokenProviders();

            services.AddAuthentication(settings =>
                {
                    settings.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    settings.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer(options =>
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

            services.AddScoped<DbContext, GametekiDbContext>();
            services.AddTransient<UserManager<GametekiUser>>();
            services.AddTransient<IRoleStore<GametekiRole>, RoleStore<GametekiRole>>();
            services.AddTransient<RoleManager<GametekiRole>>();
            services.AddTransient<IGametekiDbContext, GametekiDbContext>();
            services.AddTransient<INewsService, NewsService>();
            services.AddTransient<IEmailSender, EmailSender>();
            services.AddTransient<IViewRenderService, ViewRenderService>();
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddSingleton<IActionContextAccessor, ActionContextAccessor>();
            services.Configure<AuthMessageSenderOptions>(configuration);
            services.Configure<AuthTokenOptions>(configuration.GetSection("Tokens"));
            services.Configure<GametekiApiOptions>(configuration.GetSection("General"));
        }
    }
}