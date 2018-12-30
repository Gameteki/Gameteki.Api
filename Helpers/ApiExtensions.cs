namespace CrimsonDev.Gameteki.Api.Helpers
{
    using System;
    using System.Diagnostics.CodeAnalysis;
    using System.Text;
    using System.Threading.Tasks;
    using CrimsonDev.Gameteki.Api.Config;
    using CrimsonDev.Gameteki.Api.Scheduler;
    using CrimsonDev.Gameteki.Api.Services;
    using CrimsonDev.Gameteki.Data;
    using CrimsonDev.Gameteki.Data.Models;
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
    using Newtonsoft.Json;
    using Newtonsoft.Json.Serialization;
    using Quartz;
    using Quartz.Impl;
    using Quartz.Spi;
    using StackExchange.Redis;

    [ExcludeFromCodeCoverage]
    public static class ApiExtensions
    {
        public static void AddGameteki(this IServiceCollection services, IConfiguration configuration)
        {
            ConfigureMvc(services, configuration);
            ConfigureServices(services, configuration);
        }

        public static IApplicationBuilder UseGameteki(this IApplicationBuilder app)
        {
            ISchedulerFactory schedulerFactory = new StdSchedulerFactory();
            var scheduler = schedulerFactory.GetScheduler().GetAwaiter().GetResult();

            scheduler.JobFactory = app.ApplicationServices.GetService<IJobFactory>();

            var job = JobBuilder.Create<NodeMonitor>().WithIdentity("NodeMonitor").Build();
            var trigger = TriggerBuilder
                .Create()
                .WithIdentity("NodeMonitorTrigger")
                .WithSimpleSchedule(x => x.WithIntervalInMinutes(2).RepeatForever())
                .Build();

            scheduler.ScheduleJob(job, trigger);

            return app;
        }

        private static void ConfigureServices(IServiceCollection services, IConfiguration configuration)
        {
            var generalSection = configuration.GetSection("General");
            var generalConfig = generalSection.Get<GametekiApiOptions>();

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
            services.AddSingleton<IJobFactory, JobFactory>();
            services.AddSingleton<NodeMonitor>();
            services.Configure<AuthMessageSenderOptions>(configuration);
            services.Configure<AuthTokenOptions>(configuration.GetSection("Tokens"));
            services.Configure<GametekiApiOptions>(generalSection);

            services.AddSingleton<IConnectionMultiplexer>(ConnectionMultiplexer.Connect(generalConfig.RedisUrl));
        }

        private static void ConfigureMvc(IServiceCollection services, IConfiguration configuration)
        {
            var tokens = configuration.GetSection("Tokens").Get<AuthTokenOptions>();
            var generalOptions = configuration.GetSection("General").Get<GametekiApiOptions>();

            if (generalOptions.DatabaseProvider.ToLower() == "mssql")
            {
                services.AddDbContext<GametekiDbContext>(
                    settings => settings.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));
            }
            else
            {
                services.AddDbContext<GametekiDbContext>(
                    settings => settings.UseNpgsql(configuration.GetConnectionString("DefaultConnection")));
            }

            services.AddMvc().SetCompatibilityVersion(CompatibilityVersion.Version_2_1).AddJsonOptions(
                options =>
                {
                    options.SerializerSettings.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;
                    options.SerializerSettings.ContractResolver = new CamelCasePropertyNamesContractResolver();
                    options.SerializerSettings.NullValueHandling = NullValueHandling.Ignore;
                });
            services.AddIdentityCore<GametekiUser>(settings => { settings.User.RequireUniqueEmail = true; })
                .AddEntityFrameworkStores<GametekiDbContext>().AddDefaultTokenProviders();

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