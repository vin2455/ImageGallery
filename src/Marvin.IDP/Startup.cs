using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using Microsoft.EntityFrameworkCore;
using Marvin.IDP.Entities;
using Marvin.IDP.Services;
using IdentityServer4;
using System.Security.Cryptography.X509Certificates;
using System.Reflection;
using IdentityServer4.EntityFramework.DbContexts;

namespace Marvin.IDP
{
    public class Startup
    {
        public static IConfigurationRoot Configuration;

        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables();

            Configuration = builder.Build();
        }

        public X509Certificate2 LoadCertificateFromStore()
        {
            //string thumbPrint = "AD4AD167DE7171FAA3185480C088C877CD702562";
            string thumbPrint = "D1A51DDBE1E04A2E0149774E1C7B45A35BCDCC5E".ToUpper();

            using (var store = new X509Store(StoreName.My, StoreLocation.LocalMachine))
            {
                store.Open(OpenFlags.ReadOnly);
                //var certCollection = store.Certificates.Find(X509FindType.FindByThumbprint,
                //    thumbPrint, true);
                var certCollection = store.Certificates.Find(X509FindType.FindByThumbprint,
                    thumbPrint, false);
                if (certCollection.Count == 0)
                {
                    throw new Exception("The specified certificate wasn't found.");
                }
                return certCollection[0];
            }
        }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            var connectionString = Configuration["connectionStrings:marvinUserDBConnectionString"];
            services.AddDbContext<MarvinUserContext>(o => o.UseSqlServer(connectionString));

            services.AddScoped<IMarvinUserRepository, MarvinUserRepository>();

            var identityServerDataDBConnectionString =
               Configuration["connectionStrings:identityServerDataDBConnectionString"];

            var migrationsAssembly = typeof(Startup)
                .GetTypeInfo().Assembly.GetName().Name;

            services.AddMvc();

            services.AddIdentityServer()
                .AddSigningCredential(LoadCertificateFromStore())
                .AddMarvinUserStore()
                .AddConfigurationStore(builder =>
                    builder.UseSqlServer(identityServerDataDBConnectionString,
                    options => options.MigrationsAssembly(migrationsAssembly)))
                .AddOperationalStore(builder =>
                    builder.UseSqlServer(identityServerDataDBConnectionString,
                    options => options.MigrationsAssembly(migrationsAssembly)));

        }


        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env,
            ILoggerFactory loggerFactory, MarvinUserContext marvinUserContext,
            ConfigurationDbContext configurationDbContext, 
            PersistedGrantDbContext persistedGrantDbContext)
        {
            loggerFactory.AddConsole();
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            configurationDbContext.Database.Migrate();
            configurationDbContext.EnsureSeedDataForContext();

            persistedGrantDbContext.Database.Migrate();

            marvinUserContext.Database.Migrate();
            marvinUserContext.EnsureSeedDataForContext();

            app.UseCookieAuthentication(new CookieAuthenticationOptions
            {
                AuthenticationScheme = "idsrv.2FA",
                AutomaticAuthenticate = false,
                AutomaticChallenge = false
            });

            app.UseIdentityServer();

            app.UseFacebookAuthentication(new FacebookOptions
            {
                AuthenticationScheme = "Facebook",
                DisplayName = "Facebook",
                SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme,
                AppId = "1570475679676847",
                AppSecret = "5b9f4bca5da29e234b706040aca883d3"
            });

            app.UseStaticFiles();

            app.UseMvcWithDefaultRoute();
        }
    }
}
