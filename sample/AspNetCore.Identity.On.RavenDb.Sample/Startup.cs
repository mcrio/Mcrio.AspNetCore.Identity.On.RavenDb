using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Raven.Client.Documents;
using Raven.Client.Documents.Conventions;
using Raven.Client.Documents.Session;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Sample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Register document store
            string databaseName = Configuration.GetSection("RavenDbDatabase").Get<string>();
            IDocumentStore store = new DocumentStore
            {
                Urls = Configuration.GetSection("RavenDbUrls").Get<string[]>(),
                Database = databaseName,
            };
            store.Conventions.FindCollectionName = type =>
            {
                if (IdentityRavenDbConventions.TryGetCollectionName<RavenIdentityUser, RavenIdentityRole>(
                    type,
                    out string? collectionName))
                {
                    return collectionName;
                }

                return DocumentConventions.DefaultGetCollectionName(type);
            };
            store.Initialize();
            store.EnsureDatabaseExists(databaseName, true);

            services.AddSingleton(store);

            // Register scoped document session
            services.AddScoped(
                provider => provider.GetRequiredService<IDocumentStore>().OpenAsyncSession()
            );

            // Add identity
            services
                .AddIdentity<RavenIdentityUser, RavenIdentityRole>(
                    options =>
                    {
                        options.User.RequireUniqueEmail = true;
                        options.SignIn.RequireConfirmedEmail = false;
                    }
                )
                .AddRavenDbStores(provider => provider.GetRequiredService<IAsyncDocumentSession>)
                .AddDefaultUI()
                .AddDefaultTokenProviders();

            // Facebook test authentication
            services.AddAuthentication(o =>
                {
                    o.DefaultScheme = IdentityConstants.ApplicationScheme;
                    o.DefaultSignInScheme = IdentityConstants.ExternalScheme;
                })
                .AddFacebook(facebookOptions =>
                {
                    facebookOptions.AppId = Configuration["FacebookAppId"];
                    facebookOptions.AppSecret = Configuration["FacebookAppSecret"];
                });

            services.AddRazorPages();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");

                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints => { endpoints.MapRazorPages(); });
        }
    }
}