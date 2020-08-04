using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Raven.Client.Documents;

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
            var urls = Configuration.GetSection("RavenDbUrls").Get<string[]>();
            var database = Configuration.GetSection("RavenDbDatabase").Get<string>();
            IDocumentStore store = new DocumentStore
            {
                Urls = urls,
                Database = database,
            };
            store.Initialize();
            services.AddSingleton(store);
            services.AddScoped(
                provider => provider
                    .GetRequiredService<IDocumentStore>()
                    .OpenAsyncSession(database));

            services.AddTransient<IdentityErrorDescriber>(provider => new IdentityErrorDescriber());
            services.AddScoped<IUserStore<RavenIdentityUser>, RavenUserStore>();
            services.AddScoped<IRoleStore<RavenIdentityRole>, RavenRoleStore>();
            services.AddIdentity<RavenIdentityUser, RavenIdentityRole>(
                    options =>
                    {
                        options.User.RequireUniqueEmail = true;
                        options.SignIn.RequireConfirmedEmail = true;
                    }
                )
                .AddDefaultUI()
                .AddDefaultTokenProviders();

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