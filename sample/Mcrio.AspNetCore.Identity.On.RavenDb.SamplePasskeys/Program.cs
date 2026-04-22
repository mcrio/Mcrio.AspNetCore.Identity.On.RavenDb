using Mcrio.AspNetCore.Identity.On.RavenDb;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role;
using Mcrio.AspNetCore.Identity.On.RavenDb.RavenDb;
using Mcrio.AspNetCore.Identity.On.RavenDb.SamplePasskeys;
using Mcrio.AspNetCore.Identity.On.RavenDb.SamplePasskeys.Components;
using Mcrio.AspNetCore.Identity.On.RavenDb.SamplePasskeys.Components.Account;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Index;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Raven.Client.Documents;
using Raven.Client.Documents.Conventions;
using Raven.Client.Documents.Session;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Register document store
string? databaseName = builder.Configuration.GetSection("RavenDbDatabase").Get<string>();
if (string.IsNullOrWhiteSpace(databaseName))
{
    throw new Exception("The databaseName parameter is required.");
}

var store = new DocumentStore
{
    Urls = builder.Configuration.GetSection("RavenDbUrls").Get<string[]>(),
    Database = databaseName,
};
store.Conventions.FindCollectionName = type =>
{
    if (IdentityRavenDbConventions.TryGetCollectionName(
            type,
            out string? collectionName))
    {
        return collectionName;
    }

    return DocumentConventions.DefaultGetCollectionName(type);
};
store.Initialize();
store.EnsureDatabaseExists(databaseName, createDatabaseIfNotExists: true);

builder.Services.AddSingleton<IDocumentStore>(store);

// Register scoped document session
builder.Services.AddScoped(provider => provider.GetRequiredService<IDocumentStore>().OpenAsyncSession()
);

// Add services to the container.
builder.Services
    .AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

builder.Services
    .AddIdentity<ApplicationUser, RavenIdentityRole>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.SignIn.RequireConfirmedEmail = false;
        }
    )
    .AddRavenDbStores<
        ApplicationUserStore,
        ApplicationRoleStore,
        ApplicationUser,
        RavenIdentityRole,
        ApplicationUserByClaimIndex,
        UsersByClaimIndexEntry>(provider => provider.GetRequiredService<IAsyncDocumentSession>()
    )
    .AddSignInManager()
    .AddDefaultTokenProviders();
//
// builder.Services.AddAuthentication(options =>
//     {
//         options.DefaultScheme = IdentityConstants.ApplicationScheme;
//         options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
//     })
//     .AddIdentityCookies();

builder.Services.AddSingleton<IEmailSender<ApplicationUser>, EmailSender>();

WebApplication app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseStatusCodePagesWithReExecute("/not-found", createScopeForStatusCodePages: true);
app.UseHttpsRedirection();

app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add additional endpoints required by the Identity /Account Razor components.
app.MapAdditionalIdentityEndpoints();

app.Run();