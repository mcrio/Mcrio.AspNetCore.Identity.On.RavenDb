<img src="https://github.com/mcrio/Mcrio.AspNetCore.Identity.On.RavenDb/raw/master/ravendb-logo.png" height="100px" alt="RavenDB" />
<img src="https://github.com/mcrio/Mcrio.AspNetCore.Identity.On.RavenDb/raw/master/asp-net-core-logo.png" height="100px" alt="asp net core" />

# ASP.NET Core Identity on RavenDB 

[![Build status](https://dev.azure.com/midnight-creative/Mcrio.AspNetCore.Identity.On.RavenDb/_apis/build/status/Build)](https://dev.azure.com/midnight-creative/Mcrio.AspNetCore.Identity.On.RavenDb/_build/latest?definitionId=3)

A RavenDB *copy of the original EntityFramework user and role stores implementation.
Use RavenDB to store your user and role entities. Covers most of the tests implemented 
by the official EntityFramework stores.

#### Why implementing another RavenDB store solution as there were at lest two more related projects at that point?
At the time this solution was implemented the other projects were not flexible enough for 
my requirements in terms of ID generation, how uniques are handled, direct injection of IAsyncDocumentSession, and extensibility overall as
this project was required to be extensible to a multi-tenant store.
_(I am writing this document more than a year later so there may have been other reasons I don't remember any more)._

### (*) Missing functionality compared to official EF Core store implementation

- Support for [[PersonalData]](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.identity.personaldataattribute?view=aspnetcore-5.0) 
  attribute in terms of DB level encryption of properties annotated with the `[PersonalData]` attribute.
- There is no implementation of the `UserOnly` store. If required use the provided user and roles stores and ignore
  roles related functionality.

## Getting Started

### Try the sample application

```
1. CD into the solution directory

2. Start the RavenDB docker container (use flag -d to start in background)
$ docker-compose up

3. Run the sample project
$ dotnet run -p sample/Mcrio.AspNetCore.Identity.On.RavenDB.Sample/Mcrio.AspNetCore.Identity.On.RavenDB.Sample.csproj

4. Open in browser: https://localhost:5001

// RavenDB Studio is available at: http://localhost:32779
// If you want to try the Facebook login you need to provide
// the Facebook app id and secret in appsettings.json
```

### NuGet Package

Using the NuGet package manager install the [Mcrio.AspNetCore.Identity.On.RavenDb](#) package, or add the following line to the .csproj file:

```xml
<ItemGroup>
    <PackageReference Include="Mcrio.AspNetCore.Identity.On.RavenDb"></PackageReference>
</ItemGroup>
```

## Usage

### Simple usage

Add the following lines to Startup.cs.
```c# 
// ConfigureServices(...)
services
    // Add identity by providing RavenDB stores related types
    .AddIdentity<RavenIdentityUser, RavenIdentityRole>(
        options =>
        {
            options.User.RequireUniqueEmail = true;
            options.SignIn.RequireConfirmedEmail = false;
        }
    )
    // Adds the RavenDB stores
    .AddRavenDbStores<RavenUserStore, RavenRoleStore, RavenIdentityUser, RavenIdentityRole>(
        // define how IAsyncDocumentSession is resolved from DI
        // as library does NOT directly inject IAsyncDocumentSession
        provider => provider.GetRequiredService<IAsyncDocumentSession>()
    )
    .AddDefaultUI()
    .AddDefaultTokenProviders();
    
// Configure(...) 
// - Put between UseRouting() and UseEndpoints()
// - Refer to official asp.net documentation for more details
app.UseAuthentication();
app.UseAuthorization();
```

Note: Use ASP.Identity `UserManager` and `RoleManager` to manipulate user and roles.

### Classes

`Mcrio.AspNetCore.Identity.On.RavenDb.Model.User.RavenIdentityUser` RavenDB ASP.Identity User.
`Mcrio.AspNetCore.Identity.On.RavenDb.Model.Role.RavenIdentityRole` RavenDB ASP.Identity Role.
`Mcrio.AspNetCore.Identity.On.RavenDb.Stores.RavenUserStore` RavenDB user store.
`Mcrio.AspNetCore.Identity.On.RavenDb.Stores.RavenRoleStore` RavenDB role store.


### Unique values

Unique usernames are stores in the compare exchange.

When unique email is required it will be stored
in the compare exchange to ensure uniqueness, otherwise there will be no compare exchange entry.

(*) Making the emails required at a later stage (when there already are users registered) is not recommended
as the compare exchange will not have the existing emails registered. Technically it should work fine as 
ASP.Identity UserManager queries the emails before a new one is set, but uniqueness is not fully guaranteed 
as the compare exchange does not have existing emails and the RavenDB nodes are eventually consistent.

### ID generation

Id of User and Role can be changed after object construction. 
By default set to `null` which implies HiLo identifier generation.
Refer to official [RavenDB document](https://ravendb.net/docs/article-page/5.2/working-with-document-identifiers/client-api/document-identifiers/working-with-document-identifiers) about identifier generation strategies.

### Compare Exchange key prefixes

Extend UserStore and RoleStore and override `protected virtual CompareExchangeUtility CreateCompareExchangeUtility()` to return
an extended `CompareExchangeUtility` that will override the functionality for generating
compare exchange key prefixes. See `CompareExchangeUtility.GetKeyPrefix` for predefined compare exchange key prefixes.

### Multi-tenant guidelines

- Extend `RavenIdentityUser` and `RavenIdentityRole` to include a `TenantId` property
- Extend `UserStore` and `RoleStore` that will:
    - Return an extended `CompareExchangeUtility` which
includes the tenant identifier in the compare exchange prefixes.
    - Make sure tenant id is set on user and role creation.
- RavenDB document store should register a `OnBeforeQuery` callback that will make sure
the `TenantId = ...` query condition is included in each query.
- RavenDB document store should register a `OnAfterConversionToEntity` callback to make sure
the document to be converted belongs to current tenant, otherwise throw an exception.
  

## Release History

- **1.0.0**
  Stable version.

## Meta

Nikola Josipović

This project is licensed under the MIT License. See [License.md](License.md) for more information.