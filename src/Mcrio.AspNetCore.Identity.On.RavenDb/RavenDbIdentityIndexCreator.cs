using System.Threading;
using System.Threading.Tasks;
using Mcrio.AspNetCore.Identity.On.RavenDb.Model.User;
using Mcrio.AspNetCore.Identity.On.RavenDb.Stores.Index;
using Raven.Client.Documents;
using Raven.Client.Documents.Conventions;

namespace Mcrio.AspNetCore.Identity.On.RavenDb;

/// <summary>
/// RavenDB create ASP Identity related indexes helper.
/// </summary>
public static class RavenDbIdentityIndexCreator
{
    /// <summary>
    /// Creates ASP Identity related RavenDB static indexes.
    /// </summary>
    /// <param name="documentStore"></param>
    /// <param name="databaseName"></param>
    /// <param name="documentConventions"></param>
    /// <param name="cancellationToken"></param>
    /// <typeparam name="TUsersByClaimRavenDbIndex">Users by claims index type.</typeparam>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
    public static async Task CreateIndexesAsync<TUsersByClaimRavenDbIndex>(
        IDocumentStore documentStore,
        string databaseName,
        DocumentConventions? documentConventions = null,
        CancellationToken cancellationToken = default)
        where TUsersByClaimRavenDbIndex : UsersByClaimIndex<RavenIdentityUser>, new()
    {
        await new TUsersByClaimRavenDbIndex().ExecuteAsync(
            documentStore,
            documentConventions,
            databaseName,
            cancellationToken
        );
    }

    /// <summary>
    /// Creates ASP Identity related RavenDB static indexes.
    /// </summary>
    /// <param name="documentStore"></param>
    /// <param name="databaseName"></param>
    /// <param name="documentConventions"></param>
    /// <typeparam name="TUsersByClaimRavenDbIndex">Users by claims index type.</typeparam>
    public static void CreateIndexes<TUsersByClaimRavenDbIndex>(
        IDocumentStore documentStore,
        string databaseName,
        DocumentConventions? documentConventions = null)
        where TUsersByClaimRavenDbIndex : UsersByClaimIndex<RavenIdentityUser>, new()
    {
        new TUsersByClaimRavenDbIndex().Execute(
            documentStore,
            documentConventions,
            databaseName
        );
    }
}