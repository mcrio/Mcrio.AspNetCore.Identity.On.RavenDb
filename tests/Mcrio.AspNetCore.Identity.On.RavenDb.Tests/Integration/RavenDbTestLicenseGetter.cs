using System;
using System.IO;

namespace Mcrio.AspNetCore.Identity.On.RavenDb.Tests.Integration;

internal static class RavenDbTestLicenseGetter
{
    private const string RavenDbDeveloperLicensePathEnvironmentVariableName = "RAVENDB_DEVELOPER_LICENSE_PATH";

    internal static string GetRavenDbDeveloperLicensePath()
    {
        string? ravenDbLicensePath = Environment.GetEnvironmentVariable(
            RavenDbDeveloperLicensePathEnvironmentVariableName
        );
        if (string.IsNullOrWhiteSpace(ravenDbLicensePath))
        {
            throw new InvalidOperationException(
                $"RavenDb license path is missing. Set environment variable {RavenDbDeveloperLicensePathEnvironmentVariableName}."
            );
        }

        if (!File.Exists(ravenDbLicensePath))
        {
            throw new InvalidOperationException(
                $"RavenDb license path points to a non-existing RavenDb license file {ravenDbLicensePath}."
            );
        }

        return ravenDbLicensePath;
    }
}