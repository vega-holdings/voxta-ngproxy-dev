using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Voxta.Abstractions.Encryption;
using Voxta.Abstractions.Model;
using Voxta.Abstractions.Registration;
using Voxta.Abstractions.Security;
using Voxta.Abstractions.Utils;
using Voxta.Common.Reporting;
using Voxta.Modules.NGProxy.Services;

namespace Voxta.Modules.NGProxy.Configuration;

public class ServiceInstallationProvider(
    ICommonFolders folders,
    ILocalEncryptionProvider localEncryptionProvider,
    IHttpClientFactory httpClientFactory,
    ILogger<ServiceInstallationProvider> logger
) : IServiceInstallationProvider
{
    public string[] GetPythonDependencies(ISettingsSource settings) => Array.Empty<string>();

    public async Task ConfigureModuleAsync(
        IAuthenticationContext auth,
        Module module,
        IDeferredReporter reporter,
        CancellationToken cancellationToken)
    {
        var manager = new NgProxyManager(folders, localEncryptionProvider, httpClientFactory, logger);
        var evaluation = await manager.EvaluateAsync(new StaticSettingsSource(module.Configuration), cancellationToken);

        module.NeedsInstallation = evaluation.NeedsInstallation;
        module.NeedsPythonInstallation = false;
    }

    public Task InstallSharedResourcesAsync(
        IAuthenticationContext auth,
        ISettingsSource settings,
        IDeferredReporter reporter,
        CancellationToken cancellationToken)
    {
        var manager = new NgProxyManager(folders, localEncryptionProvider, httpClientFactory, logger);
        return manager.InstallOrUpdateAsync(settings, reporter, cancellationToken);
    }
}
