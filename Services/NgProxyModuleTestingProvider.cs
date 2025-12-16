using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Voxta.Abstractions.Encryption;
using Voxta.Abstractions.Modules;
using Voxta.Abstractions.Registration;
using Voxta.Abstractions.Security;
using Voxta.Abstractions.Utils;

namespace Voxta.Modules.NGProxy.Services;

public class NgProxyModuleTestingProvider(
    ICommonFolders folders,
    ILocalEncryptionProvider localEncryptionProvider,
    IHttpClientFactory httpClientFactory,
    ILogger<NgProxyModuleTestingProvider> logger
) : IVoxtaModuleTestingProvider
{
    public async Task<ModuleTestResultItem[]> TestModuleAsync(
        IAuthenticationContext auth,
        Guid moduleId,
        ISettingsSource settings,
        CancellationToken cancellationToken)
    {
        var manager = new NgProxyManager(folders, localEncryptionProvider, httpClientFactory, logger);
        var evaluation = await manager.EvaluateAsync(settings, cancellationToken);

        var results = new List<(bool ok, string message)>
        {
            (ok: evaluation.ConfigValid, message: evaluation.ConfigValid ? "Config: OK" : $"Config: {evaluation.ConfigError}"),
            (ok: evaluation.ToolsPresent, message: evaluation.ToolsPresent ? "Tools: OK" : "Tools: missing (run Install)"),
            (ok: evaluation.CertPresent, message: evaluation.CertPresent ? $"Certificate: OK (expires {evaluation.CertNotAfter:O})" : "Certificate: missing (run Install)"),
            (ok: evaluation.NginxConfigPresent, message: evaluation.NginxConfigPresent ? "Nginx config: OK" : "Nginx config: missing (run Install)"),
            (ok: evaluation.NginxRunning, message: evaluation.NginxRunning ? "Nginx: running" : "Nginx: not running"),
        };

        return results
            .Select(x => new ModuleTestResultItem { Success = x.ok, Message = x.message })
            .ToArray();
    }
}
