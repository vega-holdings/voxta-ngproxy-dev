using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Microsoft.Extensions.Logging;
using Voxta.Abstractions.Encryption;
using Voxta.Abstractions.Registration;
using Voxta.Abstractions.Security;
using Voxta.Abstractions.Utils;
using Voxta.Model.Shared.Forms;
using Voxta.Modules.NGProxy.Services;

namespace Voxta.Modules.NGProxy.Configuration;

[SuppressMessage("ReSharper", "MemberCanBePrivate.Global", Justification = "Fields are reused in module registration.")]
public class ModuleConfigurationProvider(
    ICommonFolders folders,
    ILocalEncryptionProvider localEncryptionProvider,
    IHttpClientFactory httpClientFactory,
    ILogger<ModuleConfigurationProvider> logger
) : ModuleConfigurationProviderBase, IModuleConfigurationProvider
{
    public static string[] FieldsRequiringReload =>
    [
        Domain.Name,
        Email.Name,
        CloudflareApiToken.Name,
        UpstreamUrl.Name,
        DnsResolvers.Name,
    ];

    public static readonly FormTextField Domain = new()
    {
        Name = "Domain",
        Label = "Domain",
        Text = "Public hostname to serve (e.g. `voxta.example.com`). This must resolve to this machine.",
        Placeholder = "voxta.example.com",
        Required = true,
    };

    public static readonly FormTextField Email = new()
    {
        Name = "Email",
        Label = "Email",
        Text = "ACME email for Let’s Encrypt (used for expiry notices).",
        Placeholder = "admin@example.com",
        Required = true,
    };

    public static readonly FormPasswordField CloudflareApiToken = new()
    {
        Name = "CloudflareApiToken",
        Label = "Cloudflare API Token",
        Text = "Cloudflare token for DNS-01 (Zone:DNS Edit + Zone Read). Paste the raw token (or a line like `dns_cloudflare_api_token=...`).",
        Required = true,
    };

    public static readonly FormTextField UpstreamUrl = new()
    {
        Name = "UpstreamUrl",
        Label = "Upstream URL",
        Text = "Local Voxta URL to proxy to.",
        Placeholder = "http://127.0.0.1:5384",
        DefaultValue = "http://127.0.0.1:5384",
        Required = true,
    };

    public static readonly FormStringListField DnsResolvers = new()
    {
        Name = "DnsResolvers",
        Label = "DNS Resolvers (optional)",
        Text = "Optional DNS resolvers for lego zone detection (fixes networks that block Google Public DNS). Format: `host:port` (example `1.1.1.1:53`). Leave empty to auto-detect system DNS.",
        Placeholder = "1.1.1.1:53",
        Rows = 3,
        Advanced = true,
    };

    public Task<FormField[]> GetModuleConfigurationFieldsAsync(
        IAuthenticationContext auth,
        ISettingsSource settings,
        CancellationToken cancellationToken)
    {
        return GetFieldsAsync(settings, cancellationToken);
    }

    private async Task<FormField[]> GetFieldsAsync(ISettingsSource settings, CancellationToken cancellationToken)
    {
        var manager = new NgProxyManager(folders, localEncryptionProvider, httpClientFactory, logger);
        var evaluation = await manager.EvaluateAsync(settings, cancellationToken);

        return FormBuilder.Build(
            FormTitleField.Create(
                "NGProxy (alpha)",
                "Saving this form does not install anything. Go to the Modules list and click Install to apply (Voxta blocks installs while a chat is active).",
                false),
            FormDocumentationField.Create(BuildStatusText(evaluation), "Current status"),
            Domain,
            Email,
            CloudflareApiToken,
            UpstreamUrl,
            DnsResolvers
        );
    }

    private static string BuildStatusText(NgProxyManager.NgProxyEvaluation evaluation)
    {
        var lines = new List<string>
        {
            $"Tools folder: {evaluation.ToolsRoot}",
            $"Configured: {(evaluation.ConfigValid ? "yes" : $"no ({evaluation.ConfigError})")}",
            $"Tools present: {(evaluation.ToolsPresent ? "yes" : "no")}",
            $"nginx config present: {(evaluation.NginxConfigPresent ? "yes" : "no")}",
            $"Certificate present: {(evaluation.CertPresent ? "yes" : "no")}",
            evaluation.CertNotAfter.HasValue ? $"Certificate expires: {evaluation.CertNotAfter:O}" : "Certificate expires: (unknown)",
            $"nginx running: {(evaluation.NginxRunning ? "yes" : "no")}",
            $"Needs install: {(evaluation.NeedsInstallation ? "yes" : "no")}",
        };

        if (!string.IsNullOrWhiteSpace(evaluation.State?.LastError))
        {
            lines.Add($"Last error: {evaluation.State.LastError}");
        }

        return string.Join(Environment.NewLine, lines);
    }
}
