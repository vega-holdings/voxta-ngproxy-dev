using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Voxta.Abstractions.Encryption;
using Voxta.Abstractions.Registration;
using Voxta.Abstractions.Utils;
using Voxta.Common.Reporting;
using Voxta.Modules.NGProxy.Configuration;

namespace Voxta.Modules.NGProxy.Services;

internal sealed class NgProxyManager(
    ICommonFolders folders,
    ILocalEncryptionProvider localEncryptionProvider,
    IHttpClientFactory httpClientFactory,
    ILogger logger)
{
    private const string ToolsFolderName = "NGProxy";
    private const string NginxDownloadUrl = "https://nginx.org/download/nginx-1.26.2.zip";
    private const string LegoPinnedDownloadUrl = "https://github.com/go-acme/lego/releases/download/v4.29.0/lego_v4.29.0_windows_amd64.zip";
    private const string LegoLatestReleaseApiUrl = "https://api.github.com/repos/go-acme/lego/releases/latest";
    private static readonly string[] FallbackDnsResolvers = ["1.1.1.1:53", "1.0.0.1:53", "8.8.8.8:53", "8.8.4.4:53"];
    private static readonly Encoding Utf8NoBom = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false);

    public async Task<NgProxyEvaluation> EvaluateAsync(ISettingsSource settings, CancellationToken cancellationToken)
    {
        var config = TryLoadConfig(settings, out var configError);
        var root = folders.GetDataFolder("Tools", ToolsFolderName);
        var statePath = Path.Combine(root, "state.json");
        var state = await TryReadStateAsync(statePath, cancellationToken);

        string? nginxExePath = TryFindFirstFile(Path.Combine(root, "nginx"), "nginx.exe");
        string? legoExePath = TryFindFirstFile(Path.Combine(root, "lego"), "lego.exe");
        var toolsPresent = nginxExePath != null && legoExePath != null;

        var nginxRoot = nginxExePath != null ? Path.GetDirectoryName(nginxExePath) : null;
        var nginxConfigPath = nginxRoot != null ? Path.Combine(nginxRoot, "conf", "ngproxy.conf") : null;
        var nginxConfigPresent = nginxConfigPath != null && File.Exists(nginxConfigPath);

        var nginxPidPath = nginxRoot != null ? Path.Combine(nginxRoot, "logs", "ngproxy.pid") : null;
        var nginxRunning = nginxPidPath != null && TryIsProcessRunningFromPidFile(nginxPidPath, out _);

        DateTimeOffset? certNotAfter = null;
        var certPresent = false;
        if (config != null)
        {
            var acmePath = Path.Combine(root, "acme");
            var certDir = Path.Combine(acmePath, "certificates");
            var fullChainPath = Path.Combine(certDir, $"{config.Domain}.fullchain.crt");
            var keyPath = Path.Combine(certDir, $"{config.Domain}.key");

            certPresent = File.Exists(fullChainPath) && File.Exists(keyPath);
            if (certPresent)
            {
                certNotAfter = TryGetCertNotAfter(fullChainPath);
            }
        }

        var configHash = config != null ? ComputeConfigHash(config) : null;
        var configHashMatches = configHash != null && string.Equals(state?.ConfigHash, configHash, StringComparison.OrdinalIgnoreCase);

        var needsInstall =
            !toolsPresent
            || !nginxConfigPresent
            || !certPresent
            || !nginxRunning
            || (config != null && !configHashMatches);

        return new NgProxyEvaluation(
            ConfigValid: config != null,
            ConfigError: configError,
            ToolsPresent: toolsPresent,
            NginxConfigPresent: nginxConfigPresent,
            CertPresent: certPresent,
            CertNotAfter: certNotAfter,
            NginxRunning: nginxRunning,
            NeedsInstallation: needsInstall,
            ToolsRoot: root,
            NginxExePath: nginxExePath,
            LegoExePath: legoExePath,
            NginxConfigPath: nginxConfigPath,
            State: state
        );
    }

    public async Task InstallOrUpdateAsync(ISettingsSource settings, IDeferredReporter reporter, CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("NGProxy is Windows-only.");
        }

        var config = LoadConfig(settings);
        var cloudflareToken = LoadCloudflareToken(settings);
        logger.LogInformation("NGProxy install starting for {Domain} -> {UpstreamUrl}", config.Domain, config.UpstreamUrl);

        var root = folders.GetDataFolder("Tools", ToolsFolderName);
        var nginxBase = Path.Combine(root, "nginx");
        var legoBase = Path.Combine(root, "lego");
        var downloads = Path.Combine(root, "downloads");
        var acmePath = Path.Combine(root, "acme");
        var statePath = Path.Combine(root, "state.json");

        Directory.CreateDirectory(root);
        Directory.CreateDirectory(nginxBase);
        Directory.CreateDirectory(legoBase);
        Directory.CreateDirectory(downloads);
        Directory.CreateDirectory(acmePath);

        try
        {
            reporter.Info("NGProxy install starting...");
            reporter.Info($"Tools folder: {root}");

            var http = httpClientFactory.CreateClient(nameof(NgProxyManager));

            var legoDownloadUrl = await ResolveLegoDownloadUrlAsync(http, reporter, cancellationToken);

            var nginxExePath = await EnsureToolAsync(
                toolName: "nginx",
                exeName: "nginx.exe",
                toolRoot: nginxBase,
                downloadsFolder: downloads,
                downloadUrl: NginxDownloadUrl,
                http: http,
                reporter: reporter,
                cancellationToken: cancellationToken);

            string legoExePath;
            try
            {
                legoExePath = await EnsureToolAsync(
                    toolName: "lego",
                    exeName: "lego.exe",
                    toolRoot: legoBase,
                    downloadsFolder: downloads,
                    downloadUrl: legoDownloadUrl,
                    http: http,
                    reporter: reporter,
                    cancellationToken: cancellationToken);
            }
            catch (HttpRequestException ex) when (!string.Equals(legoDownloadUrl, LegoPinnedDownloadUrl, StringComparison.OrdinalIgnoreCase))
            {
                reporter.Error($"lego: download failed ({ex.Message}). Retrying pinned URL...");
                legoExePath = await EnsureToolAsync(
                    toolName: "lego",
                    exeName: "lego.exe",
                    toolRoot: legoBase,
                    downloadsFolder: downloads,
                    downloadUrl: LegoPinnedDownloadUrl,
                    http: http,
                    reporter: reporter,
                    cancellationToken: cancellationToken);
            }

            var nginxRoot = Path.GetDirectoryName(nginxExePath) ?? throw new InvalidOperationException("nginx path invalid");
            var nginxConfDir = Path.Combine(nginxRoot, "conf");
            var nginxLogsDir = Path.Combine(nginxRoot, "logs");
            Directory.CreateDirectory(nginxConfDir);
            Directory.CreateDirectory(nginxLogsDir);

            var certDir = Path.Combine(acmePath, "certificates");
            Directory.CreateDirectory(certDir);

            reporter.Info("Issuing certificate via Let's Encrypt (Cloudflare DNS-01)...");
            await RunLegoAsync(
                legoExePath,
                config,
                cloudflareToken,
                acmePath,
                cancellationToken,
                reporter);

            var certCrtPath = Path.Combine(certDir, $"{config.Domain}.crt");
            var certIssuerPath = Path.Combine(certDir, $"{config.Domain}.issuer.crt");
            var certKeyPath = Path.Combine(certDir, $"{config.Domain}.key");
            var certFullChainPath = Path.Combine(certDir, $"{config.Domain}.fullchain.crt");

            if (!File.Exists(certCrtPath) || !File.Exists(certKeyPath))
            {
                throw new InvalidOperationException("Certificate files were not created by lego. Check install logs above.");
            }

            if (File.Exists(certIssuerPath))
            {
                await WriteFullChainAsync(certCrtPath, certIssuerPath, certFullChainPath, cancellationToken);
            }
            else
            {
                File.Copy(certCrtPath, certFullChainPath, overwrite: true);
            }

            reporter.Info("Writing nginx config...");
            var nginxConfigPath = Path.Combine(nginxConfDir, "ngproxy.conf");
            var nginxPidPath = Path.Combine(nginxLogsDir, "ngproxy.pid");
            await File.WriteAllTextAsync(
                nginxConfigPath,
                BuildNginxConfig(config, certFullChainPath, certKeyPath, nginxPidPath),
                Utf8NoBom,
                cancellationToken);

            reporter.Info("Validating nginx config...");
            await RunProcessAsync(
                nginxExePath,
                workingDirectory: nginxRoot,
                args: ["-p", nginxRoot, "-c", nginxConfigPath, "-t"],
                env: null,
                reporter: reporter,
                cancellationToken: cancellationToken);

            reporter.Info("Starting/reloading nginx...");
            var reloaded = false;
            if (TryIsProcessRunningFromPidFile(nginxPidPath, out _))
            {
                reloaded = await TryRunProcessAsync(
                    nginxExePath,
                    workingDirectory: nginxRoot,
                    args: ["-p", nginxRoot, "-c", nginxConfigPath, "-s", "reload"],
                    env: null,
                    reporter: reporter,
                    cancellationToken: cancellationToken);
            }

            if (!reloaded)
            {
                try
                {
                    if (File.Exists(nginxPidPath))
                    {
                        File.Delete(nginxPidPath);
                    }
                }
                catch
                {
                }

                await StartNginxAsync(
                    nginxExePath,
                    nginxRoot,
                    nginxConfigPath,
                    reporter,
                    cancellationToken);
            }

            if (!await WaitForNginxAsync(nginxPidPath, TimeSpan.FromSeconds(5), cancellationToken))
            {
                throw new InvalidOperationException("nginx did not appear to start. Check the nginx logs under the Tools folder.");
            }

            var certNotAfter = TryGetCertNotAfter(certCrtPath) ?? TryGetCertNotAfter(certFullChainPath);
            var state = new NgProxyState
            {
                UpdatedAtUtc = DateTimeOffset.UtcNow,
                Domain = config.Domain,
                Email = config.Email,
                UpstreamUrl = config.UpstreamUrl,
                ConfigHash = ComputeConfigHash(config),
                CertNotAfterUtc = certNotAfter,
                NginxExePath = nginxExePath,
                LegoExePath = legoExePath,
                NginxConfigPath = nginxConfigPath,
                NginxPidPath = nginxPidPath,
                AcmePath = acmePath,
                LastError = null,
            };

            await WriteStateAsync(statePath, state, cancellationToken);

            reporter.Info("NGProxy install complete.");
            reporter.Info($"nginx config: {nginxConfigPath}");
            reporter.Info($"nginx logs: {nginxLogsDir}");
            reporter.Info(certNotAfter.HasValue ? $"cert expires: {certNotAfter:O}" : "cert expires: (unknown)");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "NGProxy install failed for {Domain}", config.Domain);
            reporter.Error(ex.Message);

            try
            {
                var failedState = new NgProxyState
                {
                    UpdatedAtUtc = DateTimeOffset.UtcNow,
                    Domain = config.Domain,
                    Email = config.Email,
                    UpstreamUrl = config.UpstreamUrl,
                    ConfigHash = ComputeConfigHash(config),
                    AcmePath = acmePath,
                    LastError = ex.Message,
                };
                await WriteStateAsync(statePath, failedState, cancellationToken);
            }
            catch
            {
            }

            throw;
        }
    }

    private static async Task<string> ResolveLegoDownloadUrlAsync(
        HttpClient http,
        IDeferredReporter reporter,
        CancellationToken cancellationToken)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, LegoLatestReleaseApiUrl);
            request.Headers.Accept.ParseAdd("application/vnd.github+json");
            request.Headers.UserAgent.ParseAdd("Voxta-NGProxy");

            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if (!response.IsSuccessStatusCode)
            {
                reporter.Error($"lego: failed to resolve latest version ({(int)response.StatusCode} {response.ReasonPhrase}), using pinned URL.");
                return LegoPinnedDownloadUrl;
            }

            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);

            if (!doc.RootElement.TryGetProperty("assets", out var assets) || assets.ValueKind != JsonValueKind.Array)
            {
                reporter.Error("lego: latest release JSON missing assets array, using pinned URL.");
                return LegoPinnedDownloadUrl;
            }

            foreach (var asset in assets.EnumerateArray())
            {
                if (!asset.TryGetProperty("name", out var nameProp) || nameProp.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                var name = nameProp.GetString();
                if (string.IsNullOrWhiteSpace(name) || !name.EndsWith("windows_amd64.zip", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!asset.TryGetProperty("browser_download_url", out var urlProp) || urlProp.ValueKind != JsonValueKind.String)
                {
                    continue;
                }

                var url = urlProp.GetString();
                if (!string.IsNullOrWhiteSpace(url))
                {
                    reporter.Info($"lego: resolved latest download ({name})");
                    return url;
                }
            }

            reporter.Error("lego: no windows_amd64.zip asset found in latest release, using pinned URL.");
            return LegoPinnedDownloadUrl;
        }
        catch (Exception ex)
        {
            reporter.Error($"lego: failed to resolve latest version ({ex.Message}), using pinned URL.");
            return LegoPinnedDownloadUrl;
        }
    }

    private NgProxyConfig LoadConfig(ISettingsSource settings)
    {
        var config = TryLoadConfig(settings, out var error);
        if (config == null)
        {
            throw new InvalidOperationException(error ?? "Invalid configuration.");
        }
        return config;
    }

    private string LoadCloudflareToken(ISettingsSource settings)
    {
        var encryptedToken = settings.GetOptional(ModuleConfigurationProvider.CloudflareApiToken) ?? string.Empty;
        var token = NormalizeCloudflareToken(TryDecrypt(encryptedToken));
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidOperationException("CloudflareApiToken is required.");
        }
        return token;
    }

    private NgProxyConfig? TryLoadConfig(ISettingsSource settings, out string? error)
    {
        error = null;

        var domain = NormalizeDomain(settings.GetOptional(ModuleConfigurationProvider.Domain));
        var email = (settings.GetOptional(ModuleConfigurationProvider.Email) ?? string.Empty).Trim();
        var upstreamUrl = (settings.GetOptional(ModuleConfigurationProvider.UpstreamUrl) ?? string.Empty).Trim();
        var dnsResolversRaw = settings.HasValue(ModuleConfigurationProvider.DnsResolvers)
            ? string.Join('\n', settings.GetRequired(ModuleConfigurationProvider.DnsResolvers))
            : string.Empty;
        var dnsResolvers = ParseDnsResolvers(dnsResolversRaw);
        var encryptedToken = settings.GetOptional(ModuleConfigurationProvider.CloudflareApiToken) ?? string.Empty;
        var token = NormalizeCloudflareToken(TryDecrypt(encryptedToken));

        if (string.IsNullOrWhiteSpace(domain))
        {
            error = "Domain is required.";
            return null;
        }

        if (string.IsNullOrWhiteSpace(email))
        {
            error = "Email is required.";
            return null;
        }

        if (string.IsNullOrWhiteSpace(upstreamUrl))
        {
            error = "UpstreamUrl is required.";
            return null;
        }

        if (!Uri.TryCreate(upstreamUrl, UriKind.Absolute, out var upstreamUri) || string.IsNullOrEmpty(upstreamUri.Scheme))
        {
            error = "UpstreamUrl must be an absolute URL, e.g. http://127.0.0.1:5384";
            return null;
        }

        if (string.IsNullOrWhiteSpace(token))
        {
            error = "CloudflareApiToken is required.";
            return null;
        }

        return new NgProxyConfig(domain, email, upstreamUrl, dnsResolvers);
    }

    private static string NormalizeDomain(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return string.Empty;
        value = value.Trim();
        if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                return new Uri(value).Host.Trim().TrimEnd('.').ToLowerInvariant();
            }
            catch
            {
                return value.Trim().TrimEnd('.').ToLowerInvariant();
            }
        }

        return value.Trim().TrimEnd('.').ToLowerInvariant();
    }

    private static IReadOnlyList<string> ParseDnsResolvers(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return Array.Empty<string>();
        }

        var tokens = value.Split(new[] { '\r', '\n', ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var resolvers = new List<string>();
        foreach (var token in tokens)
        {
            var resolver = NormalizeDnsResolver(token);
            if (!string.IsNullOrWhiteSpace(resolver))
            {
                resolvers.Add(resolver);
            }
        }

        return resolvers.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string NormalizeDnsResolver(string value)
    {
        value = value.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        if (value.StartsWith("[", StringComparison.Ordinal))
        {
            return value;
        }

        if (IPAddress.TryParse(value, out var ip))
        {
            return $"{FormatDnsHost(ip)}:53";
        }

        var lastColon = value.LastIndexOf(':');
        if (lastColon > 0 && lastColon < value.Length - 1)
        {
            var portPart = value[(lastColon + 1)..];
            if (int.TryParse(portPart, out _))
            {
                return value;
            }
        }

        return $"{value}:53";
    }

    private static string FormatDnsHost(IPAddress address)
    {
        return address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();
    }

    private static IReadOnlyList<string> TryGetSystemDnsResolvers()
    {
        try
        {
            var resolvers = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                {
                    if (dns.Equals(IPAddress.Any) || dns.Equals(IPAddress.IPv6Any))
                    {
                        continue;
                    }

                    if (dns.AddressFamily == AddressFamily.InterNetworkV6 && dns.IsIPv6SiteLocal)
                    {
                        continue;
                    }

                    var resolver = $"{FormatDnsHost(dns)}:53";
                    if (seen.Add(resolver))
                    {
                        resolvers.Add(resolver);
                    }
                }
            }

            // Prefer IPv4 resolvers first when both are available.
            return resolvers
                .OrderBy(x => x.StartsWith("[", StringComparison.Ordinal) ? 1 : 0)
                .ToArray();
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private string TryDecrypt(string value)
    {
        if (string.IsNullOrEmpty(value)) return value;
        try
        {
            return localEncryptionProvider.Decrypt(value);
        }
        catch
        {
            return value;
        }
    }

    private static string NormalizeCloudflareToken(string value)
    {
        value = value.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return string.Empty;
        }

        if (value.Contains('\n'))
        {
            value = value.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).FirstOrDefault()
                ?? value;
        }

        value = value.Trim().Trim('"').Trim('\'');
        if (value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            value = value["Bearer ".Length..].Trim();
        }

        var equalsIndex = value.IndexOf('=');
        if (equalsIndex <= 0)
        {
            return value;
        }

        var left = value[..equalsIndex].Trim();
        var right = value[(equalsIndex + 1)..].Trim().Trim('"').Trim('\'');
        if (left.Equals("dns_cloudflare_api_token", StringComparison.OrdinalIgnoreCase)
            || left.Equals("cf_dns_api_token", StringComparison.OrdinalIgnoreCase)
            || left.Equals("cf_zone_api_token", StringComparison.OrdinalIgnoreCase)
            || left.Equals("cloudflare_dns_api_token", StringComparison.OrdinalIgnoreCase)
            || left.Equals("cloudflare_zone_api_token", StringComparison.OrdinalIgnoreCase)
            || left.Equals("cloudflare_api_token", StringComparison.OrdinalIgnoreCase)
            || left.Equals("cf_api_token", StringComparison.OrdinalIgnoreCase)
            || left.Equals("CF_DNS_API_TOKEN", StringComparison.OrdinalIgnoreCase)
            || left.Equals("CF_ZONE_API_TOKEN", StringComparison.OrdinalIgnoreCase)
            || left.Equals("CLOUDFLARE_DNS_API_TOKEN", StringComparison.OrdinalIgnoreCase)
            || left.Equals("CLOUDFLARE_ZONE_API_TOKEN", StringComparison.OrdinalIgnoreCase))
        {
            return right;
        }

        return value;
    }

    private static string ComputeConfigHash(NgProxyConfig config)
    {
        var canonical =
            $"v2|domain={config.Domain}|email={config.Email}|upstream={config.UpstreamUrl}|dns_resolvers={string.Join(",", config.DnsResolvers)}";
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    private static async Task<string> EnsureToolAsync(
        string toolName,
        string exeName,
        string toolRoot,
        string downloadsFolder,
        string downloadUrl,
        HttpClient http,
        IDeferredReporter reporter,
        CancellationToken cancellationToken)
    {
        var existingExe = TryFindFirstFile(toolRoot, exeName);
        if (existingExe != null)
        {
            return existingExe;
        }

        reporter.Info($"{toolName}: downloading {downloadUrl}");
        var zipPath = Path.Combine(downloadsFolder, $"{toolName}.zip");
        await DownloadAsync(http, new Uri(downloadUrl), zipPath, reporter, cancellationToken);

        reporter.Info($"{toolName}: extracting...");
        Directory.CreateDirectory(toolRoot);

        var extractTo = Path.Combine(toolRoot, "_extract");
        if (Directory.Exists(extractTo))
        {
            Directory.Delete(extractTo, recursive: true);
        }
        Directory.CreateDirectory(extractTo);

        ZipFile.ExtractToDirectory(zipPath, extractTo, overwriteFiles: true);

        var extractedExe = TryFindFirstFile(extractTo, exeName);
        if (extractedExe == null)
        {
            throw new FileNotFoundException($"{toolName}: {exeName} not found after extraction", exeName);
        }

        if (Directory.Exists(toolRoot))
        {
            foreach (var entry in Directory.GetFileSystemEntries(toolRoot))
            {
                if (Path.GetFileName(entry).Equals("_extract", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                try
                {
                    if (Directory.Exists(entry))
                    {
                        Directory.Delete(entry, recursive: true);
                    }
                    else
                    {
                        File.Delete(entry);
                    }
                }
                catch
                {
                }
            }
        }

        foreach (var entry in Directory.GetFileSystemEntries(extractTo))
        {
            var dest = Path.Combine(toolRoot, Path.GetFileName(entry));
            if (Directory.Exists(entry))
            {
                Directory.Move(entry, dest);
            }
            else
            {
                File.Move(entry, dest, overwrite: true);
            }
        }

        Directory.Delete(extractTo, recursive: true);

        var finalExe = TryFindFirstFile(toolRoot, exeName);
        if (finalExe == null)
        {
            throw new FileNotFoundException($"{toolName}: {exeName} not found after install", exeName);
        }

        reporter.Info($"{toolName}: ready ({finalExe})");
        return finalExe;
    }

    private static async Task DownloadAsync(
        HttpClient http,
        Uri uri,
        string destinationPath,
        IDeferredReporter reporter,
        CancellationToken cancellationToken)
    {
        using var response = await http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            reporter.Error($"Download failed ({(int)response.StatusCode} {response.ReasonPhrase}): {uri}");
            throw new HttpRequestException(
                $"Download failed ({(int)response.StatusCode} {response.ReasonPhrase}): {uri}",
                inner: null,
                statusCode: response.StatusCode);
        }

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var fs = new FileStream(destinationPath, FileMode.Create, FileAccess.Write, FileShare.None);
        await stream.CopyToAsync(fs, cancellationToken);

        reporter.Info($"Downloaded {uri} ({new FileInfo(destinationPath).Length} bytes)");
    }

    private async Task RunLegoAsync(
        string legoExePath,
        NgProxyConfig config,
        string cloudflareToken,
        string acmePath,
        CancellationToken cancellationToken,
        IDeferredReporter reporter)
    {
        var certDir = Path.Combine(acmePath, "certificates");
        var certCrtPath = Path.Combine(certDir, $"{config.Domain}.crt");
        var certKeyPath = Path.Combine(certDir, $"{config.Domain}.key");

        var env = new Dictionary<string, string?>
        {
            ["CF_DNS_API_TOKEN"] = cloudflareToken,
            ["CF_ZONE_API_TOKEN"] = cloudflareToken,
            ["CLOUDFLARE_DNS_API_TOKEN"] = cloudflareToken,
            ["CLOUDFLARE_ZONE_API_TOKEN"] = cloudflareToken,
        };

        var commonArgs = new List<string>
        {
            "--accept-tos",
            "--email", config.Email,
            "--domains", config.Domain,
            "--path", acmePath,
            "--dns", "cloudflare",
        };

        IReadOnlyList<string> dnsResolvers = config.DnsResolvers;
        if (dnsResolvers.Count == 0)
        {
            dnsResolvers = TryGetSystemDnsResolvers();
        }
        if (dnsResolvers.Count == 0)
        {
            dnsResolvers = FallbackDnsResolvers;
        }

        if (dnsResolvers.Count > 0)
        {
            reporter.Info($"lego: using dns.resolvers: {string.Join(", ", dnsResolvers)}");
            foreach (var resolver in dnsResolvers)
            {
                commonArgs.Add("--dns.resolvers");
                commonArgs.Add(resolver);
            }
        }

        if (!File.Exists(certCrtPath) || !File.Exists(certKeyPath))
        {
            await RunProcessAsync(
                legoExePath,
                workingDirectory: Path.GetDirectoryName(legoExePath) ?? Environment.CurrentDirectory,
                args: [.. commonArgs, "run"],
                env: env,
                reporter: reporter,
                cancellationToken: cancellationToken);
            return;
        }

        await RunProcessAsync(
            legoExePath,
            workingDirectory: Path.GetDirectoryName(legoExePath) ?? Environment.CurrentDirectory,
            args: [.. commonArgs, "renew", "--days", "30"],
            env: env,
            reporter: reporter,
            cancellationToken: cancellationToken);
    }

    private static async Task RunProcessAsync(
        string fileName,
        string workingDirectory,
        IReadOnlyList<string> args,
        IReadOnlyDictionary<string, string?>? env,
        IDeferredReporter reporter,
        CancellationToken cancellationToken)
    {
        var ok = await TryRunProcessAsync(fileName, workingDirectory, args, env, reporter, cancellationToken);
        if (!ok)
        {
            throw new InvalidOperationException($"Process failed: {Path.GetFileName(fileName)} {string.Join(' ', args)}");
        }
    }

    private static async Task<bool> TryRunProcessAsync(
        string fileName,
        string workingDirectory,
        IReadOnlyList<string> args,
        IReadOnlyDictionary<string, string?>? env,
        IDeferredReporter reporter,
        CancellationToken cancellationToken)
    {
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = fileName,
            WorkingDirectory = workingDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (var arg in args)
        {
            process.StartInfo.ArgumentList.Add(arg);
        }

        if (env != null)
        {
            foreach (var (k, v) in env)
            {
                if (v != null)
                {
                    process.StartInfo.Environment[k] = v;
                }
            }
        }

        reporter.Info($"Running: {Path.GetFileName(fileName)} {string.Join(' ', args.Select(FormatArg))}");
        try
        {
            if (!process.Start())
            {
                reporter.Error($"Failed to start process: {fileName}");
                return false;
            }

            var stdoutTask = PumpAsync(process.StandardOutput, reporter.Info, cancellationToken);
            var stderrTask = PumpAsync(process.StandardError, reporter.Error, cancellationToken);

            await process.WaitForExitAsync(cancellationToken);
            await Task.WhenAll(stdoutTask, stderrTask);

            if (process.ExitCode != 0)
            {
                reporter.Error($"Exit code: {process.ExitCode}");
                return false;
            }

            return true;
        }
        catch (OperationCanceledException)
        {
            TryKill(process);
            throw;
        }
        catch (Exception ex)
        {
            reporter.Error(ex.Message);
            TryKill(process);
            return false;
        }
    }

    private static async Task StartNginxAsync(
        string nginxExePath,
        string nginxRoot,
        string nginxConfigPath,
        IDeferredReporter reporter,
        CancellationToken cancellationToken)
    {
        using var pumpCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var process = new Process();
        process.StartInfo = new ProcessStartInfo
        {
            FileName = nginxExePath,
            WorkingDirectory = nginxRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        process.StartInfo.ArgumentList.Add("-p");
        process.StartInfo.ArgumentList.Add(nginxRoot);
        process.StartInfo.ArgumentList.Add("-c");
        process.StartInfo.ArgumentList.Add(nginxConfigPath);

        reporter.Info($"Running: {Path.GetFileName(nginxExePath)} -p {FormatArg(nginxRoot)} -c {FormatArg(nginxConfigPath)}");

        if (!process.Start())
        {
            throw new InvalidOperationException("Failed to start nginx.");
        }

        var stdoutTask = PumpAsync(process.StandardOutput, reporter.Info, pumpCts.Token);
        var stderrTask = PumpAsync(process.StandardError, reporter.Error, pumpCts.Token);

        var waitTask = process.WaitForExitAsync(cancellationToken);
        var finished = await Task.WhenAny(waitTask, Task.Delay(TimeSpan.FromSeconds(3), cancellationToken));

        if (finished == waitTask)
        {
            pumpCts.Cancel();
            try
            {
                await Task.WhenAll(stdoutTask, stderrTask);
            }
            catch (OperationCanceledException)
            {
            }

            if (process.ExitCode != 0)
            {
                throw new InvalidOperationException($"nginx failed to start (exit code {process.ExitCode}).");
            }
        }
        else
        {
            // nginx likely daemonized. Stop pumping to avoid hanging forever.
            pumpCts.Cancel();
            try
            {
                await Task.WhenAll(stdoutTask, stderrTask);
            }
            catch (OperationCanceledException)
            {
            }
        }
    }

    private static async Task WriteFullChainAsync(string certPath, string issuerPath, string fullChainPath, CancellationToken cancellationToken)
    {
        await using var dest = new FileStream(fullChainPath, FileMode.Create, FileAccess.Write, FileShare.None);
        await using (var src = new FileStream(certPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await src.CopyToAsync(dest, cancellationToken);
        }

        await using (var src = new FileStream(issuerPath, FileMode.Open, FileAccess.Read, FileShare.Read))
        {
            await src.CopyToAsync(dest, cancellationToken);
        }
    }

    private static async Task<bool> WaitForNginxAsync(string pidFilePath, TimeSpan timeout, CancellationToken cancellationToken)
    {
        var sw = Stopwatch.StartNew();
        while (sw.Elapsed < timeout && !cancellationToken.IsCancellationRequested)
        {
            if (TryIsProcessRunningFromPidFile(pidFilePath, out _))
            {
                return true;
            }

            await Task.Delay(250, cancellationToken);
        }

        return TryIsProcessRunningFromPidFile(pidFilePath, out _);
    }

    private static string BuildNginxConfig(NgProxyConfig config, string fullChainPath, string keyPath, string pidPath)
    {
        var fullChain = ToNginxPath(fullChainPath);
        var key = ToNginxPath(keyPath);
        var pid = ToNginxPath(pidPath);

        // Note: proxy_pass expects a URL, so we keep it as-is.
        var upstream = config.UpstreamUrl;

        return $$"""
        worker_processes  1;
        error_log  logs/ngproxy_error.log  info;
        pid        "{{pid}}";

        events {
            worker_connections  1024;
        }

        http {
            include       mime.types;
            default_type  application/octet-stream;

            log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                              '$status $body_bytes_sent "$http_referer" '
                              '"$http_user_agent" "$http_x_forwarded_for"';

            access_log  logs/ngproxy_access.log  main;

            sendfile        on;
            keepalive_timeout  65;

            map $http_upgrade $connection_upgrade {
                default upgrade;
                '' close;
            }

            server {
                listen 80;
                server_name {{config.Domain}};
                return 301 https://$host$request_uri;
            }

            server {
                listen 443 ssl;
                server_name {{config.Domain}};

                ssl_certificate "{{fullChain}}";
                ssl_certificate_key "{{key}}";

                location / {
                    proxy_pass {{upstream}};
                    proxy_http_version 1.1;
                    proxy_set_header Host $host;
                    proxy_set_header X-Real-IP $remote_addr;
                    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                    proxy_set_header X-Forwarded-Proto $scheme;
                    proxy_set_header Upgrade $http_upgrade;
                    proxy_set_header Connection $connection_upgrade;
                    proxy_read_timeout 3600s;
                    proxy_send_timeout 3600s;
                    proxy_buffering off;
                }
            }
        }
        """;
    }

    private static string ToNginxPath(string path) => path.Replace('\\', '/');

    private static async Task PumpAsync(StreamReader reader, Action<string> sink, CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(cancellationToken);
            if (line == null)
            {
                break;
            }

            if (!string.IsNullOrWhiteSpace(line))
            {
                sink(line);
            }
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
        }
    }

    private static string? TryFindFirstFile(string root, string fileName)
    {
        try
        {
            if (!Directory.Exists(root))
            {
                return null;
            }

            return Directory.GetFiles(root, fileName, SearchOption.AllDirectories)
                .OrderBy(x => x.Length)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    private static bool TryIsProcessRunningFromPidFile(string pidFilePath, out int pid)
    {
        pid = 0;
        try
        {
            if (!File.Exists(pidFilePath))
            {
                return false;
            }

            var text = File.ReadAllText(pidFilePath).Trim();
            if (!int.TryParse(text, out pid))
            {
                return false;
            }

            var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch
        {
            return false;
        }
    }

    private static DateTimeOffset? TryGetCertNotAfter(string certPemPath)
    {
        try
        {
            using var cert = X509Certificate2.CreateFromPemFile(certPemPath);
            return new DateTimeOffset(cert.NotAfter.ToUniversalTime());
        }
        catch
        {
            return null;
        }
    }

    private static async Task<NgProxyState?> TryReadStateAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var json = await File.ReadAllTextAsync(path, cancellationToken);
            return JsonSerializer.Deserialize<NgProxyState>(json);
        }
        catch
        {
            return null;
        }
    }

    private static async Task WriteStateAsync(string path, NgProxyState state, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(state, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(path, json, Encoding.UTF8, cancellationToken);
    }

    private static string FormatArg(string arg) => arg.Contains(' ') ? $"\"{arg}\"" : arg;

    private sealed record NgProxyConfig(string Domain, string Email, string UpstreamUrl, IReadOnlyList<string> DnsResolvers);

    public sealed record NgProxyEvaluation(
        bool ConfigValid,
        string? ConfigError,
        bool ToolsPresent,
        bool NginxConfigPresent,
        bool CertPresent,
        DateTimeOffset? CertNotAfter,
        bool NginxRunning,
        bool NeedsInstallation,
        string ToolsRoot,
        string? NginxExePath,
        string? LegoExePath,
        string? NginxConfigPath,
        NgProxyState? State);

    public sealed class NgProxyState
    {
        public DateTimeOffset UpdatedAtUtc { get; init; }
        public string? Domain { get; init; }
        public string? Email { get; init; }
        public string? UpstreamUrl { get; init; }
        public string? ConfigHash { get; init; }
        public DateTimeOffset? CertNotAfterUtc { get; init; }
        public string? NginxExePath { get; init; }
        public string? LegoExePath { get; init; }
        public string? NginxConfigPath { get; init; }
        public string? NginxPidPath { get; init; }
        public string? AcmePath { get; init; }
        public string? LastError { get; init; }
    }
}
