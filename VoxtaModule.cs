using JetBrains.Annotations;
using Microsoft.Extensions.DependencyInjection;
using Voxta.Abstractions.Modules;
using Voxta.Abstractions.Registration;
using Voxta.Model.Shared;
using Voxta.Modules.NGProxy.Configuration;
using Voxta.Modules.NGProxy.Services;

namespace Voxta.Modules.NGProxy;

[UsedImplicitly]
public class VoxtaModule : IVoxtaModule
{
    public const string ServiceName = "NGProxy";
    public const string AugmentationKey = "ngproxy";

    public void Configure(IVoxtaModuleBuilder builder)
    {
        builder.Register(new ModuleDefinition
        {
            ServiceName = ServiceName,
            Label = "NGProxy (Single-Host Nginx Reverse Proxy) [alpha]",
            Notes = "Windows-only nginx reverse proxy for a single hostname. Installs nginx + lego, issues Let’s Encrypt certs via Cloudflare DNS-01, and proxies to a local upstream URL.",
            HelpLink = "https://doc.voxta.ai/",
            Experimental = true,
            Single = true,
            CanBeInstalledByAdminsOnly = true,
            Supports = new()
            {
                { ServiceTypes.ChatAugmentations, ServiceDefinitionCategoryScore.Low },
            },
            Pricing = ServiceDefinitionPricing.Free,
            Hosting = ServiceDefinitionHosting.Builtin,
            SupportsExplicitContent = true,
            Recommended = false,
            Augmentations = [AugmentationKey],
            ModuleConfigurationProviderType = typeof(ModuleConfigurationProvider),
            ModuleConfigurationFieldsRequiringReload = ModuleConfigurationProvider.FieldsRequiringReload,
            ModuleInstallationProviderType = typeof(ServiceInstallationProvider),
            ModuleTestingProviderType = typeof(NgProxyModuleTestingProvider),
        });

        builder.AddChatAugmentationsService<NgProxyChatAugmentationsService>(ServiceName);
        builder.Services.AddHttpClient();
    }
}
