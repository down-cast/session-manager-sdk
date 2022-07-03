using Downcast.Common.HttpClient.Extensions;
using Downcast.SessionManager.SDK.Client;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using Refit;

namespace Downcast.SessionManager.SDK.Extensions;

public static class SessionManagerConfigExtensions
{
    public static IHttpClientBuilder AddSessionManagerHttpClient(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        return services
            .AddRefitClient<ISessionManagerClient>()
            .ConfigureDowncastHttpClient(configuration, "SessionManagerClient");
    }
}