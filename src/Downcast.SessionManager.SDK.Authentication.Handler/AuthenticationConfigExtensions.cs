using Downcast.SessionManager.SDK.Extensions;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Downcast.SessionManager.SDK.Authentication.Handler;

public static class AuthenticationConfigExtensions
{
    public static AuthenticationBuilder AddDowncastAuthentication(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.AddSessionManagerHttpClient(configuration);
        return services.AddAuthentication(options =>
            {
                options.DefaultScheme = DowncastAuthenticationHandler.BearerTokenScheme;
            })
            .AddScheme<AuthenticationSchemeOptions, DowncastAuthenticationHandler>("Bearer", _ => { });
    }
}