using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;

using Downcast.SessionManager.SDK.Authentication.Extensions;
using Downcast.SessionManager.SDK.Client;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.Net.Http.Headers;

namespace Downcast.SessionManager.SDK.Authentication.Handler;

public class DowncastAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly ISessionManagerClient _sessionManagerClient;
    private readonly ILogger<DowncastAuthenticationHandler> _logger;
    private readonly JsonWebTokenHandler _handler = new();
    internal const string BearerTokenScheme = "Bearer";

    public DowncastAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock,
        ISessionManagerClient sessionManagerClient) : base(options, logger, encoder, clock)
    {
        _sessionManagerClient = sessionManagerClient;
        _logger               = logger.CreateLogger<DowncastAuthenticationHandler>();
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue(HeaderNames.Authorization, out StringValues header))
        {
            return AuthenticateResult.Fail($"{HeaderNames.Authorization} header not present");
        }

        if (!AuthenticationHeaderValue.TryParse(header, out AuthenticationHeaderValue? authHeader))
        {
            return AuthenticateResult.Fail("Could not correctly parse Authorization header");
        }

        if (authHeader is not { Scheme: BearerTokenScheme, Parameter.Length: > 0 })
        {
            return AuthenticateResult.Fail("Authorization scheme not supported");
        }

        return await GetRemoteAuthenticateResult(authHeader.Parameter).ConfigureAwait(false);
    }

    private async Task<AuthenticateResult> GetRemoteAuthenticateResult(string token)
    {
        bool isTokenValid = await IsTokenValid(token).ConfigureAwait(false);
        return isTokenValid
            ? BuildAuthenticationResult(token)
            : HandleRequestResult.Fail("Null claims, returning failed authentication");
    }

    private AuthenticateResult BuildAuthenticationResult(string token)
    {
        IEnumerable<Claim> claims = _handler.ReadJsonWebToken(token).Claims;
        var identity = new ClaimsIdentity(
            claims,
            "remote-session-validation",
            ClaimNames.Name,
            ClaimNames.Role);

        var claimsPrincipal = new ClaimsPrincipal(identity);

        var authTicket = new AuthenticationTicket(
            claimsPrincipal,
            new AuthenticationProperties(),
            BearerTokenScheme);

        return AuthenticateResult.Success(authTicket);
    }

    private async Task<bool> IsTokenValid(string token)
    {
        try
        {
            await _sessionManagerClient.ValidateSessionToken(token).ConfigureAwait(false);
            return true;
        }
        catch (Exception e)
        {
            _logger.LogWarning("Could not validate user session: {Message}", e.Message);
            return false;
        }
    }
}