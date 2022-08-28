using System.Security.Claims;

using Downcast.Common.Errors;

namespace Downcast.SessionManager.SDK.Authentication.Extensions;

public static class HttpContextClaimsExtensions
{
    public static IReadOnlyCollection<string> Roles(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.Claims
            .Where(claim => claim.Type.Equals(ClaimNames.Role))
            .Select(claim => claim.Value)
            .ToList();
    }

    public static string UserId(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.GetRequiredClaimValue(ClaimNames.UserId);
    }

    public static string Email(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.GetRequiredClaimValue(ClaimNames.Email);
    }
    
    public static string? DisplayName(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.GetClaimValue(ClaimNames.DisplayName);
    }
    

    public static string GetRequiredClaimValue(this ClaimsPrincipal claimsPrincipal, string claimName)
    {
        Claim? claim = claimsPrincipal.Claims.FirstOrDefault(claim => claim.Type.Equals(claimName));
        if (claim is null)
        {
            throw new DcException(ErrorCodes.ClaimNotFound, $"Claim {claimName} not present in context");
        }

        return claim.Value;
    }

    public static string? GetClaimValue(this ClaimsPrincipal claimsPrincipal, string claimName)
    {
        return claimsPrincipal.Claims.FirstOrDefault(claim => claim.Type.Equals(claimName))?.Value;
    }
}