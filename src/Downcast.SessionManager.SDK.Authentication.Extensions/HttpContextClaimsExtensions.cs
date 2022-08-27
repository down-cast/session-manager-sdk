using System.Security.Claims;

using Downcast.Common.Errors;

namespace Downcast.SessionManager.SDK.Authentication.Extensions;

public static class HttpContextClaimsExtensions
{
    public static string? GetUserId(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.GetClaimValue(ClaimNames.UserId);
    }

    public static IReadOnlyCollection<string> GetRoles(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.Claims
            .Where(claim => claim.Type.Equals(ClaimNames.Role))
            .Select(claim => claim.Value)
            .ToList();
    }

    public static string? GetEmail(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.GetClaimValue(ClaimNames.Email);
    }

    public static string? GetName(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.GetClaimValue(ClaimNames.Name);
    }

    public static string GetRequiredUserId(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.GetRequiredClaimValue(ClaimNames.UserId);
    }

    public static string GetRequiredEmail(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.GetRequiredClaimValue(ClaimNames.Email);
    }

    public static string GetRequiredName(this ClaimsPrincipal claimsPrincipal)
    {
        return claimsPrincipal.GetRequiredClaimValue(ClaimNames.Name);
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