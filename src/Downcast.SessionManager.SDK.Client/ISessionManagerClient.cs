using Refit;

namespace Downcast.SessionManager.SDK.Client;

public interface ISessionManagerClient
{
    [Post("/api/v1/session")]
    Task<string> CreateSessionToken([Body] IDictionary<string, string> claims);

    [Post("/api/v1/session/validate")]
    Task<IDictionary<string, object>> ValidateSessionToken([Body(BodySerializationMethod.Serialized)] string token);
}