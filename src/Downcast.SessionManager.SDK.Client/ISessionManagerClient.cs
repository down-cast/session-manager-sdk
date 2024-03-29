﻿using Downcast.SessionManager.SDK.Client.Model;

using Refit;

namespace Downcast.SessionManager.SDK.Client;

public interface ISessionManagerClient
{
    [Post("/api/v1/session")]
    Task<TokenResult> CreateSessionToken([Body] IDictionary<string, object> claims);

    [Post("/api/v1/session/validate")]
    Task ValidateSessionToken([Body(BodySerializationMethod.Serialized)] string token);
}