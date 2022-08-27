namespace Downcast.SessionManager.SDK.Client.Model;

public class TokenResult
{
    public string Token { get; set; } = null!;
    public DateTime ExpirationDate { get; set; }
}