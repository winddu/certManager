using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertManager.Shared.Models;

namespace CertManager.Server.Services;

public class AuthService
{
    private readonly ServerConfig _config;

    public AuthService(ServerConfig config)
    {
        _config = config;
    }

    public ClientAuthConfig? Authenticate(string key, string timestamp, string sign, string? body = null)
    {
        var client = _config.Clients.FirstOrDefault(c => c.Key == key);
        if (client == null) return null;

        var ts = long.TryParse(timestamp, out var tsLong)
            ? DateTimeOffset.FromUnixTimeMilliseconds(tsLong)
            : DateTimeOffset.MinValue;

        if (Math.Abs((new DateTimeOffset(SystemTime.UtcNow) - ts).TotalMinutes) > 5)
            return null;

        // 反序列化请求，去掉 sign 字段后重新序列化，确保签名时不含 sign
        var cleanBody = body;
        if (body != null)
        {
            try
            {
                var req = JsonSerializer.Deserialize(body, CertManagerJsonContext.Default.CertDownloadRequest);
                if (req != null)
                {
                    req.Sign = "";
                    cleanBody = JsonSerializer.Serialize(req, CertManagerJsonContext.Default.CertDownloadRequest);
                }
            }
            catch { }
        }

        var expectedSign = ComputeSign(client.Salt, timestamp, cleanBody);

        if (sign != expectedSign) return null;

        return client;
    }

    public static string ComputeSign(string salt, string timestamp, string? body = null)
    {
        var data = timestamp + (body ?? "");
        var keyBytes = Encoding.UTF8.GetBytes(salt);
        var dataBytes = Encoding.UTF8.GetBytes(data);

        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(dataBytes);
        return Convert.ToHexString(hash).ToLower();
    }
}
