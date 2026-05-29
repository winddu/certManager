using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertManager.Shared.Models;
using Microsoft.Extensions.Logging;

namespace CertManager.Client.Services;

public class CertDownloadService
{
    private readonly ILogger<CertDownloadService> _logger;
    private readonly HttpClient _httpClient;

    public CertDownloadService(ILogger<CertDownloadService> logger)
    {
        _logger = logger;
        _httpClient = new HttpClient();
    }

    public async Task<bool> DownloadCertificatesAsync(ClientConfig config)
    {
        var domains = config.Domains.Select(d => d.Name).ToList();
        _logger.LogInformation("Requesting certificates for: {Domains}", string.Join(", ", domains));

        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();

        var request = new CertDownloadRequest
        {
            Key = config.Key,
            Timestamp = timestamp,
            Domains = domains
        };

        var bodyJson = JsonSerializer.Serialize(request);
        request.Sign = ComputeSign(config.Salt, timestamp, bodyJson);

        var httpContent = new StringContent(JsonSerializer.Serialize(request), Encoding.UTF8, "application/json");

        try
        {
            var response = await _httpClient.PostAsync($"{config.ServerUrl}/cert/download", httpContent);
            var responseBody = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Server returned {StatusCode}: {Body}", (int)response.StatusCode, responseBody);
                return false;
            }

            var apiResponse = JsonSerializer.Deserialize<ApiResponse>(responseBody);
            if (apiResponse == null || apiResponse.Code != 0)
            {
                _logger.LogError("API error: {Code} - {Message}", apiResponse?.Code, apiResponse?.Message);
                return false;
            }

            if (apiResponse.Data == null || apiResponse.Data.Count == 0)
            {
                _logger.LogWarning("No certificate data returned from server");
                return false;
            }

            foreach (var certInfo in apiResponse.Data)
            {
                var domainConfig = config.Domains.FirstOrDefault(d => d.Name == certInfo.Domain);
                if (domainConfig == null)
                {
                    _logger.LogWarning("No local config for domain: {Domain}, skipping", certInfo.Domain);
                    continue;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(domainConfig.FullchainPath)!);
                Directory.CreateDirectory(Path.GetDirectoryName(domainConfig.PrivkeyPath)!);

                await File.WriteAllTextAsync(domainConfig.FullchainPath, certInfo.FullchainPem);
                await File.WriteAllTextAsync(domainConfig.PrivkeyPath, certInfo.PrivkeyPem);

                _logger.LogInformation("Saved certificate for {Domain}: {Fullchain}, {Privkey}",
                    certInfo.Domain, domainConfig.FullchainPath, domainConfig.PrivkeyPath);
            }

            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to download certificates from server");
            return false;
        }
    }

    private static string ComputeSign(string salt, string timestamp, string? body = null)
    {
        var data = timestamp + (body ?? "");
        var keyBytes = Encoding.UTF8.GetBytes(salt);
        var dataBytes = Encoding.UTF8.GetBytes(data);

        using var hmac = new HMACSHA256(keyBytes);
        var hash = hmac.ComputeHash(dataBytes);
        return Convert.ToHexString(hash).ToLower();
    }
}
