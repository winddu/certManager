using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertManager.Server.Services;
using CertManager.Shared.Models;

namespace CertManager.Server.Api;

public static class CertApi
{
    public static void Map(WebApplication app)
    {
        app.MapGet("/ping", () => Results.Ok(new { status = "ok", time = SystemTime.UtcNow }));

        app.MapPost("/cert/download", async (HttpContext context, ServerConfig config, ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger("CertApi");

            string body;
            using (var reader = new StreamReader(context.Request.Body))
                body = await reader.ReadToEndAsync();

            CertDownloadRequest? request;
            try { request = JsonSerializer.Deserialize(body, CertManagerJsonContext.Default.CertDownloadRequest); }
            catch { return Results.Json(new ApiResponse { Code = 400, Message = "Invalid JSON" }, CertManagerJsonContext.Default.ApiResponse, statusCode: 400); }

            if (request == null || string.IsNullOrEmpty(request.Key) || string.IsNullOrEmpty(request.Timestamp) || string.IsNullOrEmpty(request.Sign))
                return Results.Json(new ApiResponse { Code = 400, Message = "Missing auth fields" }, CertManagerJsonContext.Default.ApiResponse, statusCode: 400);

            var authService = context.RequestServices.GetRequiredService<AuthService>();
            var client = authService.Authenticate(request.Key, request.Timestamp, request.Sign, body);
            if (client == null)
                return Results.Json(new ApiResponse { Code = 401, Message = "Authentication failed" }, CertManagerJsonContext.Default.ApiResponse, statusCode: 401);

            if (request.Domains == null || request.Domains.Count == 0)
                return Results.Json(new ApiResponse { Code = 400, Message = "No domains requested" }, CertManagerJsonContext.Default.ApiResponse, statusCode: 400);

            var result = new List<CertFileInfo>();
            foreach (var domain in request.Domains)
            {
                if (!client.Privilege.Contains(domain))
                {
                    logger.LogWarning("Client {Name} requested unauthorized domain: {Domain}", client.Name, domain);
                    return Results.Json(new ApiResponse { Code = 403, Message = $"No privilege for domain: {domain}" }, CertManagerJsonContext.Default.ApiResponse, statusCode: 403);
                }

                var certDir = Path.Combine(config.CertDir, domain);
                var fullchainFile = Path.Combine(certDir, "fullchain.pem");
                var privkeyFile = Path.Combine(certDir, "privkey.pem");

                if (!File.Exists(fullchainFile) || !File.Exists(privkeyFile))
                    return Results.Json(new ApiResponse { Code = 404, Message = $"Certificate for {domain} not found on server" }, CertManagerJsonContext.Default.ApiResponse, statusCode: 404);

                var fullchain = await File.ReadAllTextAsync(fullchainFile);
                var privkey = await File.ReadAllTextAsync(privkeyFile);

                var cert = X509Certificate2.CreateFromPem(fullchain);

                result.Add(new CertFileInfo
                {
                    Domain = domain,
                    FullchainPem = fullchain,
                    PrivkeyPem = privkey,
                    NotAfter = cert.NotAfter
                });

                logger.LogInformation("Client {Name} downloaded certificate for {Domain}", client.Name, domain);
            }

            return Results.Json(new ApiResponse { Code = 0, Message = "ok", Data = result }, CertManagerJsonContext.Default.ApiResponse);
        });
    }
}
