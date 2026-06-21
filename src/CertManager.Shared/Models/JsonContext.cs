using System.Text.Json;
using System.Text.Json.Serialization;

namespace CertManager.Shared.Models;

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = true)]
[JsonSerializable(typeof(ServerConfig))]
[JsonSerializable(typeof(ClientAuthConfig))]
[JsonSerializable(typeof(CertProviderConfig))]
[JsonSerializable(typeof(ClientConfig))]
[JsonSerializable(typeof(DomainCertConfig))]
[JsonSerializable(typeof(AuthRequest))]
[JsonSerializable(typeof(CertDownloadRequest))]
[JsonSerializable(typeof(CertFileInfo))]
[JsonSerializable(typeof(ApiResponse))]
public partial class CertManagerJsonContext : JsonSerializerContext
{
}
