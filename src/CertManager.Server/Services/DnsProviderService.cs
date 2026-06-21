using AlibabaCloud.SDK.Alidns20150109;
using AlibabaCloud.SDK.Alidns20150109.Models;
using CertManager.Shared.Models;

namespace CertManager.Server.Services;

public class DnsProviderService
{
    private readonly ILogger<DnsProviderService> _logger;
    private readonly Dictionary<string, List<string>> _zoneCache = [];

    public DnsProviderService(ILogger<DnsProviderService> logger)
    {
        _logger = logger;
    }

    public async Task AddTxtRecordAsync(CertProviderConfig provider, string domain, string txtValue)
    {
        var client = CreateClient(provider);
        var (zoneName, rr) = await ResolveZoneAsync(client, domain);
        _logger.LogInformation("Adding TXT record: {Rr}.{Zone} = {Value}", rr, zoneName, txtValue);

        var request = new AddDomainRecordRequest
        {
            DomainName = zoneName,
            RR = rr,
            Type = "TXT",
            Value = txtValue
        };

        await client.AddDomainRecordAsync(request);
        _logger.LogInformation("TXT record added successfully");
    }

    public async Task DeleteTxtRecordAsync(CertProviderConfig provider, string domain)
    {
        var client = CreateClient(provider);
        var (zoneName, rr) = await ResolveZoneAsync(client, domain);
        _logger.LogInformation("Deleting TXT records: {Rr}.{Zone}", rr, zoneName);

        var describeRequest = new DescribeDomainRecordsRequest
        {
            DomainName = zoneName,
            RRKeyWord = rr,
            Type = "TXT"
        };
        var describeResponse = await client.DescribeDomainRecordsAsync(describeRequest);

        if (describeResponse.Body?.DomainRecords?.Record?.Count > 0)
        {
            foreach (var record in describeResponse.Body.DomainRecords.Record)
            {
                var deleteRequest = new DeleteDomainRecordRequest
                {
                    RecordId = record.RecordId
                };
                await client.DeleteDomainRecordAsync(deleteRequest);
                _logger.LogInformation("Deleted record: {RecordId}", record.RecordId);
            }
        }
    }

    private Client CreateClient(CertProviderConfig provider)
    {
        var config = new AlibabaCloud.OpenApiClient.Models.Config
        {
            AccessKeyId = provider.KeyId,
            AccessKeySecret = provider.KeySecret
        };
        config.Endpoint = "alidns.cn-hangzhou.aliyuncs.com";
        return new Client(config);
    }

    private async Task<List<string>> GetAliyunZonesAsync(Client client)
    {
        var cacheKey = client.GetHashCode().ToString();
        if (_zoneCache.TryGetValue(cacheKey, out var cached))
            return cached;

        var zones = new List<string>();
        var page = 1L;
        while (true)
        {
            var request = new DescribeDomainsRequest
            {
                PageNumber = page,
                PageSize = 100
            };
            var response = await client.DescribeDomainsAsync(request);
            if (response.Body?.Domains?.Domain == null || response.Body.Domains.Domain.Count == 0)
                break;

            foreach (var d in response.Body.Domains.Domain)
            {
                if (!string.IsNullOrEmpty(d.DomainName))
                    zones.Add(d.DomainName);
            }

            if (response.Body.TotalCount <= page * 100)
                break;
            page++;
        }

        _zoneCache[cacheKey] = zones;
        _logger.LogInformation("Loaded {Count} DNS zones from Aliyun", zones.Count);
        return zones;
    }

    private async Task<(string zoneName, string rr)> ResolveZoneAsync(Client client, string certDomain)
    {
        var zones = await GetAliyunZonesAsync(client);
        var challengeName = $"_acme-challenge.{certDomain}";

        var matchedZone = zones
            .Where(z => challengeName.EndsWith("." + z) || challengeName == z)
            .OrderByDescending(z => z.Length)
            .FirstOrDefault();

        if (matchedZone == null)
            throw new Exception($"Cannot find DNS zone for domain {certDomain} in Aliyun account. Available zones: {string.Join(", ", zones)}");

        var rr = challengeName[..^(matchedZone.Length + 1)];
        _logger.LogInformation("Resolved zone: {Zone}, RR: {Rr} for domain {Domain}", matchedZone, rr, certDomain);
        return (matchedZone, rr);
    }
}
