using AlibabaCloud.SDK.Alidns20150109;
using AlibabaCloud.SDK.Alidns20150109.Models;
using CertManager.Shared.Models;

namespace CertManager.Server.Services;

public class DnsProviderService
{
    private readonly ILogger<DnsProviderService> _logger;

    public DnsProviderService(ILogger<DnsProviderService> logger)
    {
        _logger = logger;
    }

    public async Task AddTxtRecordAsync(CertProviderConfig provider, string domain, string txtValue)
    {
        var (zoneName, rr) = ResolveZone(provider.Domains, domain);
        _logger.LogInformation("Adding TXT record: {Rr}.{Zone} = {Value}", rr, zoneName, txtValue);

        var client = CreateClient(provider);
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
        var (zoneName, rr) = ResolveZone(provider.Domains, domain);
        _logger.LogInformation("Deleting TXT records: {Rr}.{Zone}", rr, zoneName);

        var client = CreateClient(provider);

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

    public async Task WaitForPropagationAsync(string domain, string txtValue, int timeoutSeconds = 120)
    {
        _logger.LogInformation("Waiting for DNS propagation for {Domain}...", domain);
        var challengeHost = $"_acme-challenge.{domain}";
        var deadline = DateTime.UtcNow.AddSeconds(timeoutSeconds);

        while (DateTime.UtcNow < deadline)
        {
            try
            {
                var dnsLookup = System.Net.Dns.GetHostEntry(challengeHost);
                if (dnsLookup.Aliases.Any(a => a.Contains(txtValue)))
                {
                    _logger.LogInformation("DNS propagation confirmed");
                    return;
                }

                var txtRecords = dnsLookup.Aliases.ToList();
                _logger.LogDebug("Current TXT records: {Records}", string.Join(", ", txtRecords));
            }
            catch
            {
                _logger.LogDebug("DNS not yet propagated...");
            }

            await Task.Delay(5000);
        }

        _logger.LogWarning("DNS propagation timeout, proceeding anyway");
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

    private (string zoneName, string rr) ResolveZone(List<string> zones, string certDomain)
    {
        var challengeName = $"_acme-challenge.{certDomain}";

        var matchedZone = zones
            .Where(z => challengeName.EndsWith("." + z) || challengeName == z)
            .OrderByDescending(z => z.Length)
            .FirstOrDefault();

        if (matchedZone == null)
            throw new Exception($"Cannot find DNS zone for domain {certDomain}. Available zones: {string.Join(", ", zones)}");

        var rr = challengeName[..^(matchedZone.Length + 1)];
        return (matchedZone, rr);
    }
}
