using System.Security.Cryptography.X509Certificates;
using CertManager.Shared.Models;

namespace CertManager.Server.Services;

public class CertRenewWorker : BackgroundService
{
    private readonly ILogger<CertRenewWorker> _logger;
    private readonly ServerConfig _config;
    private readonly AcmeService _acmeService;
    private readonly DnsProviderService _dnsProviderService;
    private readonly IServiceProvider _serviceProvider;

    public CertRenewWorker(
        ILogger<CertRenewWorker> logger,
        ServerConfig config,
        AcmeService acmeService,
        DnsProviderService dnsProviderService,
        IServiceProvider serviceProvider)
    {
        _logger = logger;
        _config = config;
        _acmeService = acmeService;
        _dnsProviderService = dnsProviderService;
        _serviceProvider = serviceProvider;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("CertRenewWorker started, interval: {Hours}h", _config.CertCheckIntervalHours);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await CheckAndRenewCertsAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking certificates");
            }

            await Task.Delay(TimeSpan.FromHours(_config.CertCheckIntervalHours), stoppingToken);
        }
    }

    private async Task CheckAndRenewCertsAsync(CancellationToken ct)
    {
        _logger.LogInformation("Starting certificate check...");
        var allDomains = _config.Certs.SelectMany(c => c.Domains).Distinct().ToList();

        foreach (var domain in allDomains)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                await CheckDomainCertAsync(domain, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing domain {Domain}", domain);
            }
        }
    }

    private async Task CheckDomainCertAsync(string domain, CancellationToken ct)
    {
        var certDir = Path.Combine(_config.CertDir, domain);
        var fullchainFile = Path.Combine(certDir, "fullchain.pem");
        var privkeyFile = Path.Combine(certDir, "privkey.pem");

        var needsRenew = ShouldRenew(fullchainFile);

        if (!needsRenew)
        {
            _logger.LogInformation("Certificate for {Domain} is valid, skip renew", domain);
            return;
        }

        _logger.LogInformation("Certificate for {Domain} needs renewal", domain);

        var provider = _config.Certs.FirstOrDefault(c => c.Domains.Contains(domain));
        if (provider == null)
        {
            _logger.LogError("No DNS provider configured for domain {Domain}", domain);
            return;
        }

        var (fullchainPem, privkeyPem) = await _acmeService.RequestCertificateAsync(
            _config.LetsEncryptEmail,
            domain,
            async (txtValue) =>
            {
                await _dnsProviderService.AddTxtRecordAsync(provider, domain, txtValue);
                await Task.Delay(15000, ct);
            },
            async () =>
            {
                try { await _dnsProviderService.DeleteTxtRecordAsync(provider, domain); }
                catch (Exception ex) { _logger.LogWarning(ex, "Failed to delete TXT record for {Domain}", domain); }
            });

        Directory.CreateDirectory(certDir);
        await File.WriteAllTextAsync(fullchainFile, fullchainPem, ct);
        await File.WriteAllTextAsync(privkeyFile, privkeyPem, ct);

        _logger.LogInformation("Certificate for {Domain} saved to {Dir}", domain, certDir);
    }

    private bool ShouldRenew(string fullchainFile)
    {
        if (!File.Exists(fullchainFile))
        {
            _logger.LogInformation("Certificate file not found: {File}", fullchainFile);
            return true;
        }

        try
        {
            var pem = File.ReadAllText(fullchainFile);
            var cert = X509Certificate2.CreateFromPem(pem);
            var daysLeft = (cert.NotAfter - DateTime.UtcNow).TotalDays;

            _logger.LogInformation("Certificate expires in {DaysLeft:F1} days, renew threshold: {RenewDays} days",
                daysLeft, _config.CertRenewDays);

            return daysLeft < _config.CertRenewDays;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to parse certificate, will renew");
            return true;
        }
    }
}
