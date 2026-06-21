using Certes;
using Certes.Acme;
using Certes.Acme.Resource;

namespace CertManager.Server.Services;

public class AcmeService
{
    private readonly ILogger<AcmeService> _logger;
    private readonly string _accountKeyPath;

    public AcmeService(ILogger<AcmeService> logger)
    {
        _logger = logger;
        _accountKeyPath = Path.Combine(AppContext.BaseDirectory, ".acme_account_key.pem");
    }

    public async Task<(string fullchainPem, string privkeyPem)> RequestCertificateAsync(
        string email, string domain, Func<string, Task> addDnsRecord, Func<Task> deleteDnsRecord)
    {
        var wildcardDomain = $"*.{domain}";
        _logger.LogInformation("Requesting certificate for {Domain}", wildcardDomain);

        IKey accountKey;
        if (File.Exists(_accountKeyPath))
        {
            var pem = await File.ReadAllTextAsync(_accountKeyPath);
            accountKey = KeyFactory.FromPem(pem);
            _logger.LogInformation("Loaded existing ACME account key");
        }
        else
        {
            accountKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
            await File.WriteAllTextAsync(_accountKeyPath, accountKey.ToPem());
            _logger.LogInformation("Created new ACME account key");
        }

        var ctx = new AcmeContext(WellKnownServers.LetsEncryptV2, accountKey);
        await ctx.NewAccount(email, true);
        _logger.LogInformation("ACME account ready");

        var order = await ctx.NewOrder(new[] { wildcardDomain });
        _logger.LogInformation("Order created for {Domain}", wildcardDomain);

        var authorizations = await order.Authorizations();
        foreach (var auth in authorizations)
        {
            var dnsChallenge = await auth.Dns();
            var txtValue = accountKey.DnsTxt(dnsChallenge.Token);
            var authDomain = wildcardDomain.TrimStart('*', '.');

            _logger.LogInformation("DNS challenge: _acme-challenge.{Domain} TXT = {Value}", domain, txtValue);

            await addDnsRecord(txtValue);

            try
            {
                var challengeResult = await dnsChallenge.Validate();
                var retries = 0;
                while ((challengeResult.Status == ChallengeStatus.Pending ||
                        challengeResult.Status == ChallengeStatus.Processing) && retries < 30)
                {
                    await Task.Delay(3000);
                    challengeResult = await dnsChallenge.Resource();
                    retries++;
                }

                if (challengeResult.Status != ChallengeStatus.Valid)
                {
                    _logger.LogError("DNS challenge validation failed: {Status}, {Error}",
                        challengeResult.Status, challengeResult.Error?.Detail);
                    throw new Exception($"DNS challenge validation failed: {challengeResult.Status}");
                }

                _logger.LogInformation("DNS challenge validated successfully");
            }
            finally
            {
                await deleteDnsRecord();
            }
        }

        var certKey = KeyFactory.NewKey(KeyAlgorithm.RS256);
        var csrInfo = new CsrInfo { CommonName = wildcardDomain };
        var certChain = await order.Generate(csrInfo, certKey);
        _logger.LogInformation("Certificate finalized for {Domain}", wildcardDomain);

        var fullchainPem = certChain.ToPem(certKey);
        var privkeyPem = ((IEncodable)certKey).ToPem();

        return (fullchainPem, privkeyPem);
    }
}
