namespace CertManager.Shared.Models;

public class ServerConfig
{
    public string Ver { get; set; } = "1";
    public int Port { get; set; } = 15555;
    public string LetsEncryptEmail { get; set; } = "admin@example.com";
    public string CertDir { get; set; } = "./certs";
    public int CertCheckIntervalHours { get; set; } = 48;
    public int CertRenewDays { get; set; } = 10;
    public List<ClientAuthConfig> Clients { get; set; } = [];
    public List<CertProviderConfig> Certs { get; set; } = [];
}

public class ClientAuthConfig
{
    public string Name { get; set; } = "";
    public string Key { get; set; } = "";
    public string Salt { get; set; } = "";
    public List<string> Privilege { get; set; } = [];
}

public class CertProviderConfig
{
    public string DnsName { get; set; } = "";
    public string DnsProvider { get; set; } = "";
    public string KeyId { get; set; } = "";
    public string KeySecret { get; set; } = "";
    public List<string> Domains { get; set; } = [];
}
