namespace CertManager.Shared.Models;

public class ClientConfig
{
    public string ServerUrl { get; set; } = "http://127.0.0.1:15555";
    public string Key { get; set; } = "";
    public string Salt { get; set; } = "";
    public string NginxPath { get; set; } = "";
    public string NginxReloadCmd { get; set; } = "nginx -s reload";
    public List<DomainCertConfig> Domains { get; set; } = [];
}

public class DomainCertConfig
{
    public string Name { get; set; } = "";
    public string FullchainPath { get; set; } = "";
    public string PrivkeyPath { get; set; } = "";
}
