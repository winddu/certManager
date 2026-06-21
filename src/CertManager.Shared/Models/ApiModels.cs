namespace CertManager.Shared.Models;

public class AuthRequest
{
    public string Key { get; set; } = "";
    public string Timestamp { get; set; } = "";
    public string Sign { get; set; } = "";
}

public class CertDownloadRequest
{
    public string Key { get; set; } = "";
    public string Timestamp { get; set; } = "";
    public string Sign { get; set; } = "";
    public List<string> Domains { get; set; } = [];
}

public class CertFileInfo
{
    public string Domain { get; set; } = "";
    public string FullchainPem { get; set; } = "";
    public string PrivkeyPem { get; set; } = "";
    public DateTime NotAfter { get; set; }
}

public class ApiResponse
{
    public int Code { get; set; } = 0;
    public string Message { get; set; } = "ok";
    public List<CertFileInfo>? Data { get; set; }
}
