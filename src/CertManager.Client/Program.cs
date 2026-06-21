using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using CertManager.Client.Services;
using CertManager.Shared.Models;
using Microsoft.Extensions.Logging;

namespace CertManager.Client;

public class Program
{
    private const string TaskName = "CertManagerClient";
    private static readonly string LogDir = Path.Combine(AppContext.BaseDirectory, "logs");
    private static readonly string ConfigPath = Path.Combine(AppContext.BaseDirectory, "conf.json");

    public static async Task Main(string[] args)
    {
        if (!TryLoadConfig(out var config, out var generated))
        {
            if (generated)
            {
                Console.WriteLine("配置文件已自动创建，请修改配置后再运行程序。");
                Console.Write("按任意键退出...");
                Console.ReadKey(true);
            }
            return;
        }

        SetupLogging();
        var logger = new Logger();
        logger.Info("CertManager Client v1.0 started");

        if (!IsScheduledTaskInstalled())
        {
            logger.Info("Scheduled task not installed. Installing...");
            InstallScheduledTask(logger);
            return;
        }

        var domainsToRenew = new List<DomainCertConfig>();
        foreach (var domain in config!.Domains)
        {
            if (ShouldRenew(domain, logger))
                domainsToRenew.Add(domain);
        }

        if (domainsToRenew.Count == 0)
        {
            logger.Info("All certificates are valid, no renewal needed");
            return;
        }

        logger.Info($"Certificates to renew: {string.Join(", ", domainsToRenew.Select(d => d.Name))}");

        var certService = new CertDownloadService(new LoggerAdapter<CertDownloadService>(logger));
        var success = await certService.DownloadCertificatesAsync(config);

        if (!success)
        {
            logger.Error("Failed to download certificates");
            return;
        }

        var nginxService = new NginxService(new LoggerAdapter<NginxService>(logger));
        await nginxService.ReloadAsync(config.NginxPath, config.NginxReloadCmd);

        logger.Info("Certificate renewal completed successfully");
    }

    private static bool TryLoadConfig(out ClientConfig? config, out bool generated)
    {
        config = null;
        generated = false;

        if (!File.Exists(ConfigPath))
        {
            Console.Error.WriteLine("配置文件不存在，正在生成示例配置...");
            GenerateExampleConfig();
            generated = true;
            return false;
        }

        string json;
        try
        {
            json = File.ReadAllText(ConfigPath);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"读取配置文件失败: {ex.Message}");
            Console.Error.WriteLine("正在生成示例配置...");
            GenerateExampleConfig();
            generated = true;
            return false;
        }

        try
        {
            config = JsonSerializer.Deserialize(json, CertManagerJsonContext.Default.ClientConfig);
            if (config == null || string.IsNullOrEmpty(config.ServerUrl) || string.IsNullOrEmpty(config.Key) || config.Domains == null || config.Domains.Count == 0)
                throw new Exception("配置缺少必要字段");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"配置文件格式错误: {ex.Message}");
            Console.Error.WriteLine("正在生成示例配置...");
            GenerateExampleConfig();
            generated = true;
            return false;
        }

        return true;
    }

    private static void GenerateExampleConfig()
    {
        var example = new ClientConfig
        {
            ServerUrl = "http://127.0.0.1:15555",
            Key = "your-client-key",
            Salt = "your-client-salt",
            NginxPath = "",
            NginxReloadCmd = "nginx -s reload",
            Domains =
            [
                new()
                {
                    Name = "example.com",
                    FullchainPath = "C:/nginx/ssl/example.com/fullchain.pem",
                    PrivkeyPath = "C:/nginx/ssl/example.com/privkey.pem"
                }
            ]
        };

        var options = new JsonSerializerOptions { WriteIndented = true, TypeInfoResolver = CertManagerJsonContext.Default };
        var json = JsonSerializer.Serialize(example, options);
        File.WriteAllText(ConfigPath, json);
        Console.Error.WriteLine($"示例配置文件已创建: {ConfigPath}");
    }

    private static bool ShouldRenew(DomainCertConfig domain, Logger logger)
    {
        if (!File.Exists(domain.FullchainPath))
        {
            logger.Info($"Certificate file not found for {domain.Name}, will download");
            return true;
        }

        try
        {
            var pem = File.ReadAllText(domain.FullchainPath);
            var cert = X509Certificate2.CreateFromPem(pem);
            var daysLeft = (cert.NotAfter - DateTime.UtcNow).TotalDays;

            logger.Info($"Certificate {domain.Name} expires in {daysLeft:F1} days");

            if (daysLeft <= 5)
            {
                logger.Info($"Certificate {domain.Name} expires in {daysLeft:F1} days, will renew");
                return true;
            }

            return false;
        }
        catch (Exception ex)
        {
            logger.Warning($"Failed to parse certificate for {domain.Name}: {ex.Message}");
            return true;
        }
    }

    private static bool IsScheduledTaskInstalled()
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "schtasks",
                Arguments = $"/query /tn \"{TaskName}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            using var process = Process.Start(psi);
            if (process == null) return false;
            if (process.WaitForExit(3000) && process.ExitCode == 0)
                return true;
            try { process.Kill(); } catch { }
        }
        catch { }

        // 文件检测兜底
        try
        {
            var sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var taskFile = Path.Combine(sysRoot, "Tasks", TaskName);
            return File.Exists(taskFile);
        }
        catch { return false; }
    }

    private static void InstallScheduledTask(Logger logger)
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
        {
            logger.Error("Failed to get executable path");
            return;
        }

        var random = new Random();
        var hour = random.Next(1, 4);
        var minute = random.Next(0, 59);
        var timeStr = $"{hour:D2}:{minute:D2}";

        var psi = new ProcessStartInfo
        {
            FileName = "schtasks",
            Arguments = $"/create /tn \"{TaskName}\" /tr \"{exePath}\" /sc daily /st {timeStr} /f",
            Verb = "runas",
            UseShellExecute = true
        };

        var process = Process.Start(psi);
        process?.WaitForExit();

        if (process?.ExitCode == 0)
        {
            logger.Info($"Scheduled task '{TaskName}' created successfully, will run daily at {timeStr}");
        }
        else
        {
            logger.Error($"Failed to create scheduled task (exit code: {process?.ExitCode})");
        }
    }

    private static void SetupLogging()
    {
        var now = DateTime.Now;
        var logDir = Path.Combine(LogDir, now.ToString("yyyy"), now.ToString("MM"));
        Directory.CreateDirectory(logDir);
        Logger.LogFilePath = Path.Combine(logDir, $"certmanager_{now:yyyyMMdd}.log");
    }

    private class Logger
    {
        public static string? LogFilePath { get; set; }

        public void Info(string msg) => Write("INFO", msg);
        public void Warning(string msg) => Write("WARN", msg);
        public void Error(string msg) => Write("ERROR", msg);

        private void Write(string level, string msg)
        {
            var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {msg}";
            Console.WriteLine(line);
            if (LogFilePath != null)
                File.AppendAllText(LogFilePath, line + Environment.NewLine, Encoding.UTF8);
        }
    }

    private class LoggerAdapter<T> : ILogger<T>
    {
        private readonly Logger _logger;

        public LoggerAdapter(Logger logger) => _logger = logger;

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var msg = formatter(state, exception);
            if (exception != null)
                msg = $"{msg}{Environment.NewLine}{exception}";

            switch (logLevel)
            {
                case LogLevel.Error: _logger.Error(msg); break;
                case LogLevel.Warning: _logger.Warning(msg); break;
                default: _logger.Info(msg); break;
            }
        }
    }
}
