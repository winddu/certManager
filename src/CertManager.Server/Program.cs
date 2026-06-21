using System.Diagnostics;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Text.Json;
using CertManager.Server.Api;
using CertManager.Server.Logging;
using CertManager.Server.Services;
using CertManager.Shared.Models;

namespace CertManager.Server;

public class Program
{
    private const string ServiceName = "CertManagerServer";
    private static readonly string LogDir = Path.Combine(AppContext.BaseDirectory, "logs");
    private static readonly string ConfigPath = Path.Combine(AppContext.BaseDirectory, "conf.json");

    public static async Task Main(string[] args)
    {
        if (args.Length > 0)
        {
            switch (args[0].ToLower())
            {
                case "--install":
                case "-i":
                    InstallService();
                    return;
                case "--uninstall":
                case "-u":
                    UninstallService();
                    return;
                case "--run":
                case "-r":
                    break;
                default:
                    Console.WriteLine($"Usage: {Process.GetCurrentProcess().ProcessName} [--install|--uninstall|--run]");
                    return;
            }
        }

        if (!Environment.UserInteractive)
        {
            if (!TryLoadConfig(out var config, out _))
                Environment.Exit(1);
            await RunServiceAsync(config!);
            return;
        }

        if (!TryLoadConfig(out var cfg, out var generated))
        {
            if (generated)
            {
                Console.WriteLine("配置文件已自动创建，请修改配置后再运行程序。");
                Console.Write("按任意键退出...");
                Console.ReadKey(true);
            }
            return;
        }

        await RunServiceAsync(cfg!);
    }

    private static bool TryLoadConfig(out ServerConfig? config, out bool generated)
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
            config = JsonSerializer.Deserialize(json, CertManagerJsonContext.Default.ServerConfig);
            if (config == null || string.IsNullOrEmpty(config.LetsEncryptEmail) || config.Clients == null || config.Certs == null)
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
        var example = new ServerConfig
        {
            Ver = "1",
            Port = 15555,
            LetsEncryptEmail = "your-email@example.com",
            CertDir = "./certs",
            CertCheckIntervalHours = 48,
            CertRenewDays = 10,
            Clients =
            [
                new()
                {
                    Name = "client1",
                    Key = "your-client-key",
                    Salt = "your-client-salt",
                    Privilege = ["example.com"]
                }
            ],
            Certs =
            [
                new()
                {
                    DnsName = "阿里云账号",
                    DnsProvider = "阿里云",
                    KeyId = "your-aliyun-key-id",
                    KeySecret = "your-aliyun-key-secret",
                    Domains = ["example.com"]
                }
            ]
        };

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true, TypeInfoResolver = CertManagerJsonContext.Default };
        var json = JsonSerializer.Serialize(example, jsonOptions);
        File.WriteAllText(ConfigPath, json);
        Console.Error.WriteLine($"示例配置文件已创建: {ConfigPath}");
    }

    private static async Task RunServiceAsync(ServerConfig serverConfig)
    {
        serverConfig.CertDir = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, serverConfig.CertDir));

        var builder = WebApplication.CreateBuilder(Array.Empty<string>());

        builder.Host.UseWindowsService(options => options.ServiceName = ServiceName);

        builder.Logging.ClearProviders();
        builder.Logging.AddDailyFileLogger(LogDir);
        builder.Logging.AddConsole();

        builder.WebHost.UseUrls($"http://0.0.0.0:{serverConfig.Port}");

        builder.Services.AddSingleton(serverConfig);
        builder.Services.AddSingleton<AuthService>();
        builder.Services.AddSingleton<AcmeService>();
        builder.Services.AddSingleton<DnsProviderService>();
        builder.Services.AddHostedService<CertRenewWorker>();

        var app = builder.Build();

        CertApi.Map(app);

        await app.RunAsync();
    }

    private static void InstallService()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.Error.WriteLine("Service installation is only supported on Windows");
            return;
        }

        var exePath = Process.GetCurrentProcess().MainModule?.FileName;
        if (string.IsNullOrEmpty(exePath))
        {
            Console.Error.WriteLine("Failed to get executable path");
            return;
        }

        Console.WriteLine($"Installing Windows service '{ServiceName}'...");
        var psi = new ProcessStartInfo
        {
            FileName = "sc",
            Arguments = $"create {ServiceName} binPath=\"{exePath}\" start=auto DisplayName=\"CertManager Server\"",
            Verb = "runas",
            UseShellExecute = true
        };
        var process = Process.Start(psi);
        process?.WaitForExit();

        psi = new ProcessStartInfo
        {
            FileName = "sc",
            Arguments = $"start {ServiceName}",
            Verb = "runas",
            UseShellExecute = true
        };
        process = Process.Start(psi);
        process?.WaitForExit();

        Console.WriteLine("Service installed and started successfully.");
    }

    private static void UninstallService()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Console.Error.WriteLine("Service uninstallation is only supported on Windows");
            return;
        }

        Console.WriteLine($"Uninstalling Windows service '{ServiceName}'...");

        var psi = new ProcessStartInfo
        {
            FileName = "sc",
            Arguments = $"stop {ServiceName}",
            Verb = "runas",
            UseShellExecute = true
        };
        var process = Process.Start(psi);
        process?.WaitForExit();

        psi = new ProcessStartInfo
        {
            FileName = "sc",
            Arguments = $"delete {ServiceName}",
            Verb = "runas",
            UseShellExecute = true
        };
        process = Process.Start(psi);
        process?.WaitForExit();

        Console.WriteLine("Service uninstalled successfully.");
    }
}
