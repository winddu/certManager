using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace CertManager.Client.Services;

public class NginxService
{
    private readonly ILogger<NginxService> _logger;

    public NginxService(ILogger<NginxService> logger)
    {
        _logger = logger;
    }

    public async Task<bool> ReloadAsync(string nginxPath, string reloadCmd)
    {
        if (string.IsNullOrEmpty(nginxPath))
        {
            var detected = DetectNginxPath();
            if (string.IsNullOrEmpty(detected))
            {
                _logger.LogError("Nginx not found. Please set NginxPath in conf.json or start nginx first.");
                return false;
            }
            nginxPath = detected;
            _logger.LogInformation("Auto-detected nginx path: {Path}", nginxPath);
        }

        var nginxExe = Path.Combine(nginxPath, "nginx.exe");
        if (!File.Exists(nginxExe))
        {
            _logger.LogError("Nginx executable not found: {Path}", nginxExe);
            return false;
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = nginxExe,
                Arguments = "-s reload",
                WorkingDirectory = nginxPath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };

            using var process = Process.Start(psi);
            if (process == null)
            {
                _logger.LogError("Failed to start nginx process");
                return false;
            }

            var stdout = await process.StandardOutput.ReadToEndAsync();
            var stderr = await process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            if (process.ExitCode != 0)
            {
                _logger.LogError("Nginx reload failed (exit code: {Code}): {Error}",
                    process.ExitCode, stderr);
                return false;
            }

            if (!string.IsNullOrEmpty(stdout))
                _logger.LogInformation("Nginx reload output: {Output}", stdout);

            _logger.LogInformation("Nginx reloaded successfully");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to reload nginx");
            return false;
        }
    }

    public static string? DetectNginxPath()
    {
        try
        {
            var processes = Process.GetProcessesByName("nginx");
            if (processes.Length == 0) return null;

            foreach (var proc in processes)
            {
                try
                {
                    var path = proc.MainModule?.FileName;
                    if (!string.IsNullOrEmpty(path))
                    {
                        var dir = Path.GetDirectoryName(path);
                        if (dir != null && File.Exists(Path.Combine(dir, "nginx.exe")))
                            return dir;
                    }
                }
                catch { }
                finally
                {
                    proc.Dispose();
                }
            }
        }
        catch { }

        return null;
    }
}
