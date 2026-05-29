using System.Text;

namespace CertManager.Server.Logging;

public class DailyFileLoggerProvider : ILoggerProvider
{
    private readonly string _logDir;
    private readonly string _categoryName;
    private readonly object _lock = new();

    public DailyFileLoggerProvider(string logDir, string categoryName = "CertManager")
    {
        _logDir = logDir;
        _categoryName = categoryName;
        Directory.CreateDirectory(logDir);
    }

    public ILogger CreateLogger(string categoryName) =>
        new DailyFileLogger(_logDir, categoryName);

    public void Dispose() { }

    private class DailyFileLogger : ILogger
    {
        private readonly string _logDir;
        private readonly string _categoryName;
        private static readonly object _lock = new();

        public DailyFileLogger(string logDir, string categoryName)
        {
            _logDir = logDir;
            _categoryName = categoryName;
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (!IsEnabled(logLevel)) return;

            var now = DateTime.Now;
            var logDir = Path.Combine(_logDir, now.ToString("yyyy"), now.ToString("MM"));
            Directory.CreateDirectory(logDir);

            var logFile = Path.Combine(logDir, $"certmanager_{now:yyyyMMdd}.log");
            var message = formatter(state, exception);

            if (exception != null)
                message = $"{message}{Environment.NewLine}{exception}";

            var logLine = $"[{now:yyyy-MM-dd HH:mm:ss}] [{logLevel}] [{_categoryName}] {message}";

            lock (_lock)
            {
                File.AppendAllText(logFile, logLine + Environment.NewLine, Encoding.UTF8);
            }
        }
    }
}

public static class DailyFileLoggerExtensions
{
    public static ILoggingBuilder AddDailyFileLogger(this ILoggingBuilder builder, string logDir)
    {
        builder.AddProvider(new DailyFileLoggerProvider(logDir));
        return builder;
    }
}
