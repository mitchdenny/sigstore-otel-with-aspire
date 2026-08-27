using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Sigstore.Bootstrap;

internal sealed class StateFileLock : IDisposable
{
    public const string FileName = "state.lock";

    private const int LockExclusive = 2;
    private const int LockNonBlocking = 4;
    private const int LockUnlock = 8;

    private readonly FileStream _stream;
    private readonly bool _usesFlock;
    private bool _disposed;

    private StateFileLock(
        FileStream stream,
        bool usesFlock)
    {
        _stream = stream;
        _usesFlock = usesFlock;
    }

    public static StateFileLock Acquire(
        string statePath,
        TimeSpan timeout,
        string operation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);
        if (timeout < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(timeout),
                "The state lock timeout must not be negative.");
        }

        Directory.CreateDirectory(statePath);
        var path = Path.Combine(statePath, FileName);
        var stopwatch = Stopwatch.StartNew();

        while (true)
        {
            FileStream? stream = null;
            try
            {
                stream = new FileStream(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    OperatingSystem.IsWindows()
                        ? FileShare.None
                        : FileShare.ReadWrite);
                var usesFlock = !OperatingSystem.IsWindows();
                if (usesFlock
                    && Flock(
                        stream.SafeFileHandle.DangerousGetHandle().ToInt32(),
                        LockExclusive | LockNonBlocking) != 0)
                {
                    throw new IOException(
                        "The shared Sigstore state lock is held.",
                        new Win32Exception(
                            Marshal.GetLastPInvokeError()));
                }
                WriteOwner(stream, operation);
                return new StateFileLock(
                    stream,
                    usesFlock);
            }
            catch (IOException exception)
            {
                stream?.Dispose();
                if (stopwatch.Elapsed >= timeout)
                {
                    var owner = ReadOwner(path);
                    throw new InvalidOperationException(
                        $"Sigstore state at '{statePath}' is locked by another " +
                        $"operation{owner}. The operating-system lock is " +
                        "released automatically if its owner exits.",
                        exception);
                }

                Thread.Sleep(TimeSpan.FromMilliseconds(50));
            }
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            if (_usesFlock
                && Flock(
                    _stream.SafeFileHandle.DangerousGetHandle().ToInt32(),
                    LockUnlock) != 0)
            {
                throw new IOException(
                    "Unable to release the shared Sigstore state lock.",
                    new Win32Exception(
                        Marshal.GetLastPInvokeError()));
            }
        }
        finally
        {
            _stream.Dispose();
        }
        _disposed = true;
    }

    private static void WriteOwner(
        FileStream stream,
        string operation)
    {
        var owner = new
        {
            schemaVersion = 1,
            processId = Environment.ProcessId,
            operation,
            acquiredAtUtc = DateTimeOffset.UtcNow
        };
        var contents = JsonSerializer.Serialize(owner)
            + "\n";
        var bytes = Encoding.UTF8.GetBytes(contents);

        stream.Position = 0;
        stream.SetLength(0);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    private static string ReadOwner(string path)
    {
        try
        {
            var contents = File.ReadAllText(path).Trim();
            return contents.Length == 0
                ? string.Empty
                : $" (last owner metadata: {contents})";
        }
        catch (IOException)
        {
            return string.Empty;
        }
        catch (UnauthorizedAccessException)
        {
            return string.Empty;
        }
    }

    [DllImport(
        "libc",
        EntryPoint = "flock",
        SetLastError = true)]
    private static extern int Flock(
        int fileDescriptor,
        int operation);
}
