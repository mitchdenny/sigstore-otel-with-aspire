#:sdk Aspire.AppHost.Sdk@13.5.2
#:project ./src/Sigstore.Aspire.Hosting/Sigstore.Aspire.Hosting.csproj
#:property AspireUseCliBundle=false
#:property NoWarn=$(NoWarn);ASPIRE010;ASPIRECERTIFICATES001

using Aspire.Hosting;
using System.Diagnostics;

var builder = DistributedApplication.CreateBuilder(args);

var appHostDirectory = Path.GetFullPath(
    builder.AppHostDirectory);
var sigstoreStatePath = Path.GetFullPath(
    Path.Combine(
        appHostDirectory,
        SigstoreOptions.StateDirectoryName));
var shadyBlobStoreStatePath = Path.GetFullPath(
    Path.Combine(
        appHostDirectory,
        ".shady-blob-store"));
ResetRunScopedState(
    appHostDirectory,
    sigstoreStatePath,
    shadyBlobStoreStatePath);
// Materialize bind-mount sources before Docker Desktop resolves the model.
// The tracked resource below repeats validation so failures remain visible.
EnsureSigstoreState(
    appHostDirectory,
    sigstoreStatePath);

var sigstore = builder.AddSigstore(
    "sigstore",
    new SigstoreOptions
    {
        SourcePath = Path.Combine(appHostDirectory, "src")
    });

var shadyBlobStore = builder
    .AddDockerfile(
        "shady-blob-store",
        "./src/ShadyBlobStore")
    .WithBindMount(
        shadyBlobStoreStatePath,
        "/var/lib/shady-blob-store")
    .WithEnvironment(
        "ASPNETCORE_URLS",
        "http://+:8080")
    .WithEnvironment(
        "SHADY_BLOB_STORE_DATA_PATH",
        "/var/lib/shady-blob-store")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc);

shadyBlobStore
    .WithEnvironment(
        "SHADY_BLOB_STORE_BASE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork));

shadyBlobStore.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Shady artifact store");

var dotnetClient = builder
    .AddDockerfile(
        "dotnet-client",
        "./src/dotnet-client")
    .WithEnvironment(
        "ASPNETCORE_URLS",
        "http://+:8080")
    .WithEnvironment("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    .WithEnvironment("SIGSTORE_TUF_CACHE_PATH", "/tmp/sigstore-tuf-cache")
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WithSigstoreReference(
        sigstore,
        new SigstoreClientOptions
        {
            AddCanonicalHostMappings = false,
            IncludeDirectServiceEndpointVariables = true
        });

dotnetClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = ".NET producer and validator");

var goClient = builder
    .AddDockerfile("go-client", "./src/go-client")
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment("GO_CLIENT_PORT", "8080")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WithSigstoreReference(
        sigstore,
        new SigstoreClientOptions
        {
            TufMount = SigstoreTufMountKind.RepositoryDirectory
        });

goClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Go producer and validator");

var pythonClient = builder
    .AddDockerfile("python-client", "./src/python-client")
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment("PYTHON_CLIENT_PORT", "8080")
    .WithEnvironment("OTEL_TRACES_EXPORTER", "otlp")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "otlp")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "otlp")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WithSigstoreReference(sigstore);

pythonClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Python producer and validator");

var javascriptClient = builder
    .AddDockerfile(
        "javascript-client",
        "./src/javascript-client")
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment(
        "JAVASCRIPT_CLIENT_PORT",
        "8080")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WithSigstoreReference(sigstore);

javascriptClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText =
        "JavaScript producer and validator");

var javaClient = builder
    .AddDockerfile("java-client", "./src/java-client")
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment("JAVA_CLIENT_PORT", "8080")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WithSigstoreReference(sigstore);

javaClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Java producer and validator");

var rustClient = builder
    .AddDockerfile("rust-client", "./src/rust-client")
    .WithEnvironment(
        "SHADY_BLOB_STORE_URL",
        shadyBlobStore.GetEndpoint(
            "http",
            KnownNetworkIdentifiers.DefaultAspireContainerNetwork))
    .WithEnvironment("RUST_CLIENT_PORT", "8080")
    .WithEnvironment("OTEL_METRICS_EXPORTER", "none")
    .WithEnvironment("OTEL_LOGS_EXPORTER", "none")
    .WithEnvironment(
        "OTEL_EXPORTER_OTLP_CERTIFICATE",
        "/usr/lib/ssl/aspire/cert.pem")
    .WithHttpEndpoint(
        targetPort: 8080,
        name: "http")
    .WithHttpHealthCheck(
        "/healthz",
        endpointName: "http")
    .WithExternalHttpEndpoints()
    .WithOtlpExporter(OtlpProtocol.Grpc)
    .WaitFor(shadyBlobStore)
    .WithSigstoreReference(sigstore);

rustClient.WithUrlForEndpoint(
    "http",
    url => url.DisplayText = "Rust producer and validator");

builder.Build().Run();

static void ResetRunScopedState(
    string appHostDirectory,
    string sigstoreStatePath,
    string shadyBlobStoreStatePath)
{
    var stateDirectories = new[]
    {
        (Description: "Sigstore", Path: sigstoreStatePath),
        (Description: "shady blob store", Path: shadyBlobStoreStatePath)
    };

    foreach (var stateDirectory in stateDirectories)
    {
        ValidateStateDirectory(
            appHostDirectory,
            stateDirectory.Path,
            stateDirectory.Description);
    }

    if (PathsOverlap(
            sigstoreStatePath,
            shadyBlobStoreStatePath))
    {
        throw new InvalidOperationException(
            "The Sigstore and shady blob store state directories must not " +
            "overlap.");
    }

    foreach (var stateDirectory in stateDirectories)
    {
        DeleteDirectoryTree(
            stateDirectory.Path,
            stateDirectory.Description);
        Directory.CreateDirectory(stateDirectory.Path);
    }

    Console.WriteLine(
        "Reset run-scoped Sigstore trust and artifact state.");
}

static void ValidateStateDirectory(
    string appHostDirectory,
    string statePath,
    string description)
{
    var normalizedAppHostDirectory =
        Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(appHostDirectory));
    var normalizedStatePath =
        Path.TrimEndingDirectorySeparator(
            Path.GetFullPath(
                statePath,
                normalizedAppHostDirectory));
    var fileSystemRoot = Path.GetPathRoot(normalizedStatePath);

    if (string.IsNullOrWhiteSpace(fileSystemRoot)
        || PathsEqual(
            normalizedStatePath,
            Path.TrimEndingDirectorySeparator(fileSystemRoot)))
    {
        throw new InvalidOperationException(
            $"Refusing to reset the {description} state at filesystem root " +
            $"'{normalizedStatePath}'.");
    }

    var relativePath = Path.GetRelativePath(
        normalizedAppHostDirectory,
        normalizedStatePath);
    if (relativePath == "."
        || Path.IsPathFullyQualified(relativePath)
        || relativePath == ".."
        || relativePath.StartsWith(
            $"..{Path.DirectorySeparatorChar}",
            GetPathComparison())
        || relativePath.StartsWith(
            $"..{Path.AltDirectorySeparatorChar}",
            GetPathComparison()))
    {
        throw new InvalidOperationException(
            $"The {description} state directory '{normalizedStatePath}' " +
            $"must be a descendant of the AppHost directory " +
            $"'{normalizedAppHostDirectory}'.");
    }

    EnsurePathSegmentsAreDirectories(
        normalizedAppHostDirectory,
        relativePath,
        description);
    ValidateDirectoryTree(
        normalizedStatePath,
        description);
}

static void EnsurePathSegmentsAreDirectories(
    string appHostDirectory,
    string relativePath,
    string description)
{
    ValidateExistingDirectory(
        appHostDirectory,
        "AppHost");

    var currentPath = appHostDirectory;
    foreach (var segment in relativePath.Split(
        [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
        StringSplitOptions.RemoveEmptyEntries))
    {
        currentPath = Path.Combine(
            currentPath,
            segment);
        var attributes = GetExistingAttributes(currentPath);
        if (attributes is null)
        {
            break;
        }
        if (attributes.Value.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException(
                $"Refusing to reset the {description} state because " +
                $"'{currentPath}' is a symbolic link or reparse point.");
        }
        if (!attributes.Value.HasFlag(FileAttributes.Directory))
        {
            throw new InvalidOperationException(
                $"Refusing to reset the {description} state because " +
                $"'{currentPath}' is not a directory.");
        }
    }
}

static void ValidateExistingDirectory(
    string path,
    string description)
{
    var attributes = GetExistingAttributes(path)
        ?? throw new DirectoryNotFoundException(
            $"{description} directory '{path}' does not exist.");
    if (attributes.HasFlag(FileAttributes.ReparsePoint))
    {
        throw new InvalidOperationException(
            $"{description} directory '{path}' must not be a symbolic link " +
            "or reparse point.");
    }
    if (!attributes.HasFlag(FileAttributes.Directory))
    {
        throw new InvalidOperationException(
            $"{description} path '{path}' is not a directory.");
    }
}

static void ValidateDirectoryTree(
    string path,
    string description)
{
    var attributes = GetExistingAttributes(path);
    if (attributes is null)
    {
        return;
    }
    if (attributes.Value.HasFlag(FileAttributes.ReparsePoint))
    {
        throw new InvalidOperationException(
            $"Refusing to reset the {description} state because '{path}' " +
            "is a symbolic link or reparse point.");
    }
    if (!attributes.Value.HasFlag(FileAttributes.Directory))
    {
        throw new InvalidOperationException(
            $"Refusing to reset the {description} state because '{path}' " +
            "is not a directory.");
    }

    foreach (var entry in Directory.EnumerateFileSystemEntries(path))
    {
        var entryAttributes = GetExistingAttributes(entry)
            ?? throw new IOException(
                $"State entry '{entry}' disappeared during validation.");
        if (entryAttributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException(
                $"Refusing to reset the {description} state because " +
                $"'{entry}' is a symbolic link or reparse point.");
        }
        if (entryAttributes.HasFlag(FileAttributes.Directory))
        {
            ValidateDirectoryTree(
                entry,
                description);
        }
    }
}

static void DeleteDirectoryTree(
    string path,
    string description)
{
    var attributes = GetExistingAttributes(path);
    if (attributes is null)
    {
        return;
    }
    if (attributes.Value.HasFlag(FileAttributes.ReparsePoint)
        || !attributes.Value.HasFlag(FileAttributes.Directory))
    {
        throw new InvalidOperationException(
            $"The validated {description} state path '{path}' changed before " +
            "it could be reset.");
    }

    foreach (var entry in Directory.EnumerateFileSystemEntries(path))
    {
        var entryAttributes = GetExistingAttributes(entry)
            ?? throw new IOException(
                $"State entry '{entry}' disappeared during reset.");
        if (entryAttributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidOperationException(
                $"State entry '{entry}' became a symbolic link or reparse " +
                "point during reset.");
        }
        if (entryAttributes.HasFlag(FileAttributes.Directory))
        {
            DeleteDirectoryTree(
                entry,
                description);
        }
        else
        {
            File.Delete(entry);
        }
    }

    Directory.Delete(path);
}

static FileAttributes? GetExistingAttributes(string path)
{
    var directory = new DirectoryInfo(path);
    if (directory.Exists || directory.LinkTarget is not null)
    {
        return directory.Attributes;
    }

    var file = new FileInfo(path);
    if (file.Exists || file.LinkTarget is not null)
    {
        return file.Attributes;
    }

    return null;
}

static bool PathsOverlap(
    string firstPath,
    string secondPath)
{
    var relativeFromFirst = Path.GetRelativePath(
        firstPath,
        secondPath);
    var relativeFromSecond = Path.GetRelativePath(
        secondPath,
        firstPath);
    return relativeFromFirst == "."
        || IsDescendantRelativePath(relativeFromFirst)
        || IsDescendantRelativePath(relativeFromSecond);
}

static bool IsDescendantRelativePath(string relativePath) =>
    !Path.IsPathFullyQualified(relativePath)
    && relativePath != ".."
    && !relativePath.StartsWith(
        $"..{Path.DirectorySeparatorChar}",
        GetPathComparison())
    && !relativePath.StartsWith(
        $"..{Path.AltDirectorySeparatorChar}",
        GetPathComparison());

static bool PathsEqual(
    string firstPath,
    string secondPath) =>
    string.Equals(
        firstPath,
        secondPath,
        GetPathComparison());

static StringComparison GetPathComparison() =>
    OperatingSystem.IsWindows()
        || OperatingSystem.IsMacOS()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

static void EnsureSigstoreState(
    string appHostDirectory,
    string statePath)
{
    var startInfo = new ProcessStartInfo
    {
        FileName = "dotnet",
        WorkingDirectory = appHostDirectory,
        UseShellExecute = false
    };
    startInfo.ArgumentList.Add("run");
    startInfo.ArgumentList.Add("--project");
    startInfo.ArgumentList.Add(
        "./src/Sigstore.Bootstrap/Sigstore.Bootstrap.csproj");
    startInfo.ArgumentList.Add("--configuration");
    startInfo.ArgumentList.Add("Debug");
    startInfo.ArgumentList.Add("--no-launch-profile");
    startInfo.Environment["SIGSTORE_STATE_PATH"] = statePath;

    using var process = Process.Start(startInfo)
        ?? throw new InvalidOperationException(
            "Unable to start the Sigstore bootstrapper.");
    process.WaitForExit();

    if (process.ExitCode != 0)
    {
        throw new InvalidOperationException(
            $"The Sigstore bootstrapper exited with code " +
            $"{process.ExitCode}.");
    }
}
