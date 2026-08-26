using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Sigstore.Bootstrap;

internal static class SigstoreStateBootstrapper
{
    private const int CurrentSchemaVersion = 4;
    private const string TimestampingEkuOid = "1.3.6.1.5.5.7.3.8";
    private const string LockFileName = ".bootstrap.lock";
    private const string ManifestFileName = "bootstrap-manifest.json";
    private const string FulcioPrivateKeyPath = "private/fulcio/root.key";
    private const string FulcioPrivateKeyPasswordPath =
        "private/fulcio/password";
    private const string FulcioRootCertificatePath = "public/fulcio/root.pem";
    private const string CtLogPrivateKeyPath = "private/ctlog/privkey.pem";
    private const string CtLogPublicKeyPath = "public/ctlog/pubkey.pem";
    private const string RekorPrivateKeyPath = "private/rekor/signer.key";
    private const string RekorPublicKeyPath = "public/rekor/signer.pub";
    private const string OidcPrivateKeyPath = "private/oidc/signer.key";
    private const string OidcPublicKeyPath = "public/oidc/signer.pub";
    private const string OidcJwksPath = "public/oidc/jwks.json";
    private const string TsaRootPrivateKeyPath = "private/tsa/root.key";
    private const string TsaSignerPrivateKeyPath = "private/tsa/signer.key";
    private const string TsaPrivateKeyPasswordPath = "private/tsa/password";
    private const string TsaRootCertificatePath = "public/tsa/root.pem";
    private const string TsaLeafCertificatePath = "public/tsa/leaf.pem";
    private const string TsaCertificateChainPath =
        "public/tsa/cert-chain.pem";
    private const string CtLogStateMarkerPath =
        "data/ctlog/bootstrap-state";
    private const string RekorStateMarkerPath =
        "data/rekor/bootstrap-state";

    private static readonly string[] RequiredStateFiles =
    [
        ManifestFileName,
        FulcioPrivateKeyPath,
        FulcioPrivateKeyPasswordPath,
        FulcioRootCertificatePath,
        CtLogPrivateKeyPath,
        CtLogPublicKeyPath,
        RekorPrivateKeyPath,
        RekorPublicKeyPath,
        OidcPrivateKeyPath,
        OidcPublicKeyPath,
        OidcJwksPath,
        TsaRootPrivateKeyPath,
        TsaSignerPrivateKeyPath,
        TsaPrivateKeyPasswordPath,
        TsaRootCertificatePath,
        TsaLeafCertificatePath,
        TsaCertificateChainPath,
        CtLogStateMarkerPath,
        RekorStateMarkerPath
    ];

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };

    public static BootstrapResult EnsureInitialized(string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);

        var rootPath = Path.GetFullPath(statePath);
        Directory.CreateDirectory(rootPath);

        var lockFilePath = Path.Combine(rootPath, LockFileName);
        using var lockFile = AcquireLock(lockFilePath);

        var manifestPath = Resolve(rootPath, ManifestFileName);
        if (File.Exists(manifestPath))
        {
            return new BootstrapResult(
                Created: false,
                ValidateState(rootPath));
        }

        var unexpectedEntries = Directory
            .EnumerateFiles(
                rootPath,
                "*",
                SearchOption.AllDirectories)
            .Where(path => !string.Equals(
                path,
                lockFilePath,
                StringComparison.Ordinal))
            .ToArray();

        if (unexpectedEntries.Length > 0)
        {
            throw new InvalidDataException(
                $"Sigstore state at '{rootPath}' is incomplete. " +
                $"Delete the directory to create a new trust domain.");
        }

        GenerateState(rootPath);

        return new BootstrapResult(
            Created: true,
            ValidateState(rootPath));
    }

    private static void GenerateState(string rootPath)
    {
        var ctLogStateId = InitializeCtLogState(rootPath);
        var rekorStateId = InitializeRuntimeState(
            rootPath,
            RekorStateMarkerPath);
        GenerateFulcioRoot(rootPath);
        GenerateEcdsaKeyPair(
            rootPath,
            CtLogPrivateKeyPath,
            CtLogPublicKeyPath);
        GenerateEcdsaKeyPair(
            rootPath,
            RekorPrivateKeyPath,
            RekorPublicKeyPath);
        GenerateOidcKeyPair(rootPath);
        GenerateTimestampAuthority(rootPath);
        var tsa = ValidateTimestampAuthority(rootPath);

        var manifest = new BootstrapManifest(
            CurrentSchemaVersion,
            DateTimeOffset.UtcNow,
            ctLogStateId,
            rekorStateId,
            ValidateFulcioRoot(rootPath),
            ValidateEcdsaKeyPair(
                rootPath,
                CtLogPrivateKeyPath,
                CtLogPublicKeyPath),
            ValidateEcdsaKeyPair(
                rootPath,
                RekorPrivateKeyPath,
                RekorPublicKeyPath),
            tsa.RootSha256,
            tsa.LeafSha256,
            ValidateOidcKeyPair(rootPath));

        var temporaryManifestPath = Resolve(
            rootPath,
            $".{ManifestFileName}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        WriteFile(
            temporaryManifestPath,
            JsonSerializer.Serialize(manifest, JsonOptions) + "\n",
            isPrivate: false);
        File.Move(
            temporaryManifestPath,
            Resolve(rootPath, ManifestFileName));
    }

    private static string InitializeCtLogState(string rootPath)
        => InitializeRuntimeState(
            rootPath,
            CtLogStateMarkerPath);

    private static string InitializeRuntimeState(
        string rootPath,
        string markerPath)
    {
        var stateId = Guid.NewGuid().ToString("D");
        WriteFile(
            Resolve(rootPath, markerPath),
            stateId,
            isPrivate: false);
        return stateId;
    }

    private static void GenerateFulcioRoot(string rootPath)
    {
        using var privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var password = Base64UrlEncode(
            RandomNumberGenerator.GetBytes(32));
        var request = new CertificateRequest(
            new X500DistinguishedName(
                "CN=Fulcio Root, O=Sigstore Aspire Demo"),
            privateKey,
            HashAlgorithmName.SHA256);

        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature
                | X509KeyUsageFlags.KeyCertSign
                | X509KeyUsageFlags.CrlSign,
                critical: true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                request.PublicKey,
                critical: false));

        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(
            now.AddMinutes(-5),
            now.AddYears(10));

        WriteFile(
            Resolve(rootPath, FulcioPrivateKeyPath),
            privateKey.ExportEncryptedPkcs8PrivateKeyPem(
                password,
                new PbeParameters(
                    PbeEncryptionAlgorithm.Aes256Cbc,
                    HashAlgorithmName.SHA256,
                    iterationCount: 100_000)),
            isPrivate: true);
        WriteFile(
            Resolve(rootPath, FulcioPrivateKeyPasswordPath),
            password,
            isPrivate: true);
        WriteFile(
            Resolve(rootPath, FulcioRootCertificatePath),
            certificate.ExportCertificatePem(),
            isPrivate: false);
    }

    private static void GenerateEcdsaKeyPair(
        string rootPath,
        string privateKeyPath,
        string publicKeyPath)
    {
        using var privateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        WriteFile(
            Resolve(rootPath, privateKeyPath),
            privateKey.ExportECPrivateKeyPem(),
            isPrivate: true);
        WriteFile(
            Resolve(rootPath, publicKeyPath),
            privateKey.ExportSubjectPublicKeyInfoPem(),
            isPrivate: false);
    }

    private static void GenerateOidcKeyPair(string rootPath)
    {
        using var privateKey = RSA.Create(2048);
        var publicKeyBytes = privateKey.ExportSubjectPublicKeyInfo();
        var parameters = privateKey.ExportParameters(
            includePrivateParameters: false);
        var keyId = Base64UrlEncode(SHA256.HashData(publicKeyBytes));
        var jwks = new
        {
            keys = new[]
            {
                new
                {
                    kty = "RSA",
                    use = "sig",
                    kid = keyId,
                    alg = "RS256",
                    n = Base64UrlEncode(parameters.Modulus!),
                    e = Base64UrlEncode(parameters.Exponent!)
                }
            }
        };

        WriteFile(
            Resolve(rootPath, OidcPrivateKeyPath),
            privateKey.ExportPkcs8PrivateKeyPem(),
            isPrivate: true);
        WriteFile(
            Resolve(rootPath, OidcPublicKeyPath),
            privateKey.ExportSubjectPublicKeyInfoPem(),
            isPrivate: false);
        WriteFile(
            Resolve(rootPath, OidcJwksPath),
            JsonSerializer.Serialize(jwks, JsonOptions) + "\n",
            isPrivate: false);
    }

    private static void GenerateTimestampAuthority(string rootPath)
    {
        using var rootKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signerKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var password = Base64UrlEncode(
            RandomNumberGenerator.GetBytes(32));
        var now = DateTimeOffset.UtcNow;

        var rootRequest = new CertificateRequest(
            new X500DistinguishedName(
                "CN=Timestamp Authority Root, O=Sigstore Aspire Demo"),
            rootKey,
            HashAlgorithmName.SHA256);
        rootRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
        rootRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign
                | X509KeyUsageFlags.CrlSign,
                critical: true));
        rootRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                rootRequest.PublicKey,
                critical: false));

        using var rootCertificate = rootRequest.CreateSelfSigned(
            now.AddMinutes(-5),
            now.AddYears(10));

        var leafRequest = new CertificateRequest(
            new X500DistinguishedName(
                "CN=Timestamp Authority, O=Sigstore Aspire Demo"),
            signerKey,
            HashAlgorithmName.SHA256);
        leafRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: false,
                hasPathLengthConstraint: false,
                pathLengthConstraint: 0,
                critical: true));
        leafRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature,
                critical: true));
        var timestampingEkus = new OidCollection
        {
            new Oid(TimestampingEkuOid)
        };
        leafRequest.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                timestampingEkus,
                critical: true));
        leafRequest.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(
                leafRequest.PublicKey,
                critical: false));

        using var leafCertificate = leafRequest.Create(
            rootCertificate,
            now.AddMinutes(-5),
            now.AddYears(9),
            CreateSerialNumber());

        var rootPem = rootCertificate.ExportCertificatePem();
        var leafPem = leafCertificate.ExportCertificatePem();

        WriteFile(
            Resolve(rootPath, TsaRootPrivateKeyPath),
            rootKey.ExportEncryptedPkcs8PrivateKeyPem(
                password,
                CreatePrivateKeyEncryptionParameters()),
            isPrivate: true);
        WriteFile(
            Resolve(rootPath, TsaSignerPrivateKeyPath),
            signerKey.ExportEncryptedPkcs8PrivateKeyPem(
                password,
                CreatePrivateKeyEncryptionParameters()),
            isPrivate: true);
        WriteFile(
            Resolve(rootPath, TsaPrivateKeyPasswordPath),
            password,
            isPrivate: true);
        WriteFile(
            Resolve(rootPath, TsaRootCertificatePath),
            rootPem,
            isPrivate: false);
        WriteFile(
            Resolve(rootPath, TsaLeafCertificatePath),
            leafPem,
            isPrivate: false);
        WriteFile(
            Resolve(rootPath, TsaCertificateChainPath),
            $"{leafPem.TrimEnd()}\n{rootPem.TrimEnd()}\n",
            isPrivate: false);
    }

    private static BootstrapManifest ValidateState(string rootPath)
    {
        foreach (var relativePath in RequiredStateFiles)
        {
            var path = Resolve(rootPath, relativePath);
            if (!File.Exists(path))
            {
                throw new InvalidDataException(
                    $"Sigstore state at '{rootPath}' is missing " +
                    $"'{relativePath}'. Delete the directory to create a " +
                    $"new trust domain.");
            }
        }

        var manifestPath = Resolve(rootPath, ManifestFileName);
        var manifest = JsonSerializer.Deserialize<BootstrapManifest>(
            File.ReadAllText(manifestPath),
            JsonOptions)
            ?? throw new InvalidDataException(
                $"Manifest '{manifestPath}' is empty.");

        if (manifest.SchemaVersion != CurrentSchemaVersion)
        {
            throw new InvalidDataException(
                $"Sigstore state schema {manifest.SchemaVersion} is not " +
                $"supported; expected {CurrentSchemaVersion}.");
        }

        EnsureEqual(
            "CT log state ID",
            manifest.CtLogStateId,
            File.ReadAllText(
                Resolve(rootPath, CtLogStateMarkerPath)));
        EnsureEqual(
            "Rekor state ID",
            manifest.RekorStateId,
            File.ReadAllText(
                Resolve(rootPath, RekorStateMarkerPath)));
        ValidateCtLogRuntimeState(rootPath);
        ValidateRuntimeState(
            rootPath,
            "Rekor",
            "data/rekor");
        EnsureEqual(
            "Fulcio root certificate",
            manifest.FulcioRootSha256,
            ValidateFulcioRoot(rootPath));
        EnsureEqual(
            "CT log public key",
            manifest.CtLogPublicKeySha256,
            ValidateEcdsaKeyPair(
                rootPath,
                CtLogPrivateKeyPath,
                CtLogPublicKeyPath));
        EnsureEqual(
            "Rekor public key",
            manifest.RekorPublicKeySha256,
            ValidateEcdsaKeyPair(
                rootPath,
                RekorPrivateKeyPath,
                RekorPublicKeyPath));
        var tsa = ValidateTimestampAuthority(rootPath);
        EnsureEqual(
            "TSA root certificate",
            manifest.TsaRootSha256,
            tsa.RootSha256);
        EnsureEqual(
            "TSA leaf certificate",
            manifest.TsaLeafSha256,
            tsa.LeafSha256);
        EnsureEqual(
            "OIDC key ID",
            manifest.OidcKeyId,
            ValidateOidcKeyPair(rootPath));

        return manifest;
    }

    private static (string RootSha256, string LeafSha256)
        ValidateTimestampAuthority(string rootPath)
    {
        using var rootKey = LoadEncryptedEcdsaKey(
            Resolve(rootPath, TsaRootPrivateKeyPath),
            Resolve(rootPath, TsaPrivateKeyPasswordPath));
        using var signerKey = LoadEncryptedEcdsaKey(
            Resolve(rootPath, TsaSignerPrivateKeyPath),
            Resolve(rootPath, TsaPrivateKeyPasswordPath));
        using var rootCertificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Resolve(rootPath, TsaRootCertificatePath)));
        using var leafCertificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Resolve(rootPath, TsaLeafCertificatePath)));

        EnsureCertificateMatchesKey(
            "TSA root certificate",
            rootCertificate,
            rootKey);
        EnsureCertificateMatchesKey(
            "TSA leaf certificate",
            leafCertificate,
            signerKey);

        var rootConstraints = rootCertificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault();
        if (rootConstraints is null
            || !rootConstraints.CertificateAuthority)
        {
            throw new InvalidDataException(
                "The TSA root is not a certificate authority.");
        }

        var leafConstraints = leafCertificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault();
        if (leafConstraints is null
            || leafConstraints.CertificateAuthority)
        {
            throw new InvalidDataException(
                "The TSA leaf must be an end-entity certificate.");
        }

        var enhancedKeyUsage = leafCertificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .SingleOrDefault();
        if (enhancedKeyUsage is null
            || !enhancedKeyUsage.Critical
            || enhancedKeyUsage.EnhancedKeyUsages.Count != 1
            || enhancedKeyUsage.EnhancedKeyUsages[0].Value
                != TimestampingEkuOid)
        {
            throw new InvalidDataException(
                "The TSA leaf must contain only a critical timestamping EKU.");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode =
            X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(rootCertificate);
        chain.ChainPolicy.RevocationMode =
            X509RevocationMode.NoCheck;
        chain.ChainPolicy.ApplicationPolicy.Add(
            new Oid(TimestampingEkuOid));
        if (!chain.Build(leafCertificate))
        {
            var failures = string.Join(
                ", ",
                chain.ChainStatus.Select(
                    status => status.StatusInformation.Trim()));
            throw new InvalidDataException(
                $"The TSA certificate chain is invalid: {failures}");
        }

        var chainCertificates = new X509Certificate2Collection();
        chainCertificates.ImportFromPem(
            File.ReadAllText(
                Resolve(rootPath, TsaCertificateChainPath)));
        if (chainCertificates.Count != 2
            || !chainCertificates[0].RawData.SequenceEqual(
                leafCertificate.RawData)
            || !chainCertificates[1].RawData.SequenceEqual(
                rootCertificate.RawData))
        {
            throw new InvalidDataException(
                "The TSA certificate chain must contain leaf then root.");
        }

        return (
            Fingerprint(rootCertificate.RawData),
            Fingerprint(leafCertificate.RawData));
    }

    private static void ValidateCtLogRuntimeState(string rootPath)
        => ValidateRuntimeState(
            rootPath,
            "CT log",
            "data/ctlog");

    private static void ValidateRuntimeState(
        string rootPath,
        string displayName,
        string relativePath)
    {
        var checkpointExists = File.Exists(
            Resolve(rootPath, $"{relativePath}/checkpoint"));
        var storageVersionExists = File.Exists(
            Resolve(rootPath, $"{relativePath}/.state/version"));

        if (checkpointExists != storageVersionExists)
        {
            throw new InvalidDataException(
                $"{displayName} state at '{Resolve(rootPath, relativePath)}' " +
                "is incomplete. Delete the entire Sigstore state directory " +
                "to create a new trust domain.");
        }
    }

    private static string ValidateFulcioRoot(string rootPath)
    {
        using var privateKey = LoadEncryptedEcdsaKey(
            Resolve(rootPath, FulcioPrivateKeyPath),
            Resolve(rootPath, FulcioPrivateKeyPasswordPath));
        using var certificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Resolve(rootPath, FulcioRootCertificatePath)));
        using var certificatePublicKey =
            certificate.GetECDsaPublicKey()
            ?? throw new InvalidDataException(
                "The Fulcio root certificate does not contain an ECDSA key.");

        EnsureKeyBytesEqual(
            "Fulcio root certificate and private key",
            privateKey.ExportSubjectPublicKeyInfo(),
            certificatePublicKey.ExportSubjectPublicKeyInfo());

        var basicConstraints = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault();
        if (basicConstraints is null
            || !basicConstraints.CertificateAuthority)
        {
            throw new InvalidDataException(
                "The Fulcio root certificate is not a certificate authority.");
        }

        var now = DateTimeOffset.UtcNow;
        if (now < certificate.NotBefore
            || now > certificate.NotAfter)
        {
            throw new InvalidDataException(
                "The Fulcio root certificate is not currently valid.");
        }

        return Fingerprint(certificate.RawData);
    }

    private static string ValidateEcdsaKeyPair(
        string rootPath,
        string privateKeyPath,
        string publicKeyPath)
    {
        using var privateKey = LoadEcdsaKey(
            Resolve(rootPath, privateKeyPath));
        using var publicKey = LoadEcdsaKey(
            Resolve(rootPath, publicKeyPath));
        var publicKeyBytes = publicKey.ExportSubjectPublicKeyInfo();

        EnsureKeyBytesEqual(
            publicKeyPath,
            privateKey.ExportSubjectPublicKeyInfo(),
            publicKeyBytes);

        return Fingerprint(publicKeyBytes);
    }

    private static string ValidateOidcKeyPair(string rootPath)
    {
        using var privateKey = LoadRsaKey(
            Resolve(rootPath, OidcPrivateKeyPath));
        using var publicKey = LoadRsaKey(
            Resolve(rootPath, OidcPublicKeyPath));
        var publicKeyBytes = publicKey.ExportSubjectPublicKeyInfo();

        EnsureKeyBytesEqual(
            "OIDC public and private keys",
            privateKey.ExportSubjectPublicKeyInfo(),
            publicKeyBytes);

        var parameters = publicKey.ExportParameters(
            includePrivateParameters: false);
        var expectedKeyId = Base64UrlEncode(
            SHA256.HashData(publicKeyBytes));

        using var document = JsonDocument.Parse(
            File.ReadAllText(Resolve(rootPath, OidcJwksPath)));
        var keys = document.RootElement
            .GetProperty("keys")
            .EnumerateArray()
            .ToArray();

        if (keys.Length != 1)
        {
            throw new InvalidDataException(
                "The OIDC JWKS must contain exactly one key.");
        }

        var key = keys[0];
        EnsureEqual("OIDC key type", "RSA", key.GetProperty("kty").GetString());
        EnsureEqual("OIDC key use", "sig", key.GetProperty("use").GetString());
        EnsureEqual("OIDC algorithm", "RS256", key.GetProperty("alg").GetString());
        EnsureEqual("OIDC key ID", expectedKeyId, key.GetProperty("kid").GetString());
        EnsureEqual(
            "OIDC modulus",
            Base64UrlEncode(parameters.Modulus!),
            key.GetProperty("n").GetString());
        EnsureEqual(
            "OIDC exponent",
            Base64UrlEncode(parameters.Exponent!),
            key.GetProperty("e").GetString());

        return expectedKeyId;
    }

    private static ECDsa LoadEcdsaKey(string path)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(path));
        return key;
    }

    private static byte[] CreateSerialNumber()
    {
        var serialNumber = RandomNumberGenerator.GetBytes(16);
        serialNumber[0] &= 0x7f;
        if (serialNumber.All(value => value == 0))
        {
            serialNumber[^1] = 1;
        }
        return serialNumber;
    }

    private static PbeParameters CreatePrivateKeyEncryptionParameters() =>
        new(
            PbeEncryptionAlgorithm.Aes256Cbc,
            HashAlgorithmName.SHA256,
            iterationCount: 100_000);

    private static void EnsureCertificateMatchesKey(
        string description,
        X509Certificate2 certificate,
        ECDsa privateKey)
    {
        using var certificatePublicKey =
            certificate.GetECDsaPublicKey()
            ?? throw new InvalidDataException(
                $"{description} does not contain an ECDSA key.");

        EnsureKeyBytesEqual(
            description,
            privateKey.ExportSubjectPublicKeyInfo(),
            certificatePublicKey.ExportSubjectPublicKeyInfo());
    }

    private static ECDsa LoadEncryptedEcdsaKey(
        string path,
        string passwordPath)
    {
        var key = ECDsa.Create();
        key.ImportFromEncryptedPem(
            File.ReadAllText(path),
            File.ReadAllText(passwordPath));
        return key;
    }

    private static FileStream AcquireLock(string path)
    {
        var timeout = TimeSpan.FromSeconds(30);
        var stopwatch = Stopwatch.StartNew();

        while (true)
        {
            try
            {
                return new FileStream(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None);
            }
            catch (IOException) when (stopwatch.Elapsed < timeout)
            {
                Thread.Sleep(TimeSpan.FromMilliseconds(100));
            }
            catch (IOException exception)
            {
                throw new InvalidOperationException(
                    $"Another bootstrapper is using Sigstore state at " +
                    $"'{Path.GetDirectoryName(path)}'.",
                    exception);
            }
        }
    }

    private static RSA LoadRsaKey(string path)
    {
        var key = RSA.Create();
        key.ImportFromPem(File.ReadAllText(path));
        return key;
    }

    private static void EnsureKeyBytesEqual(
        string description,
        byte[] expected,
        byte[] actual)
    {
        if (!CryptographicOperations.FixedTimeEquals(expected, actual))
        {
            throw new InvalidDataException(
                $"{description} do not match.");
        }
    }

    private static void EnsureEqual(
        string description,
        string expected,
        string? actual)
    {
        if (!string.Equals(
            expected,
            actual,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"{description} does not match the bootstrap manifest.");
        }
    }

    private static void WriteFile(
        string path,
        string contents,
        bool isPrivate)
    {
        Directory.CreateDirectory(
            Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException(
                $"Unable to determine the directory for '{path}'."));

        using (var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None))
        using (var writer = new StreamWriter(
            stream,
            new UTF8Encoding(encoderShouldEmitUTF8Identifier: false)))
        {
            writer.Write(contents);
        }

        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                isPrivate
                    ? UnixFileMode.UserRead
                        | UnixFileMode.UserWrite
                    : UnixFileMode.UserRead
                        | UnixFileMode.UserWrite
                        | UnixFileMode.GroupRead
                        | UnixFileMode.OtherRead);
        }
    }

    private static string Resolve(
        string rootPath,
        string relativePath) =>
        Path.Combine(
            rootPath,
            relativePath.Replace(
                '/',
                Path.DirectorySeparatorChar));

    private static string Fingerprint(byte[] bytes) =>
        Convert.ToHexString(SHA256.HashData(bytes))
            .ToLowerInvariant();

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
