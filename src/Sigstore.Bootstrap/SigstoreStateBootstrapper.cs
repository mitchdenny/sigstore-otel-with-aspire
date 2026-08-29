using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sigstore.Bootstrap;

internal static partial class SigstoreStateBootstrapper
{
    private const int LegacySchemaVersion = 4;
    private const string TimestampingEkuOid = "1.3.6.1.5.5.7.3.8";
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
    private const string RekorSecondaryDataPath =
        "data/rekor-shards/secondary";
    private const string CtLogSecondaryDataPath =
        "data/ctlog-shards/secondary";

    private static readonly string[] LegacyRequiredStateFiles =
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

    private static readonly string[] TimestampRotationCandidateFiles =
    [
        TsaSignerPrivateKeyPath,
        TsaPrivateKeyPasswordPath,
        TsaRootCertificatePath,
        TsaLeafCertificatePath,
        TsaCertificateChainPath
    ];

    private static readonly string[] FulcioRotationCandidateFiles =
    [
        FulcioPrivateKeyPath,
        FulcioPrivateKeyPasswordPath,
        FulcioRootCertificatePath
    ];

    private static readonly string[] RekorRotationCandidateFiles =
    [
        RekorPrivateKeyPath,
        RekorPublicKeyPath
    ];

    private static readonly string[] CtLogRotationCandidateFiles =
    [
        CtLogPrivateKeyPath,
        CtLogPublicKeyPath
    ];

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };

    /// <summary>
    /// Options for reading trust metadata that either the C# bootstrapper or
    /// the Go worker may have written. Unknown members are rejected so
    /// injected fields cannot ride along unnoticed, but no constraint is
    /// placed on property order or on whether absent optional members were
    /// emitted as explicit nulls.
    /// </summary>
    private static readonly JsonSerializerOptions PortableJsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow
        };

    public static BootstrapResult EnsureInitialized(string statePath)
        => EnsureInitialized(
            statePath,
            TrustStateOperationOptions.Default);

    internal static BootstrapResult EnsureInitialized(
        string statePath,
        TrustStateOperationOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentNullException.ThrowIfNull(options);

        var rootPath = Path.GetFullPath(statePath);
        Directory.CreateDirectory(rootPath);

        using var stateLock = StateFileLock.Acquire(
            rootPath,
            options.LockTimeout,
            "bootstrap-or-trust-transition");
        var result = EnsureTrustStateLocked(
            rootPath,
            options);
        Directory.CreateDirectory(
            Resolve(rootPath, RekorSecondaryDataPath));
        Directory.CreateDirectory(
            Resolve(rootPath, CtLogSecondaryDataPath));
        return result;
    }

    internal static BootstrapManifest CreateSchema4StateForMigrationTests(
        string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        var rootPath = Path.GetFullPath(statePath);
        Directory.CreateDirectory(rootPath);
        if (Directory.EnumerateFileSystemEntries(rootPath).Any())
        {
            throw new InvalidOperationException(
                "The schema-4 test state directory must be empty.");
        }

        return GenerateLegacyState(
            rootPath,
            rootPath,
            writeManifest: true);
    }

    private static BootstrapManifest GenerateLegacyState(
        string stateRootPath,
        string materialRootPath,
        bool writeManifest)
    {
        var ctLogStateId = InitializeCtLogState(stateRootPath);
        var rekorStateId = InitializeRuntimeState(
            stateRootPath,
            RekorStateMarkerPath);
        GenerateFulcioRoot(materialRootPath);
        GenerateEcdsaKeyPair(
            materialRootPath,
            CtLogPrivateKeyPath,
            CtLogPublicKeyPath);
        GenerateEcdsaKeyPair(
            materialRootPath,
            RekorPrivateKeyPath,
            RekorPublicKeyPath);
        GenerateOidcKeyPair(materialRootPath);
        GenerateTimestampAuthority(materialRootPath);
        var tsa = ValidateTimestampAuthority(materialRootPath);

        var manifest = new BootstrapManifest(
            LegacySchemaVersion,
            DateTimeOffset.UtcNow,
            ctLogStateId,
            rekorStateId,
            ValidateFulcioRoot(materialRootPath),
            ValidateEcdsaKeyPair(
                materialRootPath,
                CtLogPrivateKeyPath,
                CtLogPublicKeyPath),
            ValidateEcdsaKeyPair(
                materialRootPath,
                RekorPrivateKeyPath,
                RekorPublicKeyPath),
            tsa.RootSha256,
            tsa.LeafSha256,
            ValidateOidcKeyPair(materialRootPath));

        if (writeManifest)
        {
            var temporaryManifestPath = Resolve(
                stateRootPath,
                $".{ManifestFileName}.{Environment.ProcessId}." +
                $"{Guid.NewGuid():N}.tmp");
            WriteFile(
                temporaryManifestPath,
                JsonSerializer.Serialize(manifest, JsonOptions) + "\n",
                isPrivate: false);
            File.Move(
                temporaryManifestPath,
                Resolve(stateRootPath, ManifestFileName));
        }

        return manifest;
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

    internal static TimestampAuthorityMaterialInfo
        EnsureTimestampAuthorityRotationCandidate(string candidatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);
        candidatePath = Path.GetFullPath(candidatePath);
        var parentPath = Directory.GetParent(candidatePath)?.FullName
            ?? throw new InvalidOperationException(
                $"Cannot determine the parent directory for '{candidatePath}'.");
        Directory.CreateDirectory(parentPath);

        if (Directory.Exists(candidatePath))
        {
            ValidateTimestampRotationCandidateFileSet(candidatePath);
            return ValidateTimestampAuthority(candidatePath);
        }
        if (File.Exists(candidatePath))
        {
            throw new InvalidDataException(
                $"TSA rotation candidate '{candidatePath}' is not a directory.");
        }

        var stagingPath = candidatePath + ".staging";
        if (Directory.Exists(stagingPath))
        {
            Directory.Delete(stagingPath, recursive: true);
        }
        else if (File.Exists(stagingPath))
        {
            throw new InvalidDataException(
                $"TSA rotation staging path '{stagingPath}' is not a directory.");
        }

        try
        {
            Directory.CreateDirectory(stagingPath);
            GenerateTimestampAuthority(stagingPath);
            _ = ValidateTimestampAuthority(stagingPath);
            File.Delete(Resolve(stagingPath, TsaRootPrivateKeyPath));
            ValidateTimestampRotationCandidateFileSet(stagingPath);
            _ = ValidateTimestampAuthority(stagingPath);
            Directory.Move(stagingPath, candidatePath);
        }
        catch
        {
            if (Directory.Exists(stagingPath))
            {
                Directory.Delete(stagingPath, recursive: true);
            }
            throw;
        }

        ValidateTimestampRotationCandidateFileSet(candidatePath);
        return ValidateTimestampAuthority(candidatePath);
    }

    /// <summary>
    /// Deterministically materializes the Fulcio certificate-authority
    /// rotation candidate at <paramref name="candidatePath"/>. Generation is
    /// atomic: material is produced in a sibling staging directory, fully
    /// validated, and only then renamed into place, so a crash can never
    /// expose a half-written candidate. An already-present candidate is never
    /// regenerated; it is re-validated and its identity returned, which makes
    /// the operation idempotent and makes tampering a hard failure.
    /// </summary>
    internal static FulcioCaMaterialInfo
        EnsureFulcioCaRotationCandidate(string candidatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);
        candidatePath = Path.GetFullPath(candidatePath);
        var parentPath = Directory.GetParent(candidatePath)?.FullName
            ?? throw new InvalidOperationException(
                $"Cannot determine the parent directory for '{candidatePath}'.");
        Directory.CreateDirectory(parentPath);

        if (Directory.Exists(candidatePath))
        {
            ValidateFulcioRotationCandidateFileSet(candidatePath);
            return ValidateFulcioCertificateAuthority(candidatePath);
        }

        if (File.Exists(candidatePath))
        {
            throw new InvalidDataException(
                $"Fulcio rotation candidate '{candidatePath}' is not a " +
                "directory.");
        }

        var stagingPath = candidatePath + ".staging";
        if (Directory.Exists(stagingPath))
        {
            Directory.Delete(stagingPath, recursive: true);
        }
        else if (File.Exists(stagingPath))
        {
            throw new InvalidDataException(
                $"Fulcio rotation staging path '{stagingPath}' is not a " +
                "directory.");
        }

        try
        {
            Directory.CreateDirectory(stagingPath);
            GenerateFulcioRoot(stagingPath);
            ValidateFulcioRotationCandidateFileSet(stagingPath);
            _ = ValidateFulcioCertificateAuthority(stagingPath);
            Directory.Move(stagingPath, candidatePath);
        }
        catch
        {
            if (Directory.Exists(stagingPath))
            {
                Directory.Delete(stagingPath, recursive: true);
            }
            throw;
        }

        ValidateFulcioRotationCandidateFileSet(candidatePath);
        return ValidateFulcioCertificateAuthority(candidatePath);
    }

    internal static RekorShardMaterialInfo
        EnsureRekorShardRotationCandidate(string candidatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);
        candidatePath = Path.GetFullPath(candidatePath);
        var parentPath = Directory.GetParent(candidatePath)?.FullName
            ?? throw new InvalidOperationException(
                $"Cannot determine the parent directory for '{candidatePath}'.");
        Directory.CreateDirectory(parentPath);

        if (Directory.Exists(candidatePath))
        {
            ValidateRekorRotationCandidateFileSet(candidatePath);
            return ValidateRekorShardMaterial(candidatePath);
        }
        if (File.Exists(candidatePath))
        {
            throw new InvalidDataException(
                $"Rekor rotation candidate '{candidatePath}' is not a directory.");
        }

        var stagingPath = candidatePath + ".staging";
        if (Directory.Exists(stagingPath))
        {
            Directory.Delete(stagingPath, recursive: true);
        }
        else if (File.Exists(stagingPath))
        {
            throw new InvalidDataException(
                $"Rekor rotation staging path '{stagingPath}' is not a directory.");
        }

        try
        {
            Directory.CreateDirectory(stagingPath);
            GenerateEcdsaKeyPair(
                stagingPath,
                RekorPrivateKeyPath,
                RekorPublicKeyPath);
            ValidateRekorRotationCandidateFileSet(stagingPath);
            _ = ValidateRekorShardMaterial(stagingPath);
            Directory.Move(stagingPath, candidatePath);
        }
        catch
        {
            if (Directory.Exists(stagingPath))
            {
                Directory.Delete(stagingPath, recursive: true);
            }
            throw;
        }

        ValidateRekorRotationCandidateFileSet(candidatePath);
        return ValidateRekorShardMaterial(candidatePath);
    }

    internal static RekorShardMaterialInfo StageRekorShardRuntime(
        string statePath,
        string candidatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);
        candidatePath = Path.GetFullPath(candidatePath);
        var expected = ValidateRekorShardMaterial(candidatePath);
        var runtimePath = Path.Combine(
            Path.GetFullPath(statePath),
            "runtime",
            "rekor-secondary");
        if (Directory.Exists(runtimePath))
        {
            var actual = ValidateRekorRuntimeSigner(runtimePath);
            if (actual != expected)
            {
                throw new InvalidDataException(
                    "The staged Rekor secondary signer does not match the " +
                    "immutable rotation candidate.");
            }
            return actual;
        }
        if (File.Exists(runtimePath))
        {
            throw new InvalidDataException(
                $"Rekor runtime path '{runtimePath}' is not a directory.");
        }

        var stagingPath = runtimePath + ".staging";
        if (Directory.Exists(stagingPath))
        {
            Directory.Delete(stagingPath, recursive: true);
        }
        else if (File.Exists(stagingPath))
        {
            throw new InvalidDataException(
                $"Rekor runtime staging path '{stagingPath}' is not a directory.");
        }

        try
        {
            Directory.CreateDirectory(stagingPath);
            WriteFile(
                Path.Combine(stagingPath, "signer.key"),
                File.ReadAllText(
                    Resolve(
                        candidatePath,
                        RekorPrivateKeyPath)),
                isPrivate: true);
            var actual = ValidateRekorRuntimeSigner(stagingPath);
            if (actual != expected)
            {
                throw new InvalidDataException(
                    "The staged Rekor runtime signer changed during copy.");
            }
            Directory.Move(stagingPath, runtimePath);
        }
        catch
        {
            if (Directory.Exists(stagingPath))
            {
                Directory.Delete(stagingPath, recursive: true);
            }
            throw;
        }

        return ValidateRekorRuntimeSigner(runtimePath);
    }

    /// <summary>
    /// Deterministically materializes the certificate-transparency shard
    /// rotation candidate at <paramref name="candidatePath"/>: a fresh,
    /// isolated ECDSA P-256 signer that will belong exclusively to the new
    /// secondary CT shard. Generation is atomic — material is produced in a
    /// sibling staging directory, fully validated, and only then renamed into
    /// place — and an already-present candidate is re-validated rather than
    /// regenerated, which makes the operation idempotent under replay and
    /// makes tampering a hard failure.
    /// </summary>
    internal static CtLogShardMaterialInfo
        EnsureCtLogShardRotationCandidate(string candidatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);
        candidatePath = Path.GetFullPath(candidatePath);
        var parentPath = Directory.GetParent(candidatePath)?.FullName
            ?? throw new InvalidOperationException(
                $"Cannot determine the parent directory for '{candidatePath}'.");
        Directory.CreateDirectory(parentPath);

        if (Directory.Exists(candidatePath))
        {
            ValidateCtLogRotationCandidateFileSet(candidatePath);
            return ValidateCtLogShardMaterial(candidatePath);
        }
        if (File.Exists(candidatePath))
        {
            throw new InvalidDataException(
                $"CT log rotation candidate '{candidatePath}' is not a " +
                "directory.");
        }

        var stagingPath = candidatePath + ".staging";
        if (Directory.Exists(stagingPath))
        {
            Directory.Delete(stagingPath, recursive: true);
        }
        else if (File.Exists(stagingPath))
        {
            throw new InvalidDataException(
                $"CT log rotation staging path '{stagingPath}' is not a " +
                "directory.");
        }

        try
        {
            Directory.CreateDirectory(stagingPath);
            GenerateEcdsaKeyPair(
                stagingPath,
                CtLogPrivateKeyPath,
                CtLogPublicKeyPath);
            ValidateCtLogRotationCandidateFileSet(stagingPath);
            _ = ValidateCtLogShardMaterial(stagingPath);
            Directory.Move(stagingPath, candidatePath);
        }
        catch
        {
            if (Directory.Exists(stagingPath))
            {
                Directory.Delete(stagingPath, recursive: true);
            }
            throw;
        }

        ValidateCtLogRotationCandidateFileSet(candidatePath);
        return ValidateCtLogShardMaterial(candidatePath);
    }

    /// <summary>
    /// Stages the isolated secondary CT shard runtime projection at
    /// <c>runtime/tesseract-secondary</c>: the candidate's private signer
    /// plus a byte-identical copy of the accepted Fulcio root bundle the
    /// historical primary shard already enforces, so the secondary shard
    /// accepts exactly the same complete set of Fulcio certificate
    /// authorities. The projection is written atomically and is never
    /// rewritten once it exists; a mismatched existing projection is a hard
    /// failure rather than being silently repaired.
    /// </summary>
    internal static CtLogShardRuntimeInfo StageCtLogShardRuntime(
        string statePath,
        string candidatePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        ArgumentException.ThrowIfNullOrWhiteSpace(candidatePath);
        candidatePath = Path.GetFullPath(candidatePath);
        var expected = ValidateCtLogShardMaterial(candidatePath);
        var rootPath = Path.GetFullPath(statePath);
        var acceptedRootsPath = Path.Combine(
            rootPath,
            RuntimeDirectoryName,
            RuntimeTesseractComponentName,
            RuntimeAcceptedRootsFileName);
        EnsureRegularFile(
            acceptedRootsPath,
            "accepted Fulcio roots");
        var acceptedRoots = File.ReadAllBytes(acceptedRootsPath);
        var privateKey = File.ReadAllText(
            Resolve(candidatePath, CtLogPrivateKeyPath));
        var runtimePath = Path.Combine(
            rootPath,
            RuntimeDirectoryName,
            RuntimeTesseractSecondaryComponentName);

        if (Directory.Exists(runtimePath))
        {
            var actual = ValidateCtLogRuntimeSigner(runtimePath);
            if (actual != expected)
            {
                throw new InvalidDataException(
                    "The staged secondary CT log signer does not match the " +
                    "immutable rotation candidate.");
            }
            if (!File.ReadAllBytes(
                    Path.Combine(
                        runtimePath,
                        RuntimeAcceptedRootsFileName))
                .SequenceEqual(acceptedRoots))
            {
                throw new InvalidDataException(
                    "The staged secondary CT log accepted-root bundle does " +
                    "not match the primary shard bundle.");
            }
            return DescribeCtLogShardRuntime(runtimePath, actual);
        }
        if (File.Exists(runtimePath))
        {
            throw new InvalidDataException(
                $"CT log runtime path '{runtimePath}' is not a directory.");
        }

        var stagingPath = runtimePath + ".staging";
        if (Directory.Exists(stagingPath))
        {
            Directory.Delete(stagingPath, recursive: true);
        }
        else if (File.Exists(stagingPath))
        {
            throw new InvalidDataException(
                $"CT log runtime staging path '{stagingPath}' is not a " +
                "directory.");
        }

        try
        {
            Directory.CreateDirectory(stagingPath);
            WriteFile(
                Path.Combine(
                    stagingPath,
                    RuntimeTesseractPrivateKeyFileName),
                privateKey,
                isPrivate: true);
            WriteRuntimeFile(
                Path.Combine(
                    stagingPath,
                    RuntimeAcceptedRootsFileName),
                acceptedRoots,
                isPrivate: false);
            var actual = ValidateCtLogRuntimeSigner(stagingPath);
            if (actual != expected)
            {
                throw new InvalidDataException(
                    "The staged secondary CT log signer changed during copy.");
            }
            Directory.Move(stagingPath, runtimePath);
        }
        catch
        {
            if (Directory.Exists(stagingPath))
            {
                Directory.Delete(stagingPath, recursive: true);
            }
            throw;
        }

        return DescribeCtLogShardRuntime(
            runtimePath,
            ValidateCtLogRuntimeSigner(runtimePath));
    }

    /// <summary>
    /// Describes one certificate-transparency shard's least-privilege
    /// runtime projection: its signer identity plus the validated identity
    /// of the complete Fulcio root bundle it accepts. The bundle identity is
    /// both its SHA-256 and its ordered per-root fingerprints, so a shard's
    /// accepted trust can be bound durably in the shard catalog and any
    /// added, removed or reordered root is detectable.
    /// </summary>
    internal static CtLogShardRuntimeInfo DescribeCtLogShardRuntime(
        string runtimePath,
        CtLogShardMaterialInfo signer)
    {
        var bundlePath = Path.Combine(
            runtimePath,
            RuntimeAcceptedRootsFileName);
        var certificates = ReadAcceptedRootsBundle(bundlePath);
        try
        {
            return new CtLogShardRuntimeInfo(
                signer.PublicKeySha256,
                signer.LogId,
                signer.ShardId,
                Fingerprint(File.ReadAllBytes(bundlePath)),
                certificates
                    .Select(certificate => Fingerprint(certificate.RawData))
                    .ToArray());
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    /// <summary>
    /// Validates a certificate-transparency signer material tree — a
    /// generation directory or a rotation candidate — and returns its
    /// identity. The CT log ID is the SHA-256 fingerprint of the signer's
    /// SubjectPublicKeyInfo, exactly the value Tesseract embeds in SCTs and
    /// the Go worker publishes as the TrustedRoot <c>ctlogs</c> log ID.
    /// </summary>
    internal static CtLogShardMaterialInfo ValidateCtLogShardMaterial(
        string rootPath)
    {
        var publicKeySha256 = ValidateEcdsaKeyPair(
            rootPath,
            CtLogPrivateKeyPath,
            CtLogPublicKeyPath);
        return new(
            publicKeySha256,
            publicKeySha256,
            $"sha256-{publicKeySha256}");
    }

    /// <summary>
    /// Validates the secondary CT shard runtime projection
    /// (<c>runtime/tesseract-secondary</c>), which is deliberately
    /// least-privilege: exactly the signer Tesseract needs plus the accepted
    /// Fulcio root bundle, and never the public key or any other generation
    /// material.
    /// </summary>
    internal static CtLogShardMaterialInfo ValidateCtLogRuntimeSigner(
        string runtimePath)
    {
        EnsureOnlyEntries(
            runtimePath,
            RuntimeTesseractFileNames);
        using var privateKey = LoadEcdsaKey(
            Path.Combine(
                runtimePath,
                RuntimeTesseractPrivateKeyFileName));
        if (privateKey.KeySize != 256)
        {
            throw new InvalidDataException(
                "The CT log shard signer must use ECDSA P-256.");
        }
        var publicKeySha256 = Fingerprint(
            privateKey.ExportSubjectPublicKeyInfo());
        return new(
            publicKeySha256,
            publicKeySha256,
            $"sha256-{publicKeySha256}");
    }

    private static void ValidateCtLogRotationCandidateFileSet(
        string rootPath)
    {
        var actual = Directory.EnumerateFiles(
                rootPath,
                "*",
                SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(rootPath, path)
                .Replace(Path.DirectorySeparatorChar, '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!actual.SequenceEqual(
                CtLogRotationCandidateFiles.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The CT log rotation candidate has an unexpected file set.");
        }
    }

    /// <summary>
    /// Validates a Fulcio certificate-authority material tree — a generation
    /// directory or a rotation candidate — against the exact profile this
    /// bootstrapper produces: an encrypted ECDSA P-256 private key whose
    /// password decrypts it, a self-signed ECDSA-SHA256 root carrying a
    /// critical CA basic-constraints extension without a path-length
    /// constraint, exactly the critical
    /// DigitalSignature|KeyCertSign|CrlSign key usage, a subject key
    /// identifier, and a currently valid validity window.
    /// </summary>
    internal static FulcioCaMaterialInfo
        ValidateFulcioCertificateAuthority(string rootPath)
        => ValidateFulcioCertificateAuthority(
            Resolve(rootPath, FulcioPrivateKeyPath),
            Resolve(rootPath, FulcioPrivateKeyPasswordPath),
            Resolve(rootPath, FulcioRootCertificatePath));

    /// <summary>
    /// Path-explicit overload used for the flat component-scoped runtime
    /// projection, where the same three artifacts live side by side rather
    /// than under the generation's private/public trees.
    /// </summary>
    internal static FulcioCaMaterialInfo
        ValidateFulcioCertificateAuthority(
            string privateKeyPath,
            string passwordPath,
            string certificatePath)
    {
        using var privateKey = LoadEncryptedEcdsaKey(
            privateKeyPath,
            passwordPath);
        using var certificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(certificatePath));
        using var certificatePublicKey =
            certificate.GetECDsaPublicKey()
            ?? throw new InvalidDataException(
                "The Fulcio root certificate does not contain an ECDSA key.");

        var publicKeyBytes = certificatePublicKey.ExportSubjectPublicKeyInfo();
        EnsureKeyBytesEqual(
            "Fulcio root certificate and private key",
            privateKey.ExportSubjectPublicKeyInfo(),
            publicKeyBytes);

        if (certificatePublicKey.KeySize != 256
            || certificate.SignatureAlgorithm.Value
                != "1.2.840.10045.4.3.2")
        {
            throw new InvalidDataException(
                "The Fulcio root must use ECDSA P-256 with SHA-256.");
        }

        var basicConstraints = certificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault();
        if (basicConstraints is null
            || !basicConstraints.Critical
            || !basicConstraints.CertificateAuthority
            || basicConstraints.HasPathLengthConstraint)
        {
            throw new InvalidDataException(
                "The Fulcio root certificate must carry critical certificate " +
                "authority basic constraints without a path-length " +
                "constraint.");
        }

        var keyUsage = certificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .SingleOrDefault();
        if (keyUsage is null
            || !keyUsage.Critical
            || keyUsage.KeyUsages
                != (X509KeyUsageFlags.DigitalSignature
                    | X509KeyUsageFlags.KeyCertSign
                    | X509KeyUsageFlags.CrlSign))
        {
            throw new InvalidDataException(
                "The Fulcio root certificate has invalid key usage.");
        }

        if (!certificate.Extensions
            .OfType<X509SubjectKeyIdentifierExtension>()
            .Any())
        {
            throw new InvalidDataException(
                "The Fulcio root certificate is missing a subject key " +
                "identifier.");
        }

        if (!certificate.SubjectName.RawData.SequenceEqual(
                certificate.IssuerName.RawData))
        {
            throw new InvalidDataException(
                "The Fulcio root certificate is not self-issued.");
        }

        var now = DateTimeOffset.UtcNow;
        if (now < certificate.NotBefore
            || now >= certificate.NotAfter)
        {
            throw new InvalidDataException(
                "The Fulcio root certificate is not currently valid.");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(certificate);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        if (!chain.Build(certificate))
        {
            var failures = string.Join(
                ", ",
                chain.ChainStatus.Select(
                    status => status.StatusInformation.Trim()));
            throw new InvalidDataException(
                $"The Fulcio root certificate is not validly self-signed: " +
                $"{failures}");
        }

        return new FulcioCaMaterialInfo(
            Fingerprint(certificate.RawData),
            Fingerprint(publicKeyBytes),
            certificate.Subject,
            certificate.NotBefore.ToUniversalTime(),
            certificate.NotAfter.ToUniversalTime());
    }

    private static void ValidateFulcioRotationCandidateFileSet(
        string rootPath)
    {
        var actual = Directory.EnumerateFiles(
                rootPath,
                "*",
                SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(rootPath, path)
                .Replace(Path.DirectorySeparatorChar, '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!actual.SequenceEqual(
                FulcioRotationCandidateFiles.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The Fulcio rotation candidate has an unexpected file set.");
        }
    }

    private static void ValidateRekorRotationCandidateFileSet(
        string rootPath)
    {
        var actual = Directory.EnumerateFiles(
                rootPath,
                "*",
                SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(rootPath, path)
                .Replace(Path.DirectorySeparatorChar, '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!actual.SequenceEqual(
                RekorRotationCandidateFiles.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The Rekor rotation candidate has an unexpected file set.");
        }
    }

    internal static RekorShardMaterialInfo ValidateRekorShardMaterial(
        string rootPath)
    {
        var publicKeySha256 = ValidateEcdsaKeyPair(
            rootPath,
            RekorPrivateKeyPath,
            RekorPublicKeyPath);
        return new(
            publicKeySha256,
            publicKeySha256,
            $"sha256-{publicKeySha256}");
    }

    internal static RekorShardMaterialInfo ValidateRekorRuntimeSigner(
        string runtimePath)
    {
        EnsureOnlyEntries(runtimePath, ["signer.key"]);
        using var privateKey = LoadEcdsaKey(
            Path.Combine(runtimePath, "signer.key"));
        if (privateKey.KeySize != 256)
        {
            throw new InvalidDataException(
                "The Rekor shard signer must use ECDSA P-256.");
        }
        var publicKeySha256 = Fingerprint(
            privateKey.ExportSubjectPublicKeyInfo());
        return new(
            publicKeySha256,
            publicKeySha256,
            $"sha256-{publicKeySha256}");
    }

    private static BootstrapManifest ValidateLegacyState(string rootPath)
    {
        foreach (var relativePath in LegacyRequiredStateFiles)
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

        if (manifest.SchemaVersion != LegacySchemaVersion)
        {
            throw new InvalidDataException(
                $"Sigstore state schema {manifest.SchemaVersion} is not " +
                $"supported for migration; expected {LegacySchemaVersion}.");
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

    internal static TimestampAuthorityMaterialInfo
        ValidateTimestampAuthority(string rootPath)
    {
        var rootKeyPath = Resolve(rootPath, TsaRootPrivateKeyPath);
        using var rootKey = File.Exists(rootKeyPath)
            ? LoadEncryptedEcdsaKey(
                rootKeyPath,
                Resolve(rootPath, TsaPrivateKeyPasswordPath))
            : null;
        using var signerKey = LoadEncryptedEcdsaKey(
            Resolve(rootPath, TsaSignerPrivateKeyPath),
            Resolve(rootPath, TsaPrivateKeyPasswordPath));
        using var rootCertificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Resolve(rootPath, TsaRootCertificatePath)));
        using var leafCertificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Resolve(rootPath, TsaLeafCertificatePath)));

        if (rootKey is not null)
        {
            EnsureCertificateMatchesKey(
                "TSA root certificate",
                rootCertificate,
                rootKey);
        }
        EnsureCertificateMatchesKey(
            "TSA leaf certificate",
            leafCertificate,
            signerKey);
        using var rootPublicKey = rootCertificate.GetECDsaPublicKey()
            ?? throw new InvalidDataException(
                "The TSA root certificate does not contain an ECDSA key.");
        using var leafPublicKey = leafCertificate.GetECDsaPublicKey()
            ?? throw new InvalidDataException(
                "The TSA leaf certificate does not contain an ECDSA key.");
        if (rootPublicKey.KeySize != 256
            || leafPublicKey.KeySize != 256
            || rootCertificate.SignatureAlgorithm.Value
                != "1.2.840.10045.4.3.2"
            || leafCertificate.SignatureAlgorithm.Value
                != "1.2.840.10045.4.3.2")
        {
            throw new InvalidDataException(
                "The TSA chain must use ECDSA P-256 with SHA-256.");
        }

        var rootConstraints = rootCertificate.Extensions
            .OfType<X509BasicConstraintsExtension>()
            .SingleOrDefault();
        if (rootConstraints is null
            || !rootConstraints.CertificateAuthority)
        {
            throw new InvalidDataException(
                "The TSA root is not a certificate authority.");
        }
        var rootKeyUsage = rootCertificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .SingleOrDefault();
        if (rootKeyUsage is null
            || !rootKeyUsage.Critical
            || rootKeyUsage.KeyUsages
                != (X509KeyUsageFlags.KeyCertSign
                    | X509KeyUsageFlags.CrlSign))
        {
            throw new InvalidDataException(
                "The TSA root has invalid key usage.");
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
        var leafKeyUsage = leafCertificate.Extensions
            .OfType<X509KeyUsageExtension>()
            .SingleOrDefault();
        if (leafKeyUsage is null
            || !leafKeyUsage.Critical
            || leafKeyUsage.KeyUsages
                != X509KeyUsageFlags.DigitalSignature)
        {
            throw new InvalidDataException(
                "The TSA leaf has invalid key usage.");
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
        var now = DateTimeOffset.UtcNow;
        if (now < rootCertificate.NotBefore
            || now >= rootCertificate.NotAfter
            || now < leafCertificate.NotBefore
            || now >= leafCertificate.NotAfter)
        {
            throw new InvalidDataException(
                "The TSA certificate chain is not currently valid.");
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

        var notBefore = new[]
        {
            rootCertificate.NotBefore.ToUniversalTime(),
            leafCertificate.NotBefore.ToUniversalTime()
        }.Max();
        var notAfter = new[]
        {
            rootCertificate.NotAfter.ToUniversalTime(),
            leafCertificate.NotAfter.ToUniversalTime()
        }.Min();
        return new TimestampAuthorityMaterialInfo(
            Fingerprint(rootCertificate.RawData),
            Fingerprint(leafCertificate.RawData),
            Fingerprint(signerKey.ExportSubjectPublicKeyInfo()),
            Fingerprint(
                File.ReadAllBytes(
                    Resolve(rootPath, TsaCertificateChainPath))),
            rootKey is not null,
            notBefore,
            notAfter);
    }

    private static void ValidateTimestampRotationCandidateFileSet(
        string rootPath)
    {
        var actual = Directory.EnumerateFiles(
                rootPath,
                "*",
                SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(rootPath, path)
                .Replace(Path.DirectorySeparatorChar, '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();
        if (!actual.SequenceEqual(
                TimestampRotationCandidateFiles.Order(StringComparer.Ordinal),
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "The TSA rotation candidate has an unexpected file set.");
        }
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
        => ValidateFulcioCertificateAuthority(rootPath).RootSha256;

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

    internal static string ValidateOidcKeyPair(string rootPath)
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

        if (keys.Length < 1)
        {
            throw new InvalidDataException(
                "The OIDC JWKS must contain at least one key.");
        }

        var matchingKey = keys.FirstOrDefault(k =>
            k.TryGetProperty("kid", out var kid) && kid.GetString() == expectedKeyId);
        if (matchingKey.ValueKind == JsonValueKind.Undefined)
        {
            throw new InvalidDataException(
                $"The OIDC JWKS does not contain the active key ID '{expectedKeyId}'.");
        }

        var key = matchingKey;
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
        try
        {
            var key = ECDsa.Create();
            key.ImportFromPem(File.ReadAllText(path));
            return key;
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                $"ECDSA key '{path}' is invalid.",
                exception);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"ECDSA key '{path}' is invalid.",
                exception);
        }
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
        try
        {
            var key = ECDsa.Create();
            key.ImportFromEncryptedPem(
                File.ReadAllText(path),
                File.ReadAllText(passwordPath));
            return key;
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                $"Encrypted ECDSA key '{path}' is invalid.",
                exception);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"Encrypted ECDSA key '{path}' is invalid.",
                exception);
        }
    }

    private static RSA LoadRsaKey(string path)
    {
        try
        {
            var key = RSA.Create();
            key.ImportFromPem(File.ReadAllText(path));
            return key;
        }
        catch (ArgumentException exception)
        {
            throw new InvalidDataException(
                $"RSA key '{path}' is invalid.",
                exception);
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"RSA key '{path}' is invalid.",
                exception);
        }
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
            writer.Flush();
            stream.Flush(flushToDisk: true);
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
