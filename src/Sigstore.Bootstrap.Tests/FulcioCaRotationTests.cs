using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Sigstore.Bootstrap;
using Xunit;

namespace Sigstore.Bootstrap.Tests;

public sealed class FulcioCaRotationTests
{
    private static readonly string[] ExpectedCandidateFiles =
    [
        "private/fulcio/password",
        "private/fulcio/root.key",
        "public/fulcio/root.pem"
    ];

    [Fact]
    public void CandidateUsesExistingProfileAndMatchesKeyAndPassword()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var initial = SigstoreStateBootstrapper.EnsureInitialized(state);
        var activeGenerationPath = Path.Combine(
            state,
            "generations",
            initial.Generation.GenerationId);
        var activeMaterial =
            SigstoreStateBootstrapper.ValidateFulcioCertificateAuthority(
                activeGenerationPath);
        var candidatePath = Path.Combine(
            state,
            "fulcio-rotation",
            Guid.NewGuid().ToString("N"),
            "candidate");

        var candidate =
            SigstoreStateBootstrapper.EnsureFulcioCaRotationCandidate(
                candidatePath);
        var replay =
            SigstoreStateBootstrapper.EnsureFulcioCaRotationCandidate(
                candidatePath);

        Assert.Equal(candidate, replay);
        Assert.NotEqual(activeMaterial.RootSha256, candidate.RootSha256);
        Assert.NotEqual(
            activeMaterial.PublicKeySha256,
            candidate.PublicKeySha256);
        Assert.Equal(
            initial.Generation.FulcioRootSha256,
            activeMaterial.RootSha256);
        Assert.Equal(
            ExpectedCandidateFiles,
            RelativeFiles(candidatePath));

        var certificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Path.Combine(
                    candidatePath,
                    "public",
                    "fulcio",
                    "root.pem")));
        using var publicKey = certificate.GetECDsaPublicKey();
        Assert.NotNull(publicKey);
        Assert.Equal(256, publicKey!.KeySize);
        Assert.Equal(
            "1.2.840.10045.4.3.2",
            certificate.SignatureAlgorithm.Value);

        var basicConstraints = Assert.Single(
            certificate.Extensions.OfType<X509BasicConstraintsExtension>());
        Assert.True(basicConstraints.Critical);
        Assert.True(basicConstraints.CertificateAuthority);
        Assert.False(basicConstraints.HasPathLengthConstraint);

        var keyUsage = Assert.Single(
            certificate.Extensions.OfType<X509KeyUsageExtension>());
        Assert.True(keyUsage.Critical);
        Assert.Equal(
            X509KeyUsageFlags.DigitalSignature
            | X509KeyUsageFlags.KeyCertSign
            | X509KeyUsageFlags.CrlSign,
            keyUsage.KeyUsages);

        Assert.Single(
            certificate.Extensions
                .OfType<X509SubjectKeyIdentifierExtension>());
        Assert.Empty(
            certificate.Extensions
                .OfType<X509EnhancedKeyUsageExtension>());

        var validity = certificate.NotAfter.ToUniversalTime()
            - certificate.NotBefore.ToUniversalTime();
        Assert.InRange(
            validity.TotalDays,
            3650,
            3654);

        var privateKeyPem = File.ReadAllText(
            Path.Combine(
                candidatePath,
                "private",
                "fulcio",
                "root.key"));
        Assert.StartsWith(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----",
            privateKeyPem,
            StringComparison.Ordinal);

        var password = File.ReadAllText(
            Path.Combine(
                candidatePath,
                "private",
                "fulcio",
                "password"));
        Assert.Equal(43, password.Length);
        Assert.All(
            password,
            character => Assert.True(
                char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_'));

        using var privateKey = ECDsa.Create();
        privateKey.ImportFromEncryptedPem(privateKeyPem, password);
        Assert.Equal(
            Convert.ToHexString(publicKey.ExportSubjectPublicKeyInfo()),
            Convert.ToHexString(privateKey.ExportSubjectPublicKeyInfo()));
        Assert.Equal(
            candidate.RootSha256,
            Convert.ToHexString(SHA256.HashData(certificate.RawData))
                .ToLowerInvariant());
    }

    [Fact]
    public void CandidateTamperingIsRejectedInsteadOfRegenerated()
    {
        using var fixture = new TemporaryDirectory();
        var candidatePath = Path.Combine(fixture.Path, "candidate");
        _ = SigstoreStateBootstrapper.EnsureFulcioCaRotationCandidate(
            candidatePath);
        File.WriteAllText(
            Path.Combine(
                candidatePath,
                "private",
                "fulcio",
                "password"),
            "not-the-real-password");

        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.EnsureFulcioCaRotationCandidate(
                candidatePath));
    }

    [Fact]
    public void CandidateWithAnExtraFileIsRejected()
    {
        using var fixture = new TemporaryDirectory();
        var candidatePath = Path.Combine(fixture.Path, "candidate");
        _ = SigstoreStateBootstrapper.EnsureFulcioCaRotationCandidate(
            candidatePath);
        File.Copy(
            Path.Combine(candidatePath, "public", "fulcio", "root.pem"),
            Path.Combine(candidatePath, "public", "fulcio", "extra.pem"));

        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.EnsureFulcioCaRotationCandidate(
                candidatePath));
    }

    [Fact]
    public void AmbiguousStagingIsDiscardedAndNeverPromoted()
    {
        using var fixture = new TemporaryDirectory();
        var candidatePath = Path.Combine(fixture.Path, "candidate");
        var stagingPath = candidatePath + ".staging";
        Directory.CreateDirectory(
            Path.Combine(stagingPath, "public", "fulcio"));
        File.WriteAllText(
            Path.Combine(stagingPath, "public", "fulcio", "root.pem"),
            "not a certificate");

        var candidate =
            SigstoreStateBootstrapper.EnsureFulcioCaRotationCandidate(
                candidatePath);

        Assert.False(Directory.Exists(stagingPath));
        Assert.Equal(
            ExpectedCandidateFiles,
            RelativeFiles(candidatePath));
        Assert.Equal(
            candidate,
            SigstoreStateBootstrapper.ValidateFulcioCertificateAuthority(
                candidatePath));
    }

    [Fact]
    public void BootstrapProjectsComponentScopedRuntimeDirectories()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var result = SigstoreStateBootstrapper.EnsureInitialized(state);
        var generationPath = Path.Combine(
            state,
            "generations",
            result.Generation.GenerationId);
        var runtimePath = Path.Combine(state, "runtime");

        Assert.Equal(
            ["fulcio", "tesseract"],
            EntryNames(runtimePath));
        Assert.Equal(
            ["ctlog.pub", "password", "root.key", "root.pem"],
            EntryNames(Path.Combine(runtimePath, "fulcio")));
        Assert.Equal(
            ["accepted-roots.pem", "privkey.pem"],
            EntryNames(Path.Combine(runtimePath, "tesseract")));
        Assert.Null(
            new DirectoryInfo(Path.Combine(runtimePath, "fulcio"))
                .LinkTarget);
        Assert.Null(
            new DirectoryInfo(Path.Combine(runtimePath, "tesseract"))
                .LinkTarget);

        AssertSameBytes(
            Path.Combine(generationPath, "public", "fulcio", "root.pem"),
            Path.Combine(runtimePath, "fulcio", "root.pem"));
        AssertSameBytes(
            Path.Combine(generationPath, "private", "fulcio", "root.key"),
            Path.Combine(runtimePath, "fulcio", "root.key"));
        AssertSameBytes(
            Path.Combine(generationPath, "private", "fulcio", "password"),
            Path.Combine(runtimePath, "fulcio", "password"));
        AssertSameBytes(
            Path.Combine(generationPath, "private", "ctlog", "privkey.pem"),
            Path.Combine(runtimePath, "tesseract", "privkey.pem"));

        var activeRoot = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Path.Combine(
                    generationPath,
                    "public",
                    "fulcio",
                    "root.pem")));
        var acceptedRootsPath = Path.Combine(
            runtimePath,
            "tesseract",
            "accepted-roots.pem");
        Assert.Equal(
            activeRoot.ExportCertificatePem() + "\n",
            File.ReadAllText(acceptedRootsPath));

        var acceptedRoots = new X509Certificate2Collection();
        acceptedRoots.ImportFromPem(File.ReadAllText(acceptedRootsPath));
        Assert.Single(acceptedRoots);
        Assert.Equal(
            Convert.ToHexString(activeRoot.RawData),
            Convert.ToHexString(acceptedRoots[0].RawData));

        // Re-running bootstrap is idempotent and revalidates the projection.
        var reused = SigstoreStateBootstrapper.EnsureInitialized(state);
        Assert.Equal(BootstrapAction.Reused, reused.Action);
    }

    [Theory]
    [MemberData(nameof(RuntimeTamperCases))]
    public void TamperedRuntimeProjectionIsRejected(
        string scenario)
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var result = SigstoreStateBootstrapper.EnsureInitialized(state);
        var runtimePath = Path.Combine(state, "runtime");
        var acceptedRootsPath = Path.Combine(
            runtimePath,
            "tesseract",
            "accepted-roots.pem");

        switch (scenario)
        {
            case "extra-file":
                File.WriteAllText(
                    Path.Combine(runtimePath, "fulcio", "stray.pem"),
                    "stray");
                break;
            case "missing-file":
                File.Delete(
                    Path.Combine(runtimePath, "tesseract", "privkey.pem"));
                break;
            case "extra-component":
                Directory.CreateDirectory(
                    Path.Combine(runtimePath, "rekor"));
                break;
            case "stale-secret":
                File.WriteAllText(
                    Path.Combine(runtimePath, "fulcio", "root.key"),
                    "tampered");
                break;
            case "duplicate-accepted-root":
                File.WriteAllText(
                    acceptedRootsPath,
                    File.ReadAllText(acceptedRootsPath)
                    + File.ReadAllText(acceptedRootsPath));
                break;
            case "unrelated-accepted-root":
                File.WriteAllText(
                    acceptedRootsPath,
                    CreateUnrelatedRootPem(fixture.Path));
                break;
            case "malformed-accepted-root":
                File.AppendAllText(
                    acceptedRootsPath,
                    "trailing junk\n");
                break;
            default:
                throw new InvalidOperationException(scenario);
        }

        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.EnsureInitialized(state));
        Assert.Equal(
            "generation-00000001",
            result.Generation.GenerationId);
    }

    public static TheoryData<string> RuntimeTamperCases =>
    [
        "extra-file",
        "missing-file",
        "extra-component",
        "stale-secret",
        "duplicate-accepted-root",
        "unrelated-accepted-root",
        "malformed-accepted-root"
    ];

    [Fact]
    public void FulcioRotationStateEntriesAreAllowedAtTheStateRoot()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        _ = SigstoreStateBootstrapper.EnsureInitialized(state);

        var candidatePath = Path.Combine(
            state,
            "fulcio-rotation",
            "00000000000000000000000000000001",
            "candidate");
        _ = SigstoreStateBootstrapper.EnsureFulcioCaRotationCandidate(
            candidatePath);
        File.WriteAllText(
            Path.Combine(state, "rotate-fulcio-ca.request"),
            "{}\n");
        File.WriteAllText(
            Path.Combine(state, "rotate-fulcio-ca.completed"),
            "{}\n");

        var reused = SigstoreStateBootstrapper.EnsureInitialized(state);
        Assert.Equal(BootstrapAction.Reused, reused.Action);

        File.WriteAllText(
            Path.Combine(state, "unexpected.request"),
            "{}\n");
        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.EnsureInitialized(state));
    }

    /// <summary>
    /// Regression coverage for the cross-language contract: the Go worker's
    /// encoder is not byte-identical to System.Text.Json, so trust metadata it
    /// writes must be validated through the transition hash, the file map and
    /// semantic identity rather than through canonical re-serialization.
    /// </summary>
    [Fact]
    public void WorkerShapedGenerationIsAcceptedByBootstrapAndProjection()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var scenario = FulcioRotationScenario.Create(state);
        var manifestPath = Path.Combine(
            state,
            "generations",
            "generation-00000002",
            "manifest.json");

        // The fixture really is in the worker's shape, not the C# one.
        var text = File.ReadAllText(manifestPath);
        Assert.DoesNotContain("\"oidcRotationOperationId\"", text);
        Assert.DoesNotContain("\"tsaRotationOperationId\"", text);
        Assert.Contains("\"fulcioRotationOperationId\"", text);
        var reserialized = JsonSerializer.Serialize(
            JsonSerializer.Deserialize<GenerationManifest>(
                File.ReadAllBytes(manifestPath),
                new JsonSerializerOptions(JsonSerializerDefaults.Web))!,
            new JsonSerializerOptions(JsonSerializerDefaults.Web)
            {
                WriteIndented = true
            }) + "\n";
        Assert.NotEqual(reserialized, text);

        var reused = SigstoreStateBootstrapper.EnsureInitialized(state);
        Assert.Equal(BootstrapAction.Reused, reused.Action);
        Assert.Equal(
            scenario.NewRootSha256,
            reused.Generation.FulcioRootSha256);
        Assert.Equal(
            scenario.OperationId,
            reused.Generation.FulcioRotationOperationId);

        var projection =
            SigstoreStateBootstrapper.ReadFulcioRuntimeProjection(state);
        Assert.True(projection.PromotionPending);
        Assert.Equal(scenario.NewRootSha256, projection.StagedRootSha256);

        var promoted = SigstoreStateBootstrapper
            .ActivateFulcioRuntimeProjection(
                state,
                scenario.OperationId,
                scenario.PriorRootSha256,
                scenario.NewRootSha256);
        Assert.Equal(scenario.NewRootSha256, promoted.ActiveRootSha256);
    }

    /// <summary>
    /// The C# invariant that generation manifests are read-only is deliberately
    /// strict: on a Docker Desktop bind mount the mode requested at creation is
    /// silently dropped, which the Go worker must correct explicitly. This
    /// pins the invariant so that regression cannot be papered over here.
    /// </summary>
    [Fact]
    public void WritableGenerationManifestIsRejected()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var scenario = FulcioRotationScenario.Create(state);
        var manifestPath = Path.Combine(
            state,
            "generations",
            "generation-00000002",
            "manifest.json");

        Assert.NotNull(
            SigstoreStateBootstrapper.ReadFulcioRuntimeProjection(state));

        // Same bytes, same hashes — only the mode regresses to 0644.
        FulcioRotationScenario.MakeManifestWritable(manifestPath);

        var failure = Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.ReadFulcioRuntimeProjection(
                state));
        Assert.Contains(
            "read-only",
            failure.Message,
            StringComparison.Ordinal);
        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.EnsureInitialized(state));
        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.ActivateFulcioRuntimeProjection(
                state,
                scenario.OperationId,
                scenario.PriorRootSha256,
                scenario.NewRootSha256));
    }

    [Theory]
    [InlineData("byte-tamper")]
    [InlineData("injected-member")]
    [InlineData("file-map-tamper")]
    [InlineData("identity-tamper")]
    [InlineData("journal-detached")]
    public void WorkerShapedGenerationStillRejectsTampering(string scenarioName)
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var scenario = FulcioRotationScenario.Create(state);
        var manifestPath = Path.Combine(
            state,
            "generations",
            "generation-00000002",
            "manifest.json");

        switch (scenarioName)
        {
            case "byte-tamper":
                // Only the bytes change; every recorded hash is now stale.
                var raw = File.ReadAllBytes(manifestPath);
                FulcioRotationScenario.RewriteRawManifest(
                    manifestPath,
                    [.. raw, (byte)' ']);
                break;
            case "injected-member":
                // Re-hashed everywhere, but carries an unmapped member.
                FulcioRotationScenario.RewriteWorkerManifest(
                    state,
                    manifest => manifest["attackerNote"] = "ride-along");
                break;
            case "file-map-tamper":
                // Re-hashed everywhere, but the file map no longer describes
                // the material actually on disk.
                FulcioRotationScenario.RewriteWorkerManifest(
                    state,
                    manifest => manifest["files"]!
                            .AsObject()["public/fulcio/root.pem"] =
                        new string('0', 64));
                break;
            case "identity-tamper":
                // Re-hashed everywhere, but claims another trust domain.
                FulcioRotationScenario.RewriteWorkerManifest(
                    state,
                    manifest => manifest["trustDomainId"] =
                        "sha256-" + new string('b', 64));
                break;
            case "journal-detached":
                // The manifest is rewritten without re-binding the journal,
                // so the journaled candidate hash no longer matches.
                FulcioRotationScenario.RewriteWorkerManifest(
                    state,
                    manifest => manifest["fulcioPriorGeneration"] = 7,
                    rebindJournal: false);
                break;
            default:
                throw new InvalidOperationException(scenarioName);
        }

        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.EnsureInitialized(state));
        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.ReadFulcioRuntimeProjection(
                state));
        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.ActivateFulcioRuntimeProjection(
                state,
                scenario.OperationId,
                scenario.PriorRootSha256,
                scenario.NewRootSha256));
    }

    [Fact]
    public void ReadFulcioRuntimeProjectionDescribesTheSteadyState()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var result = SigstoreStateBootstrapper.EnsureInitialized(state);

        var projection =
            SigstoreStateBootstrapper.ReadFulcioRuntimeProjection(state);

        Assert.False(projection.PromotionPending);
        Assert.Null(projection.StagedRootSha256);
        Assert.Equal(
            result.Generation.FulcioRootSha256,
            projection.ActiveRootSha256);
        Assert.Equal(
            [result.Generation.FulcioRootSha256],
            projection.AcceptedRootSha256);
        Assert.Equal(
            Fingerprint(
                Path.Combine(
                    state,
                    "runtime",
                    "tesseract",
                    "accepted-roots.pem")),
            projection.AcceptedRootsSha256);
        Assert.Equal(
            CtLogPublicKeySha256(state),
            projection.ActiveCtLogPublicKeySha256);
        Assert.Equal(
            result.Generation.CtLogPublicKeySha256,
            projection.ActiveCtLogPublicKeySha256);
        Assert.Contains(
            "Fulcio Root",
            projection.ActiveRootSubject,
            StringComparison.Ordinal);
        Assert.True(
            projection.ActiveNotBeforeUtc < DateTimeOffset.UtcNow);
        Assert.True(
            projection.ActiveNotAfterUtc > DateTimeOffset.UtcNow);
    }

    [Fact]
    public void ReadFulcioRuntimeProjectionRejectsTamperedMaterial()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        _ = SigstoreStateBootstrapper.EnsureInitialized(state);
        var unrelatedPath = Path.Combine(fixture.Path, "unrelated");
        _ = SigstoreStateBootstrapper.EnsureFulcioCaRotationCandidate(
            unrelatedPath);
        File.Copy(
            Path.Combine(unrelatedPath, "private", "fulcio", "root.key"),
            Path.Combine(state, "runtime", "fulcio", "root.key"),
            overwrite: true);

        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.ReadFulcioRuntimeProjection(
                state));
    }

    [Fact]
    public void RuntimePromotionActivatesOnlyTheStagedRotation()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var scenario = FulcioRotationScenario.Create(state);
        var runtimePath = Path.Combine(state, "runtime");

        // The worker stages the new CA but must never activate it: Fulcio is
        // still serving the old root at this point.
        var pending = SigstoreStateBootstrapper.ReadFulcioRuntimeProjection(
            state);
        Assert.True(pending.PromotionPending);
        Assert.Equal(scenario.PriorRootSha256, pending.ActiveRootSha256);
        Assert.Equal(scenario.NewRootSha256, pending.StagedRootSha256);
        Assert.Equal(
            [scenario.PriorRootSha256, scenario.NewRootSha256],
            pending.AcceptedRootSha256);
        Assert.Equal(
            Fingerprint(
                Path.Combine(runtimePath, "tesseract", "accepted-roots.pem")),
            pending.AcceptedRootsSha256);

        // The reported active identity is derived from — and proven against —
        // the projected key material Fulcio actually loads.
        var priorMaterial = SigstoreStateBootstrapper
            .ValidateFulcioCertificateAuthority(
                Path.Combine(
                    state,
                    "generations",
                    "generation-00000001"));
        Assert.Equal(
            priorMaterial.PublicKeySha256,
            pending.ActivePublicKeySha256);
        Assert.Equal(
            priorMaterial.SubjectDistinguishedName,
            pending.ActiveRootSubject);
        Assert.Equal(
            priorMaterial.NotBeforeUtc,
            pending.ActiveNotBeforeUtc);
        Assert.Equal(
            priorMaterial.NotAfterUtc,
            pending.ActiveNotAfterUtc);
        Assert.Equal(
            CtLogPublicKeySha256(state),
            pending.ActiveCtLogPublicKeySha256);
        AssertSameBytes(
            Path.Combine(
                state,
                "generations",
                "generation-00000001",
                "public",
                "fulcio",
                "root.pem"),
            Path.Combine(runtimePath, "fulcio", "root.pem"));

        var promoted = SigstoreStateBootstrapper
            .ActivateFulcioRuntimeProjection(
                state,
                scenario.OperationId,
                scenario.PriorRootSha256,
                scenario.NewRootSha256);

        Assert.False(promoted.PromotionPending);
        Assert.Null(promoted.StagedRootSha256);
        Assert.Equal(scenario.NewRootSha256, promoted.ActiveRootSha256);
        var newMaterial = SigstoreStateBootstrapper
            .ValidateFulcioCertificateAuthority(
                Path.Combine(
                    state,
                    "generations",
                    "generation-00000002"));
        Assert.Equal(
            newMaterial.PublicKeySha256,
            promoted.ActivePublicKeySha256);
        Assert.Equal(
            newMaterial.SubjectDistinguishedName,
            promoted.ActiveRootSubject);
        // The CT log key is unchanged by a Fulcio rotation.
        Assert.Equal(
            pending.ActiveCtLogPublicKeySha256,
            promoted.ActiveCtLogPublicKeySha256);
        Assert.False(
            Directory.Exists(Path.Combine(runtimePath, "fulcio.next")));
        Assert.Equal(
            ["fulcio", "tesseract"],
            EntryNames(runtimePath));
        AssertSameBytes(
            Path.Combine(
                state,
                "generations",
                "generation-00000002",
                "public",
                "fulcio",
                "root.pem"),
            Path.Combine(runtimePath, "fulcio", "root.pem"));
        AssertSameBytes(
            Path.Combine(
                state,
                "generations",
                "generation-00000002",
                "private",
                "fulcio",
                "root.key"),
            Path.Combine(runtimePath, "fulcio", "root.key"));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite,
                File.GetUnixFileMode(
                    Path.Combine(runtimePath, "fulcio", "root.key")));
        }

        // Promotion is idempotent.
        var replay = SigstoreStateBootstrapper
            .ActivateFulcioRuntimeProjection(
                state,
                scenario.OperationId,
                scenario.PriorRootSha256,
                scenario.NewRootSha256);
        Assert.Equal(promoted.ActiveRootSha256, replay.ActiveRootSha256);
        Assert.Equal(
            promoted.ActivePublicKeySha256,
            replay.ActivePublicKeySha256);
        Assert.Equal(
            promoted.ActiveCtLogPublicKeySha256,
            replay.ActiveCtLogPublicKeySha256);
        Assert.Equal(promoted.StagedRootSha256, replay.StagedRootSha256);
        Assert.Equal(promoted.PromotionPending, replay.PromotionPending);
        Assert.Equal(
            promoted.AcceptedRootsSha256,
            replay.AcceptedRootsSha256);
        Assert.Equal(
            promoted.AcceptedRootSha256,
            replay.AcceptedRootSha256);

        var reused = SigstoreStateBootstrapper.EnsureInitialized(state);
        Assert.Equal(BootstrapAction.Reused, reused.Action);
    }

    [Fact]
    public void RuntimePromotionRepairsRecognizedPartialWrites()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var scenario = FulcioRotationScenario.Create(state);
        var runtimePath = Path.Combine(state, "runtime");

        // Emulate a crash midway through promotion: root.pem is already the
        // new CA while the key and password still belong to the old one.
        File.Copy(
            Path.Combine(runtimePath, "fulcio.next", "root.pem"),
            Path.Combine(runtimePath, "fulcio", "root.pem"),
            overwrite: true);

        var promoted = SigstoreStateBootstrapper
            .ActivateFulcioRuntimeProjection(
                state,
                scenario.OperationId,
                scenario.PriorRootSha256,
                scenario.NewRootSha256);

        Assert.Equal(scenario.NewRootSha256, promoted.ActiveRootSha256);
        Assert.False(
            Directory.Exists(Path.Combine(runtimePath, "fulcio.next")));
        var newGenerationPath = Path.Combine(
            state,
            "generations",
            "generation-00000002");
        AssertSameBytes(
            Path.Combine(newGenerationPath, "private", "fulcio", "root.key"),
            Path.Combine(runtimePath, "fulcio", "root.key"));
        AssertSameBytes(
            Path.Combine(newGenerationPath, "private", "fulcio", "password"),
            Path.Combine(runtimePath, "fulcio", "password"));
    }

    [Theory]
    [InlineData("unrelated-bytes")]
    [InlineData("extra-file")]
    [InlineData("tampered-stage")]
    [InlineData("missing-stage")]
    public void RuntimePromotionRejectsUnrecognizedProjections(
        string scenarioName)
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var scenario = FulcioRotationScenario.Create(state);
        var runtimePath = Path.Combine(state, "runtime");

        switch (scenarioName)
        {
            case "unrelated-bytes":
                File.WriteAllText(
                    Path.Combine(runtimePath, "fulcio", "password"),
                    "neither-generation");
                break;
            case "extra-file":
                File.WriteAllText(
                    Path.Combine(runtimePath, "fulcio", "stray.pem"),
                    "stray");
                break;
            case "tampered-stage":
                File.WriteAllText(
                    Path.Combine(runtimePath, "fulcio.next", "password"),
                    "tampered");
                break;
            case "missing-stage":
                Directory.Delete(
                    Path.Combine(runtimePath, "fulcio.next"),
                    recursive: true);
                break;
            default:
                throw new InvalidOperationException(scenarioName);
        }

        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.ActivateFulcioRuntimeProjection(
                state,
                scenario.OperationId,
                scenario.PriorRootSha256,
                scenario.NewRootSha256));

        // The old CA is still the one Fulcio serves.
        AssertSameBytes(
            Path.Combine(
                state,
                "generations",
                "generation-00000001",
                "public",
                "fulcio",
                "root.pem"),
            Path.Combine(runtimePath, "fulcio", "root.pem"));
    }

    [Fact]
    public void PendingPromotionIsAValidTrustStateAndStagedEntriesAreAllowed()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var scenario = FulcioRotationScenario.Create(state);

        // A completed worker rotation that has not yet been promoted must
        // still validate: runtime/fulcio deliberately lags the active
        // generation until Hosting proves the old CA.
        var reused = SigstoreStateBootstrapper.EnsureInitialized(state);
        Assert.Equal(BootstrapAction.Reused, reused.Action);
        Assert.Equal(
            "generation-00000002",
            reused.Generation.GenerationId);
        Assert.Equal(
            scenario.OperationId,
            reused.Generation.FulcioRotationOperationId);

        // Bootstrap must not silently activate the staged CA.
        AssertSameBytes(
            Path.Combine(
                state,
                "generations",
                "generation-00000001",
                "public",
                "fulcio",
                "root.pem"),
            Path.Combine(state, "runtime", "fulcio", "root.pem"));
    }

    [Fact]
    public void RuntimeActivationRejectsUnboundOperations()
    {
        using var fixture = new TemporaryDirectory();
        var state = Path.Combine(fixture.Path, "state");
        var result = SigstoreStateBootstrapper.EnsureInitialized(state);
        var activeRoot = result.Generation.FulcioRootSha256;
        var otherRoot = new string('a', 64);

        // A generation that never rotated its CA is not bound to any
        // operation, so activation must refuse to promote it.
        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.ActivateFulcioRuntimeProjection(
                state,
                "00000000000000000000000000000001",
                otherRoot,
                activeRoot));

        // Malformed operation identity is rejected before any file is touched.
        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.ActivateFulcioRuntimeProjection(
                state,
                "not-a-valid-operation-id",
                otherRoot,
                activeRoot));

        // A no-op rotation is rejected: activation must change the CA.
        Assert.ThrowsAny<Exception>(
            () => SigstoreStateBootstrapper.ActivateFulcioRuntimeProjection(
                state,
                "00000000000000000000000000000001",
                activeRoot,
                activeRoot));

        var reused = SigstoreStateBootstrapper.EnsureInitialized(state);
        Assert.Equal(BootstrapAction.Reused, reused.Action);
    }

    /// <summary>
    /// Builds the exact on-disk state the Go worker leaves behind once a
    /// Fulcio CA rotation has committed but before Hosting promotes it:
    /// generation N+1 is active and operation-bound, the accepted-root bundle
    /// spans both certificate authorities, the new CA is staged under
    /// runtime/fulcio.next, and runtime/fulcio still serves the old CA.
    /// </summary>
    private sealed record FulcioRotationScenario(
        string OperationId,
        string PriorRootSha256,
        string NewRootSha256)
    {
        private static readonly JsonSerializerOptions CanonicalOptions =
            new(JsonSerializerDefaults.Web)
            {
                WriteIndented = true
            };

        public static FulcioRotationScenario Create(string statePath)
        {
            var initial = SigstoreStateBootstrapper.EnsureInitialized(
                statePath);
            var operationId = Guid.NewGuid().ToString("N");
            var priorGenerationPath = Path.Combine(
                statePath,
                "generations",
                initial.Generation.GenerationId);
            var newGenerationId = "generation-00000002";
            var newGenerationPath = Path.Combine(
                statePath,
                "generations",
                newGenerationId);

            var candidatePath = Path.Combine(
                statePath,
                "fulcio-rotation",
                operationId,
                "candidate");
            var candidate = SigstoreStateBootstrapper
                .EnsureFulcioCaRotationCandidate(candidatePath);

            CopyTree(
                Path.Combine(priorGenerationPath, "private"),
                Path.Combine(newGenerationPath, "private"));
            CopyTree(
                Path.Combine(priorGenerationPath, "public"),
                Path.Combine(newGenerationPath, "public"));
            foreach (var relative in new[]
            {
                "private/fulcio/root.key",
                "private/fulcio/password",
                "public/fulcio/root.pem"
            })
            {
                var destination = Resolve(newGenerationPath, relative);
                File.Delete(destination);
                File.Copy(
                    Resolve(candidatePath, relative),
                    destination);
            }

            var prior = initial.Generation;
            var generation = new GenerationManifest(
                prior.SchemaVersion,
                2,
                newGenerationId,
                prior.TrustDomainId,
                DateTimeOffset.UtcNow,
                prior.SchemaVersion,
                null,
                candidate.RootSha256,
                prior.CtLogPublicKeySha256,
                prior.RekorPublicKeySha256,
                prior.TsaRootSha256,
                prior.TsaLeafSha256,
                prior.OidcKeyId,
                null,
                0,
                null,
                null,
                null,
                prior.OidcRetainedPrivateKeyPaths,
                prior.TsaRotationOperationId,
                prior.TsaPriorGeneration,
                prior.TsaPriorGenerationId,
                prior.TsaPriorRootSha256,
                prior.TsaPriorLeafSha256,
                operationId,
                prior.Generation,
                prior.GenerationId,
                prior.FulcioRootSha256,
                CollectHashes(newGenerationPath));
            var manifestPath = Path.Combine(
                newGenerationPath,
                "manifest.json");
            WriteWorkerShapedManifest(manifestPath, generation);
            SetReadOnly(manifestPath);

            var journalPath = Path.Combine(
                statePath,
                "transition",
                "state.json");
            var journal = JsonSerializer.Deserialize<TrustTransitionJournal>(
                File.ReadAllBytes(journalPath),
                CanonicalOptions)!;
            WriteWorkerShapedJournal(
                journalPath,
                journal with
                {
                    TransitionId = operationId,
                    Operation = "fulcio-rotation",
                    UpdatedAtUtc = DateTimeOffset.UtcNow,
                    PriorGeneration = journal.Candidate,
                    Candidate = new GenerationReference(
                        2,
                        newGenerationId,
                        Sha256(File.ReadAllBytes(manifestPath))),
                    CandidateManifest = generation
                });

            var activeLink = Path.Combine(statePath, "active-generation");
            Directory.Delete(activeLink);
            Directory.CreateSymbolicLink(
                activeLink,
                Path.Combine("generations", newGenerationId));

            var stagedPath = Path.Combine(
                statePath,
                "runtime",
                "fulcio.next");
            Directory.CreateDirectory(stagedPath);
            foreach (var (name, relative) in new[]
            {
                ("root.pem", "public/fulcio/root.pem"),
                ("root.key", "private/fulcio/root.key"),
                ("password", "private/fulcio/password"),
                ("ctlog.pub", "public/ctlog/pubkey.pem")
            })
            {
                File.Copy(
                    Resolve(newGenerationPath, relative),
                    Path.Combine(stagedPath, name),
                    overwrite: true);
            }

            var acceptedRootsPath = Path.Combine(
                statePath,
                "runtime",
                "tesseract",
                "accepted-roots.pem");
            using var newRoot = X509Certificate2.CreateFromPem(
                File.ReadAllText(
                    Resolve(newGenerationPath, "public/fulcio/root.pem")));
            File.WriteAllText(
                acceptedRootsPath,
                File.ReadAllText(acceptedRootsPath)
                + newRoot.ExportCertificatePem() + "\n");

            return new FulcioRotationScenario(
                operationId,
                prior.FulcioRootSha256,
                candidate.RootSha256);
        }

        /// <summary>
        /// Serializes a generation manifest the way the Go worker's
        /// encoding/json does rather than the way System.Text.Json does:
        /// unset optional members are omitted entirely instead of being
        /// written as null, timestamps use a "Z" suffix with trimmed
        /// fractional digits, and the file map is emitted in its own order.
        /// Reading this shape back is the exact cross-language case that
        /// previously failed canonical-byte validation.
        /// </summary>
        /// <summary>
        /// Rewrites the worker-shaped generation manifest and re-binds the
        /// transition journal to the new bytes, so a test can express "the
        /// attacker also updated every hash they could reach" and still expect
        /// rejection from the checks that bind to real material.
        /// </summary>
        /// <summary>
        /// Reproduces a filesystem that ignored the requested creation mode
        /// and materialized the manifest as a writable 0644 file.
        /// </summary>
        public static void MakeManifestWritable(string path)
        {
            if (OperatingSystem.IsWindows())
            {
                File.SetAttributes(
                    path,
                    File.GetAttributes(path) & ~FileAttributes.ReadOnly);
                return;
            }
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead);
        }

        public static void RewriteRawManifest(string path, byte[] bytes)
        {
            SetWritable(path);
            File.WriteAllBytes(path, bytes);
            SetReadOnly(path);
        }

        public static void RewriteWorkerManifest(
            string statePath,
            Action<JsonObject> mutate,
            bool rebindJournal = true)
        {
            var manifestPath = Path.Combine(
                statePath,
                "generations",
                "generation-00000002",
                "manifest.json");
            var manifest = JsonNode
                .Parse(File.ReadAllBytes(manifestPath))!
                .AsObject();
            mutate(manifest);
            var bytes = Encoding.UTF8.GetBytes(
                manifest.ToJsonString(
                    new JsonSerializerOptions(JsonSerializerDefaults.Web)
                    {
                        WriteIndented = true
                    })
                + "\n");
            SetWritable(manifestPath);
            File.WriteAllBytes(manifestPath, bytes);
            SetReadOnly(manifestPath);
            if (!rebindJournal)
            {
                return;
            }

            var journalPath = Path.Combine(
                statePath,
                "transition",
                "state.json");
            var journal = JsonNode
                .Parse(File.ReadAllBytes(journalPath))!
                .AsObject();
            journal["candidate"]!.AsObject()["manifestSha256"] =
                Sha256(bytes);
            journal["candidateManifest"] = JsonNode.Parse(bytes);
            File.WriteAllBytes(
                journalPath,
                Encoding.UTF8.GetBytes(
                    journal.ToJsonString(
                        new JsonSerializerOptions(
                            JsonSerializerDefaults.Web)
                        {
                            WriteIndented = true
                        })
                    + "\n"));
        }

        private static void WriteWorkerShapedManifest(
            string path,
            GenerationManifest manifest)
        {
            var document = new Dictionary<string, object?>
            {
                ["schemaVersion"] = manifest.SchemaVersion,
                ["generation"] = manifest.Generation,
                ["generationId"] = manifest.GenerationId,
                ["trustDomainId"] = manifest.TrustDomainId,
                ["createdAtUtc"] = GoTimestamp(manifest.CreatedAtUtc),
                ["sourceSchemaVersion"] = manifest.SourceSchemaVersion,
                ["sourceManifestSha256"] = manifest.SourceManifestSha256,
                ["fulcioRootSha256"] = manifest.FulcioRootSha256,
                ["ctLogPublicKeySha256"] = manifest.CtLogPublicKeySha256,
                ["rekorPublicKeySha256"] = manifest.RekorPublicKeySha256,
                ["tsaRootSha256"] = manifest.TsaRootSha256,
                ["tsaLeafSha256"] = manifest.TsaLeafSha256,
                ["oidcKeyId"] = manifest.OidcKeyId
            };
            AddIfPresent(
                document,
                "oidcRotationOperationId",
                manifest.OidcRotationOperationId);
            AddIfPresent(
                document,
                "tsaRotationOperationId",
                manifest.TsaRotationOperationId);
            AddIfPresent(
                document,
                "fulcioRotationOperationId",
                manifest.FulcioRotationOperationId);
            if (manifest.FulcioPriorGeneration != 0)
            {
                document["fulcioPriorGeneration"] =
                    manifest.FulcioPriorGeneration;
                document["fulcioPriorGenerationId"] =
                    manifest.FulcioPriorGenerationId;
                document["fulcioPriorRootSha256"] =
                    manifest.FulcioPriorRootSha256;
            }
            document["files"] = manifest.Files
                .Reverse()
                .ToDictionary(
                    pair => pair.Key,
                    pair => pair.Value);
            WriteGoJson(path, document);
        }

        private static void WriteWorkerShapedJournal(
            string path,
            TrustTransitionJournal journal)
        {
            var document = new Dictionary<string, object?>
            {
                ["schemaVersion"] = journal.SchemaVersion,
                ["transitionId"] = journal.TransitionId,
                ["operation"] = journal.Operation,
                ["status"] = journal.Status,
                ["lastCheckpoint"] = journal.LastCheckpoint,
                ["startedAtUtc"] = GoTimestamp(journal.StartedAtUtc),
                ["updatedAtUtc"] = GoTimestamp(journal.UpdatedAtUtc),
                ["priorGeneration"] = journal.PriorGeneration,
                ["candidate"] = journal.Candidate,
                ["trustDomainManifestSha256"] =
                    journal.TrustDomainManifestSha256,
                ["trustDomain"] = new Dictionary<string, object?>
                {
                    ["schemaVersion"] = journal.TrustDomain.SchemaVersion,
                    ["trustDomainId"] = journal.TrustDomain.TrustDomainId,
                    ["createdAtUtc"] = GoTimestamp(
                        journal.TrustDomain.CreatedAtUtc),
                    ["ctLogStateId"] = journal.TrustDomain.CtLogStateId,
                    ["rekorStateId"] = journal.TrustDomain.RekorStateId
                },
                ["candidateManifest"] = ReadGoJson(
                    Path.Combine(
                        Path.GetDirectoryName(path)!,
                        "..",
                        "generations",
                        journal.Candidate.GenerationId,
                        "manifest.json"))
            };
            WriteGoJson(path, document);
        }

        private static void AddIfPresent(
            Dictionary<string, object?> document,
            string name,
            string? value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                document[name] = value;
            }
        }

        private static JsonElement ReadGoJson(string path)
            => JsonDocument
                .Parse(File.ReadAllBytes(Path.GetFullPath(path)))
                .RootElement
                .Clone();

        private static void WriteGoJson(
            string path,
            Dictionary<string, object?> document)
        {
            if (File.Exists(path))
            {
                SetWritable(path);
                File.Delete(path);
            }
            File.WriteAllBytes(
                path,
                Encoding.UTF8.GetBytes(
                    JsonSerializer.Serialize(
                        document,
                        new JsonSerializerOptions(JsonSerializerDefaults.Web)
                        {
                            WriteIndented = true
                        })
                    + "\n"));
        }

        private static string GoTimestamp(DateTimeOffset value)
            => value.ToUniversalTime()
                .ToString("yyyy-MM-ddTHH:mm:ss.FFFFFFFZ");

        private static void WriteCanonical<T>(string path, T value)
        {
            if (File.Exists(path))
            {
                SetWritable(path);
                File.Delete(path);
            }
            File.WriteAllBytes(
                path,
                Encoding.UTF8.GetBytes(
                    JsonSerializer.Serialize(value, CanonicalOptions) + "\n"));
        }

        private static void CopyTree(string source, string destination)
        {
            Directory.CreateDirectory(destination);
            foreach (var directory in Directory.EnumerateDirectories(
                source,
                "*",
                SearchOption.AllDirectories))
            {
                Directory.CreateDirectory(
                    Path.Combine(
                        destination,
                        Path.GetRelativePath(source, directory)));
            }
            foreach (var file in Directory.EnumerateFiles(
                source,
                "*",
                SearchOption.AllDirectories))
            {
                File.Copy(
                    file,
                    Path.Combine(
                        destination,
                        Path.GetRelativePath(source, file)));
            }
        }

        private static SortedDictionary<string, string> CollectHashes(
            string generationPath)
        {
            var hashes = new SortedDictionary<string, string>(
                StringComparer.Ordinal);
            foreach (var directory in new[] { "private", "public" })
            {
                foreach (var file in Directory.EnumerateFiles(
                    Path.Combine(generationPath, directory),
                    "*",
                    SearchOption.AllDirectories))
                {
                    hashes.Add(
                        Path.GetRelativePath(generationPath, file)
                            .Replace(Path.DirectorySeparatorChar, '/'),
                        Sha256(File.ReadAllBytes(file)));
                }
            }
            return hashes;
        }

        private static string Resolve(string root, string relative)
            => Path.Combine(
                root,
                relative.Replace('/', Path.DirectorySeparatorChar));

        private static void SetReadOnly(string path)
        {
            if (OperatingSystem.IsWindows())
            {
                File.SetAttributes(
                    path,
                    File.GetAttributes(path) | FileAttributes.ReadOnly);
                return;
            }
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead
                | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead);
        }

        private static void SetWritable(string path)
        {
            if (OperatingSystem.IsWindows())
            {
                File.SetAttributes(
                    path,
                    File.GetAttributes(path) & ~FileAttributes.ReadOnly);
                return;
            }
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }

        private static string Sha256(byte[] bytes)
            => Convert.ToHexString(SHA256.HashData(bytes))
                .ToLowerInvariant();
    }

    private static string CreateUnrelatedRootPem(string workingDirectory)
    {
        var unrelatedPath = Path.Combine(
            workingDirectory,
            "unrelated-candidate");
        var material = SigstoreStateBootstrapper
            .EnsureFulcioCaRotationCandidate(unrelatedPath);
        Assert.NotNull(material);
        var certificate = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                Path.Combine(
                    unrelatedPath,
                    "public",
                    "fulcio",
                    "root.pem")));
        return certificate.ExportCertificatePem() + "\n";
    }

    private static string CtLogPublicKeySha256(string statePath)
    {
        using var key = ECDsa.Create();
        key.ImportFromPem(
            File.ReadAllText(
                Path.Combine(
                    statePath,
                    "active-generation",
                    "public",
                    "ctlog",
                    "pubkey.pem")));
        return Convert.ToHexString(
                SHA256.HashData(key.ExportSubjectPublicKeyInfo()))
            .ToLowerInvariant();
    }

    private static string Fingerprint(string path)
        => Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)))
            .ToLowerInvariant();

    private static void AssertSameBytes(string expected, string actual)
        => Assert.Equal(
            Convert.ToHexString(File.ReadAllBytes(expected)),
            Convert.ToHexString(File.ReadAllBytes(actual)));

    private static string[] EntryNames(string directory)
        => Directory.EnumerateFileSystemEntries(directory)
            .Select(Path.GetFileName)
            .Order(StringComparer.Ordinal)
            .ToArray()!;

    private static string[] RelativeFiles(string root)
        => Directory.EnumerateFiles(
                root,
                "*",
                SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(root, path)
                .Replace(Path.DirectorySeparatorChar, '/'))
            .Order(StringComparer.Ordinal)
            .ToArray();

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-fulcio-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            Directory.Delete(Path, recursive: true);
        }
    }
}
