using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace Sigstore.Bootstrap;

internal static partial class SigstoreStateBootstrapper
{
    private const int TrustStateSchemaVersion = 5;
    private const int TransitionSchemaVersion = 1;
    private const int InitialGeneration = 1;
    private const string InitialGenerationId = "generation-00000001";
    private const string TrustDomainFileName = "trust-domain.json";
    private const string ActiveGenerationName = "active-generation";
    private const string GenerationsDirectoryName = "generations";
    private const string TransitionDirectoryName = "transition";
    private const string MigrationDirectoryName = "migration";
    private const string GenerationManifestFileName = "manifest.json";
    private const string TransitionStateFileName = "state.json";
    private const string LegacyManifestArchiveFileName =
        "bootstrap-manifest.schema-4.json";
    private const string LegacyLockFileName = ".bootstrap.lock";
    private const string TransitionStatusStaged = "staged";
    private const string TransitionStatusCommitted = "committed";
    private const string TransitionStatusFailed = "failed";
    private const string TransitionStatusRecovered = "recovered";
    private const string BootstrapOperation = "bootstrap";
    private const string MigrationOperation = "migrate-schema-4";
    private const string OidcRotationOperation = "oidc-rotation";
    private const string TsaRotationOperation = "tsa-rotation";
    private const string FulcioRotationOperation = "fulcio-rotation";
    private const string GenerationAdvanceOperation = "generation-advance";
    private const string OidcRotationDirectoryName = "oidc-rotation";
    private const string TsaRotationDirectoryName = "tsa-rotation";
    private const string FulcioRotationDirectoryName = "fulcio-rotation";
    private const string OidcRotationCompletionFileName =
        "rotate-oidc-signing-key.completed";
    private const string TsaRotationCompletionFileName =
        "rotate-timestamp-authority.completed";
    private const string TsaRotationRequestFileName =
        "rotate-timestamp-authority.request";
    private const string FulcioRotationCompletionFileName =
        "rotate-fulcio-ca.completed";
    private const string FulcioRotationRequestFileName =
        "rotate-fulcio-ca.request";
    private const string RuntimeDirectoryName = "runtime";
    private const string RuntimeFulcioComponentName = "fulcio";
    private const string RuntimeFulcioStagedComponentName = "fulcio.next";
    private const string RuntimeTesseractComponentName = "tesseract";
    private const string RuntimeFulcioRootCertificateFileName = "root.pem";
    private const string RuntimeFulcioRootKeyFileName = "root.key";
    private const string RuntimeFulcioPasswordFileName = "password";
    private const string RuntimeFulcioCtLogPublicKeyFileName = "ctlog.pub";
    private const string RuntimeTesseractPrivateKeyFileName = "privkey.pem";
    private const string RuntimeAcceptedRootsFileName = "accepted-roots.pem";

    private static readonly string[] RuntimeFulcioFileNames =
    [
        RuntimeFulcioCtLogPublicKeyFileName,
        RuntimeFulcioPasswordFileName,
        RuntimeFulcioRootKeyFileName,
        RuntimeFulcioRootCertificateFileName
    ];

    private static readonly string[] RuntimeTesseractFileNames =
    [
        RuntimeAcceptedRootsFileName,
        RuntimeTesseractPrivateKeyFileName
    ];

    private static readonly string[] GenerationMaterialFiles =
        LegacyRequiredStateFiles
            .Where(path =>
                path.StartsWith(
                    "private/",
                    StringComparison.Ordinal)
                || path.StartsWith(
                    "public/",
                    StringComparison.Ordinal))
            .Order(StringComparer.Ordinal)
            .ToArray();

    private sealed record TrustStateLayout(
        string Root,
        string TrustDomain,
        string TrustDomainPending,
        string ActiveGeneration,
        string ActiveGenerationNext,
        string Generations,
        string Generation,
        string Transition,
        string Candidate,
        string TransitionState,
        string Migration,
        string LegacyManifest,
        string LegacyManifestArchive,
        string Runtime,
        string RuntimeFulcio,
        string RuntimeFulcioStaged,
        string RuntimeTesseract);

    private static BootstrapResult EnsureTrustStateLocked(
        string rootPath,
        TrustStateOperationOptions options)
    {
        var layout = CreateTrustStateLayout(rootPath);
        var hasJournal = File.Exists(layout.TransitionState);
        var hasLegacyManifest = File.Exists(layout.LegacyManifest);
        var hasCurrentState =
            File.Exists(layout.TrustDomain)
            || PathExists(layout.ActiveGeneration)
            || Directory.Exists(layout.Generations)
            || Directory.Exists(layout.Transition);

        if (hasJournal)
        {
            return ResumeOrReuseCurrentState(
                layout,
                options);
        }

        if (hasLegacyManifest)
        {
            if (hasCurrentState)
            {
                throw new InvalidDataException(
                    "Sigstore state contains schema-4 and generation-aware " +
                    "metadata without a transition journal.");
            }

            return MigrateLegacyState(
                layout,
                options);
        }

        if (hasCurrentState)
        {
            throw new InvalidDataException(
                "Generation-aware Sigstore state is incomplete because its " +
                "transition journal is missing.");
        }

        return CreateFreshTrustState(
            layout,
            options);
    }

    private static BootstrapResult CreateFreshTrustState(
        TrustStateLayout layout,
        TrustStateOperationOptions options)
    {
        EnsureFreshRootIsEmpty(layout);
        EnsureTrustStateLayout(layout);
        Directory.CreateDirectory(layout.Candidate);

        BootstrapManifest projection;
        try
        {
            projection = GenerateLegacyState(
                layout.Root,
                layout.Candidate,
                writeManifest: false);
        }
        catch (Exception exception) when (
            exception is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or InvalidOperationException
            or CryptographicException)
        {
            CleanupFreshUnjournaledScratch(layout);
            throw;
        }

        var domain = CreateTrustDomainManifest(projection);
        var generation = CreateGenerationManifest(
            projection,
            domain,
            sourceSchemaVersion: TrustStateSchemaVersion,
            sourceManifestSha256: null,
            CollectGenerationFileHashes(layout.Candidate));
        WriteImmutableJson(
            Path.Combine(
                layout.Candidate,
                GenerationManifestFileName),
            generation);

        var journal = CreateTransitionJournal(
            BootstrapOperation,
            domain,
            generation,
            legacyManifestSha256: null);
        WriteTransitionJournal(
            layout,
            journal);
        journal = RecordCheckpoint(
            layout,
            journal,
            TrustTransitionCheckpoint.JournalStaged,
            options);

        return ExecuteTransition(
            layout,
            journal,
            options,
            recovering: false,
            BootstrapAction.Created);
    }

    private static BootstrapResult MigrateLegacyState(
        TrustStateLayout layout,
        TrustStateOperationOptions options)
    {
        ValidateLegacyRootEntries(layout);
        var projection = ValidateLegacyState(layout.Root);
        ValidateLegacyMaterialFileSet(layout.Root);
        var legacyBytes = File.ReadAllBytes(layout.LegacyManifest);
        var legacyManifestSha256 = Fingerprint(legacyBytes);

        var domain = CreateTrustDomainManifest(projection);
        var generation = CreateGenerationManifest(
            projection,
            domain,
            LegacySchemaVersion,
            legacyManifestSha256,
            CollectGenerationFileHashes(layout.Root));

        EnsureTrustStateLayout(layout);
        var journal = CreateTransitionJournal(
            MigrationOperation,
            domain,
            generation,
            legacyManifestSha256);
        WriteTransitionJournal(
            layout,
            journal);
        journal = RecordCheckpoint(
            layout,
            journal,
            TrustTransitionCheckpoint.JournalStaged,
            options);

        return ExecuteTransition(
            layout,
            journal,
            options,
            recovering: false,
            BootstrapAction.Migrated);
    }

    private static BootstrapResult ResumeOrReuseCurrentState(
        TrustStateLayout layout,
        TrustStateOperationOptions options)
    {
        var journal = ReadTransitionJournal(layout);
        ValidateTransitionJournal(journal);

        if (journal.Status is TransitionStatusStaged
            or TransitionStatusFailed
            || journal.LastCheckpoint != CheckpointName(
                TrustTransitionCheckpoint.TransitionFinalized))
        {
            return ExecuteTransition(
                layout,
                journal,
                options,
                recovering: true,
                BootstrapAction.Recovered);
        }

        if (journal.Status is not (
            TransitionStatusCommitted
            or TransitionStatusRecovered))
        {
            throw new InvalidDataException(
                $"Trust transition status '{journal.Status}' is unsupported.");
        }

        return ValidateCurrentTrustState(
            layout,
            BootstrapAction.Reused);
    }

    private static BootstrapResult ExecuteTransition(
        TrustStateLayout layout,
        TrustTransitionJournal journal,
        TrustStateOperationOptions options,
        bool recovering,
        BootstrapAction completedAction)
    {
        try
        {
            journal = ApplyTransition(
                layout,
                journal,
                options,
                recovering);
            return ValidateCurrentTrustState(
                layout,
                completedAction);
        }
        catch (TrustTransitionInterruptedException)
        {
            throw;
        }
        catch (Exception exception) when (
            exception is IOException
            or UnauthorizedAccessException
            or InvalidDataException
            or InvalidOperationException
            or CryptographicException)
        {
            MarkTransitionFailed(
                layout,
                exception);
            throw;
        }
    }

    private static TrustTransitionJournal ApplyTransition(
        TrustStateLayout layout,
        TrustTransitionJournal journal,
        TrustStateOperationOptions options,
        bool recovering)
    {
        EnsureTrustStateLayout(layout);
        var generationCommitted = Directory.Exists(layout.Generation);

        if (!generationCommitted)
        {
            EnsureCandidateDirectory(layout);
            journal = RecordCheckpoint(
                layout,
                journal,
                TrustTransitionCheckpoint.CandidateDirectoryCreated,
                options);

            EnsureMaterialStaged(
                layout,
                journal,
                "private");
            journal = RecordCheckpoint(
                layout,
                journal,
                TrustTransitionCheckpoint.PrivateMaterialStaged,
                options);

            EnsureMaterialStaged(
                layout,
                journal,
                "public");
            journal = RecordCheckpoint(
                layout,
                journal,
                TrustTransitionCheckpoint.PublicMaterialStaged,
                options);

            EnsureGenerationManifestStaged(
                layout,
                journal);
            journal = RecordCheckpoint(
                layout,
                journal,
                TrustTransitionCheckpoint.GenerationManifestStaged,
                options);
        }
        else
        {
            if (Directory.Exists(layout.Candidate))
            {
                throw new InvalidDataException(
                    "The candidate generation exists in both staged and " +
                    "committed locations.");
            }

            ValidateGenerationDirectory(
                layout.Generation,
                journal.CandidateManifest,
                journal.Candidate.ManifestSha256);
        }

        EnsureTrustDomainPrepared(
            layout,
            journal);
        journal = RecordCheckpoint(
            layout,
            journal,
            TrustTransitionCheckpoint.TrustDomainPrepared,
            options);

        CommitTrustDomain(
            layout,
            journal);
        journal = RecordCheckpoint(
            layout,
            journal,
            TrustTransitionCheckpoint.TrustDomainCommitted,
            options);

        CommitGeneration(
            layout,
            journal);
        journal = RecordCheckpoint(
            layout,
            journal,
            TrustTransitionCheckpoint.GenerationCommitted,
            options);

        PrepareActiveGenerationLink(
            layout,
            journal);
        journal = RecordCheckpoint(
            layout,
            journal,
            TrustTransitionCheckpoint.ActiveLinkPrepared,
            options);

        CommitActiveGenerationLink(
            layout,
            journal);
        journal = RecordCheckpoint(
            layout,
            journal,
            TrustTransitionCheckpoint.ActiveGenerationSwitched,
            options);

        EnsureRuntimeProjection(
            layout,
            Path.Combine(
                layout.Generations,
                journal.Candidate.GenerationId),
            journal.CandidateManifest);

        journal = RecordCheckpoint(
            layout,
            journal with
            {
                Status = TransitionStatusCommitted,
                Failure = null
            },
            TrustTransitionCheckpoint.TransitionCommitted,
            options);

        ArchiveLegacyManifest(
            layout,
            journal);
        journal = RecordCheckpoint(
            layout,
            journal,
            TrustTransitionCheckpoint.LegacyManifestArchived,
            options);

        RemoveLegacyLock(layout);
        ValidateTransitionContents(
            layout,
            journal);

        return RecordCheckpoint(
            layout,
            journal with
            {
                Status = recovering
                    ? TransitionStatusRecovered
                    : TransitionStatusCommitted,
                Failure = null
            },
            TrustTransitionCheckpoint.TransitionFinalized,
            options);
    }

    private static TrustTransitionJournal CreateTransitionJournal(
        string operation,
        TrustDomainManifest domain,
        GenerationManifest generation,
        string? legacyManifestSha256)
    {
        var generationManifestSha256 = HashSerialized(generation);
        var domainManifestSha256 = HashSerialized(domain);
        var now = DateTimeOffset.UtcNow;
        var transitionIdentity = legacyManifestSha256
            ?? domain.TrustDomainId["sha256-".Length..];

        return new TrustTransitionJournal(
            TransitionSchemaVersion,
            $"{operation}-{transitionIdentity}",
            operation,
            TransitionStatusStaged,
            "created",
            now,
            now,
            PriorGeneration: null,
            new GenerationReference(
                generation.Generation,
                generation.GenerationId,
                generationManifestSha256),
            domainManifestSha256,
            legacyManifestSha256,
            domain,
            generation,
            Failure: null);
    }

    private static TrustTransitionJournal RecordCheckpoint(
        TrustStateLayout layout,
        TrustTransitionJournal journal,
        TrustTransitionCheckpoint checkpoint,
        TrustStateOperationOptions options)
    {
        var updated = journal with
        {
            LastCheckpoint = CheckpointName(checkpoint),
            UpdatedAtUtc = DateTimeOffset.UtcNow
        };
        WriteTransitionJournal(
            layout,
            updated);
        options.Checkpoint?.Invoke(checkpoint);
        return updated;
    }

    private static void MarkTransitionFailed(
        TrustStateLayout layout,
        Exception failure)
    {
        if (!File.Exists(layout.TransitionState))
        {
            return;
        }

        var journal = ReadTransitionJournal(layout);
        var failed = journal with
        {
            Status = TransitionStatusFailed,
            UpdatedAtUtc = DateTimeOffset.UtcNow,
            Failure = $"{failure.GetType().Name}: {failure.Message}"
        };
        WriteTransitionJournal(
            layout,
            failed);
    }

    private static BootstrapResult ValidateCurrentTrustState(
        TrustStateLayout layout,
        BootstrapAction action)
    {
        var journal = ReadTransitionJournal(layout);
        ValidateTransitionJournal(journal);
        if (journal.Status is not (
            TransitionStatusCommitted
            or TransitionStatusRecovered)
            || journal.LastCheckpoint != CheckpointName(
                TrustTransitionCheckpoint.TransitionFinalized))
        {
            throw new InvalidDataException(
                "The trust transition has not reached a stable state.");
        }

        var domain = ReadPortableJson<TrustDomainManifest>(
            layout.TrustDomain);
        ValidateTrustDomain(
            layout,
            domain);
        var domainHash = HashFile(layout.TrustDomain);
        EnsureEqual(
            "trust-domain manifest hash",
            journal.TrustDomainManifestSha256,
            domainHash);
        if (!TrustDomainManifestsEqual(journal.TrustDomain, domain))
        {
            throw new InvalidDataException(
                "The journaled trust domain does not match the immutable " +
                "trust-domain manifest.");
        }

        var activeGeneration = ReadActiveGeneration(
            layout.ActiveGeneration);
        EnsureEqual(
            "active generation",
            journal.Candidate.GenerationId,
            activeGeneration);

        var generationPath = Path.Combine(
            layout.Generations,
            activeGeneration);
        var generation = ReadPortableJson<GenerationManifest>(
            Path.Combine(
                generationPath,
                GenerationManifestFileName));
        ValidateGenerationDirectory(
            generationPath,
            generation,
            journal.Candidate.ManifestSha256);
        ValidateGenerationIdentity(
            domain,
            generation);
        ValidateGenerationCryptography(
            layout.Root,
            generationPath,
            generation);
        ValidateLegacyArchive(
            layout,
            generation);
        ValidateRuntimeProjection(
            layout,
            generationPath,
            generation);
        ValidateCurrentRootEntries(layout, generation);

        // The journal binds the candidate by the SHA-256 of the manifest
        // bytes actually on disk, never by a re-serialization: the Go worker
        // writes these manifests and its encoder is not byte-identical to the
        // C# one. ValidateGenerationDirectory already asserted the file hash,
        // so what remains is that the journaled copy says the same thing.
        if (!GenerationManifestsEqual(journal.CandidateManifest, generation))
        {
            throw new InvalidDataException(
                "The active generation does not match the transition journal.");
        }

        return new BootstrapResult(
            action,
            domain,
            generation);
    }

    private static void ValidateTransitionContents(
        TrustStateLayout layout,
        TrustTransitionJournal journal)
    {
        ValidateTransitionJournal(journal);
        ValidateTrustDomain(
            layout,
            journal.TrustDomain);
        EnsureEqual(
            "trust-domain manifest hash",
            journal.TrustDomainManifestSha256,
            HashFile(layout.TrustDomain));
        if (!TrustDomainManifestsEqual(
                journal.TrustDomain,
                ReadPortableJson<TrustDomainManifest>(layout.TrustDomain)))
        {
            throw new InvalidDataException(
                "The journaled trust domain does not match the immutable " +
                "trust-domain manifest.");
        }
        ValidateGenerationDirectory(
            Path.Combine(
                layout.Generations,
                journal.Candidate.GenerationId),
            journal.CandidateManifest,
            journal.Candidate.ManifestSha256);
        EnsureEqual(
            "active generation",
            journal.Candidate.GenerationId,
            ReadActiveGeneration(layout.ActiveGeneration));
        ValidateRuntimeProjection(
            layout,
            Path.Combine(
                layout.Generations,
                journal.Candidate.GenerationId),
            journal.CandidateManifest);
        ValidateLegacyArchive(
            layout,
            journal.CandidateManifest);
    }

    private static void ValidateTransitionJournal(
        TrustTransitionJournal journal)
    {
        if (journal.SchemaVersion != TransitionSchemaVersion)
        {
            throw new InvalidDataException(
                $"Trust transition schema {journal.SchemaVersion} is not " +
                $"supported; expected {TransitionSchemaVersion}.");
        }
        if (journal.Operation is not (
            BootstrapOperation
            or MigrationOperation
            or OidcRotationOperation
            or TsaRotationOperation
            or FulcioRotationOperation
            or GenerationAdvanceOperation))
        {
            throw new InvalidDataException(
                $"Trust transition operation '{journal.Operation}' is " +
                "unsupported.");
        }
        if (journal.Status is not (
            TransitionStatusStaged
            or TransitionStatusCommitted
            or TransitionStatusFailed
            or TransitionStatusRecovered))
        {
            throw new InvalidDataException(
                $"Trust transition status '{journal.Status}' is unsupported.");
        }
        if (journal.Operation is BootstrapOperation or MigrationOperation
            && journal.PriorGeneration is not null)
        {
            throw new InvalidDataException(
                "Initial trust transitions cannot reference a prior generation.");
        }
        if (journal.Operation is OidcRotationOperation
            or TsaRotationOperation
            or FulcioRotationOperation
            or GenerationAdvanceOperation)
        {
            if (journal.PriorGeneration is null)
            {
                throw new InvalidDataException(
                    "Generation advance must reference its prior generation.");
            }
            ValidateGenerationReference(journal.PriorGeneration);
            if (journal.Candidate.Generation
                    != journal.PriorGeneration.Generation + 1)
            {
                throw new InvalidDataException(
                    "Generation advance must be exactly sequential.");
            }
        }
        ValidateGenerationReference(journal.Candidate);
        ValidateGenerationIdentity(
            journal.TrustDomain,
            journal.CandidateManifest);
        EnsureEqual(
            "journaled candidate generation",
            journal.Candidate.GenerationId,
            journal.CandidateManifest.GenerationId);
        // Both manifest hashes are hashes of the immutable files on disk, so
        // they are validated for shape here and bound to the real bytes where
        // those files are read. Re-serializing the journaled copies to compare
        // hashes would only be valid for C#-written state.
        ValidateSha256(
            journal.TrustDomainManifestSha256,
            "journaled trust-domain manifest");
        if (journal.Operation == MigrationOperation)
        {
            ValidateSha256(
                journal.LegacyManifestSha256,
                "legacy bootstrap manifest");
        }
        else if (journal.Operation == BootstrapOperation
            && journal.LegacyManifestSha256 is not null)
        {
            throw new InvalidDataException(
                "A fresh bootstrap transition cannot reference a legacy " +
                "manifest.");
        }
    }

    private static void ValidateGenerationReference(
        GenerationReference reference)
    {
        if (reference.Generation < InitialGeneration
            || reference.GenerationId != GenerationId(reference.Generation))
        {
            throw new InvalidDataException(
                "Generation reference has an invalid number or ID.");
        }
        ValidateSha256(
            reference.ManifestSha256,
            "generation manifest");
    }

    private static void EnsureCandidateDirectory(
        TrustStateLayout layout)
    {
        if (PathExists(layout.Candidate))
        {
            EnsureRealDirectory(
                layout.Candidate,
                "candidate generation");
            return;
        }

        Directory.CreateDirectory(layout.Candidate);
    }

    private static void EnsureMaterialStaged(
        TrustStateLayout layout,
        TrustTransitionJournal journal,
        string directoryName)
    {
        var source = Path.Combine(
            layout.Root,
            directoryName);
        var destination = Path.Combine(
            layout.Candidate,
            directoryName);
        var sourceExists = Directory.Exists(source);
        var destinationExists = Directory.Exists(destination);
        if (sourceExists && destinationExists)
        {
            throw new InvalidDataException(
                $"Generation {directoryName} material exists in both legacy " +
                "and staged locations.");
        }
        if (sourceExists)
        {
            Directory.Move(
                source,
                destination);
            destinationExists = true;
        }
        if (!destinationExists)
        {
            throw new InvalidDataException(
                $"Generation {directoryName} material is missing.");
        }

        ValidateMaterialDirectory(
            destination,
            directoryName,
            journal.CandidateManifest.Files);
    }

    private static void EnsureGenerationManifestStaged(
        TrustStateLayout layout,
        TrustTransitionJournal journal)
    {
        var path = Path.Combine(
            layout.Candidate,
            GenerationManifestFileName);
        if (!File.Exists(path))
        {
            WriteImmutableJson(
                path,
                journal.CandidateManifest);
        }

        ValidateGenerationDirectory(
            layout.Candidate,
            journal.CandidateManifest,
            journal.Candidate.ManifestSha256);
    }

    private static void EnsureTrustDomainPrepared(
        TrustStateLayout layout,
        TrustTransitionJournal journal)
    {
        if (File.Exists(layout.TrustDomain))
        {
            ValidateImmutableTrustDomain(
                layout.TrustDomain,
                journal.TrustDomain,
                journal.TrustDomainManifestSha256);
            if (File.Exists(layout.TrustDomainPending))
            {
                ValidateImmutableTrustDomain(
                    layout.TrustDomainPending,
                    journal.TrustDomain,
                    journal.TrustDomainManifestSha256);
                File.Delete(layout.TrustDomainPending);
            }
            return;
        }

        if (!File.Exists(layout.TrustDomainPending))
        {
            WriteImmutableJson(
                layout.TrustDomainPending,
                journal.TrustDomain);
        }
        ValidateImmutableTrustDomain(
            layout.TrustDomainPending,
            journal.TrustDomain,
            journal.TrustDomainManifestSha256);
    }

    private static void CommitTrustDomain(
        TrustStateLayout layout,
        TrustTransitionJournal journal)
    {
        if (!File.Exists(layout.TrustDomain))
        {
            File.Move(
                layout.TrustDomainPending,
                layout.TrustDomain);
        }
        ValidateImmutableTrustDomain(
            layout.TrustDomain,
            journal.TrustDomain,
            journal.TrustDomainManifestSha256);
    }

    private static void CommitGeneration(
        TrustStateLayout layout,
        TrustTransitionJournal journal)
    {
        var candidateExists = Directory.Exists(layout.Candidate);
        var generationExists = Directory.Exists(layout.Generation);
        if (candidateExists && generationExists)
        {
            throw new InvalidDataException(
                "The initial generation exists in both staged and committed " +
                "locations.");
        }
        if (candidateExists)
        {
            Directory.Move(
                layout.Candidate,
                layout.Generation);
            generationExists = true;
        }
        if (!generationExists)
        {
            throw new InvalidDataException(
                "The initial generation is missing.");
        }

        ValidateGenerationDirectory(
            layout.Generation,
            journal.CandidateManifest,
            journal.Candidate.ManifestSha256);
    }

    private static void PrepareActiveGenerationLink(
        TrustStateLayout layout,
        TrustTransitionJournal journal)
    {
        var expectedTarget = Path.Combine(
            GenerationsDirectoryName,
            journal.Candidate.GenerationId);
        if (PathExists(layout.ActiveGenerationNext))
        {
            EnsureEqual(
                "prepared active-generation link",
                expectedTarget,
                ReadRelativeLink(layout.ActiveGenerationNext));
            return;
        }
        if (PathExists(layout.ActiveGeneration))
        {
            EnsureEqual(
                "active generation",
                journal.Candidate.GenerationId,
                ReadActiveGeneration(layout.ActiveGeneration));
            return;
        }

        Directory.CreateSymbolicLink(
            layout.ActiveGenerationNext,
            expectedTarget);
    }

    private static void CommitActiveGenerationLink(
        TrustStateLayout layout,
        TrustTransitionJournal journal)
    {
        if (PathExists(layout.ActiveGeneration))
        {
            EnsureEqual(
                "active generation",
                journal.Candidate.GenerationId,
                ReadActiveGeneration(layout.ActiveGeneration));
            if (PathExists(layout.ActiveGenerationNext))
            {
                var expectedTarget = Path.Combine(
                    GenerationsDirectoryName,
                    journal.Candidate.GenerationId);
                EnsureEqual(
                    "prepared active-generation link",
                    expectedTarget,
                    ReadRelativeLink(layout.ActiveGenerationNext));
                Directory.Delete(layout.ActiveGenerationNext);
            }
            return;
        }

        Directory.Move(
            layout.ActiveGenerationNext,
            layout.ActiveGeneration);
        EnsureEqual(
            "active generation",
            journal.Candidate.GenerationId,
            ReadActiveGeneration(layout.ActiveGeneration));
    }

    private static void ArchiveLegacyManifest(
        TrustStateLayout layout,
        TrustTransitionJournal journal)
    {
        if (journal.Operation != MigrationOperation)
        {
            if (File.Exists(layout.LegacyManifest)
                || File.Exists(layout.LegacyManifestArchive))
            {
                throw new InvalidDataException(
                    "Fresh generation-aware state unexpectedly contains a " +
                    "schema-4 manifest.");
            }
            return;
        }

        var legacyExists = File.Exists(layout.LegacyManifest);
        var archiveExists = File.Exists(layout.LegacyManifestArchive);
        if (legacyExists && archiveExists)
        {
            throw new InvalidDataException(
                "The schema-4 bootstrap manifest exists in both active and " +
                "archived locations.");
        }
        if (legacyExists)
        {
            EnsureEqual(
                "schema-4 bootstrap manifest hash",
                journal.LegacyManifestSha256!,
                HashFile(layout.LegacyManifest));
            File.Move(
                layout.LegacyManifest,
                layout.LegacyManifestArchive);
            SetReadOnly(layout.LegacyManifestArchive);
            archiveExists = true;
        }
        if (!archiveExists)
        {
            throw new InvalidDataException(
                "The schema-4 bootstrap manifest is missing during migration.");
        }
        SetReadOnly(layout.LegacyManifestArchive);
        EnsureEqual(
            "archived schema-4 bootstrap manifest hash",
            journal.LegacyManifestSha256!,
            HashFile(layout.LegacyManifestArchive));
    }

    private static void RemoveLegacyLock(
        TrustStateLayout layout)
    {
        var path = Path.Combine(
            layout.Root,
            LegacyLockFileName);
        if (!PathExists(path))
        {
            return;
        }
        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.Directory)
            || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                $"Legacy state lock '{path}' is not a regular file.");
        }
        File.Delete(path);
    }

    private static TrustDomainManifest CreateTrustDomainManifest(
        BootstrapManifest projection)
    {
        var identity = string.Join(
            "\n",
            projection.CreatedAtUtc
                .ToUniversalTime()
                .ToString("O", CultureInfo.InvariantCulture),
            projection.CtLogStateId,
            projection.RekorStateId);
        var id = "sha256-" + Fingerprint(
            Encoding.UTF8.GetBytes(identity));
        return new TrustDomainManifest(
            TrustStateSchemaVersion,
            id,
            projection.CreatedAtUtc,
            projection.CtLogStateId,
            projection.RekorStateId);
    }

    private static GenerationManifest CreateGenerationManifest(
        BootstrapManifest projection,
        TrustDomainManifest domain,
        int sourceSchemaVersion,
        string? sourceManifestSha256,
        SortedDictionary<string, string> files)
        => new(
            TrustStateSchemaVersion,
            InitialGeneration,
            InitialGenerationId,
            domain.TrustDomainId,
            projection.CreatedAtUtc,
            sourceSchemaVersion,
            sourceManifestSha256,
            projection.FulcioRootSha256,
            projection.CtLogPublicKeySha256,
            projection.RekorPublicKeySha256,
            projection.TsaRootSha256,
            projection.TsaLeafSha256,
            projection.OidcKeyId,
            null,
            0,
            null,
            null,
            null,
            null,
            null,
            0,
            null,
            null,
            null,
            null,
            0,
            null,
            null,
            files);

    private static void ValidateTrustDomain(
        TrustStateLayout layout,
        TrustDomainManifest domain)
    {
        if (domain.SchemaVersion != TrustStateSchemaVersion)
        {
            throw new InvalidDataException(
                $"Trust-domain schema {domain.SchemaVersion} is unsupported; " +
                $"expected {TrustStateSchemaVersion}.");
        }
        var expected = CreateTrustDomainManifest(
            new BootstrapManifest(
                LegacySchemaVersion,
                domain.CreatedAtUtc,
                domain.CtLogStateId,
                domain.RekorStateId,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty));
        EnsureEqual(
            "trust-domain ID",
            expected.TrustDomainId,
            domain.TrustDomainId);
        EnsureEqual(
            "CT log state ID",
            domain.CtLogStateId,
            File.ReadAllText(
                Resolve(
                    layout.Root,
                    CtLogStateMarkerPath)));
        EnsureEqual(
            "Rekor state ID",
            domain.RekorStateId,
            File.ReadAllText(
                Resolve(
                    layout.Root,
                    RekorStateMarkerPath)));
        ValidateCtLogRuntimeState(layout.Root);
        ValidateRuntimeState(
            layout.Root,
            "Rekor",
            "data/rekor");
    }

    private static void ValidateGenerationIdentity(
        TrustDomainManifest domain,
        GenerationManifest generation)
    {
        if (generation.SchemaVersion != TrustStateSchemaVersion)
        {
            throw new InvalidDataException(
                $"Generation schema {generation.SchemaVersion} is unsupported; " +
                $"expected {TrustStateSchemaVersion}.");
        }
        if (generation.Generation < InitialGeneration
            || generation.GenerationId != GenerationId(generation.Generation))
        {
            throw new InvalidDataException(
                "Generation number and generation ID are inconsistent.");
        }
        EnsureEqual(
            "generation trust-domain ID",
            domain.TrustDomainId,
            generation.TrustDomainId);
        if (generation.Generation == InitialGeneration
            && generation.CreatedAtUtc != domain.CreatedAtUtc)
        {
            throw new InvalidDataException(
                "The initial generation creation time does not match the " +
                "trust-domain creation time.");
        }
        if (generation.SourceSchemaVersion is not (
            LegacySchemaVersion
            or TrustStateSchemaVersion))
        {
            throw new InvalidDataException(
                $"Generation source schema {generation.SourceSchemaVersion} " +
                "is unsupported.");
        }
        if (generation.SourceSchemaVersion == LegacySchemaVersion)
        {
            ValidateSha256(
                generation.SourceManifestSha256,
                "source schema-4 manifest");
        }
        else if (generation.SourceManifestSha256 is not null)
        {
            throw new InvalidDataException(
                "A fresh generation cannot reference a schema-4 manifest.");
        }
        ValidateGenerationFileMap(generation);
        ValidateOidcRotationMetadata(generation);
        ValidateTsaRotationMetadata(generation);
        ValidateFulcioRotationMetadata(generation);
    }

    private static void ValidateGenerationCryptography(
        string stateRootPath,
        string generationPath,
        GenerationManifest generation)
    {
        EnsureEqual(
            "Fulcio root certificate",
            generation.FulcioRootSha256,
            ValidateFulcioRoot(generationPath));
        EnsureEqual(
            "CT log public key",
            generation.CtLogPublicKeySha256,
            ValidateEcdsaKeyPair(
                generationPath,
                CtLogPrivateKeyPath,
                CtLogPublicKeyPath));
        EnsureEqual(
            "Rekor public key",
            generation.RekorPublicKeySha256,
            ValidateEcdsaKeyPair(
                generationPath,
                RekorPrivateKeyPath,
                RekorPublicKeyPath));
        var tsa = ValidateTimestampAuthority(generationPath);
        if (tsa.HasRootPrivateKey
            == (generation.TsaRotationOperationId is not null))
        {
            throw new InvalidDataException(
                generation.TsaRotationOperationId is null
                    ? "A non-rotated generation is missing its TSA root key."
                    : "A rotated generation must not retain its TSA root key.");
        }
        EnsureEqual(
            "TSA root certificate",
            generation.TsaRootSha256,
            tsa.RootSha256);
        EnsureEqual(
            "TSA leaf certificate",
            generation.TsaLeafSha256,
            tsa.LeafSha256);
        EnsureEqual(
            "OIDC key ID",
            generation.OidcKeyId,
            ValidateOidcKeyPair(generationPath));
        ValidateOidcRetainedKeys(generationPath, generation);
        ValidateCtLogRuntimeState(stateRootPath);
        ValidateRuntimeState(
            stateRootPath,
            "Rekor",
            "data/rekor");
    }

    private static void ValidateGenerationDirectory(
        string generationPath,
        GenerationManifest expected,
        string expectedManifestHash)
    {
        EnsureRealDirectory(
            generationPath,
            "generation");
        var manifestPath = Path.Combine(
            generationPath,
            GenerationManifestFileName);
        ValidateImmutableGenerationManifest(
            manifestPath,
            expected,
            expectedManifestHash);
        var actualHashes = CollectGenerationFileHashes(
            generationPath);
        if (!FileMapsEqual(
                expected.Files,
                actualHashes))
        {
            throw new InvalidDataException(
                $"Generation material at '{generationPath}' does not match " +
                "its exact file manifest.");
        }
        EnsureOnlyEntries(
            generationPath,
            [
                "private",
                "public",
                GenerationManifestFileName
            ]);
    }

    private static void ValidateLegacyArchive(
        TrustStateLayout layout,
        GenerationManifest generation)
    {
        if (generation.SourceSchemaVersion == LegacySchemaVersion)
        {
            if (!File.Exists(layout.LegacyManifestArchive))
            {
                throw new InvalidDataException(
                    "The archived schema-4 bootstrap manifest is missing.");
            }
            EnsureEqual(
                "archived schema-4 bootstrap manifest hash",
                generation.SourceManifestSha256!,
                HashFile(layout.LegacyManifestArchive));
            EnsureReadOnlyRegularFile(
                layout.LegacyManifestArchive,
                "archived schema-4 bootstrap manifest");
        }
        else if (File.Exists(layout.LegacyManifestArchive))
        {
            throw new InvalidDataException(
                "Fresh trust state unexpectedly contains an archived " +
                "schema-4 manifest.");
        }
    }

    private static void ValidateLegacyMaterialFileSet(
        string rootPath)
    {
        var actual = CollectGenerationFileHashes(rootPath);
        var expected = GenerationMaterialFiles;
        if (!actual.Keys.SequenceEqual(
                expected,
                StringComparer.Ordinal))
        {
            throw new InvalidDataException(
                "Schema-4 private/public material has an unexpected file set; " +
                "migration will not discard ambiguous state.");
        }
    }

    private static SortedDictionary<string, string>
        CollectGenerationFileHashes(string rootPath)
    {
        var result = new SortedDictionary<string, string>(
            StringComparer.Ordinal);
        foreach (var directoryName in new[] { "private", "public" })
        {
            var directory = Path.Combine(
                rootPath,
                directoryName);
            EnsureRealDirectory(
                directory,
                $"generation {directoryName}");
            foreach (var entry in Directory.EnumerateFileSystemEntries(
                directory,
                "*",
                SearchOption.AllDirectories))
            {
                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    throw new InvalidDataException(
                        $"Generation material '{entry}' must not be a " +
                        "symbolic link or reparse point.");
                }
                if (attributes.HasFlag(FileAttributes.Directory))
                {
                    continue;
                }
                var relative = Path.GetRelativePath(
                        rootPath,
                        entry)
                    .Replace(
                        Path.DirectorySeparatorChar,
                        '/');
                result.Add(
                    relative,
                    HashFile(entry));
            }
        }
        return result;
    }

    private static void ValidateMaterialDirectory(
        string directoryPath,
        string directoryName,
        SortedDictionary<string, string> expectedFiles)
    {
        EnsureRealDirectory(
            directoryPath,
            $"generation {directoryName}");
        var temporaryRoot = Directory.GetParent(directoryPath)?.FullName
            ?? throw new InvalidOperationException(
                $"Cannot determine generation root for '{directoryPath}'.");
        var actual = new SortedDictionary<string, string>(
            StringComparer.Ordinal);
        foreach (var entry in Directory.EnumerateFileSystemEntries(
            directoryPath,
            "*",
            SearchOption.AllDirectories))
        {
            var attributes = File.GetAttributes(entry);
            if (attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new InvalidDataException(
                    $"Generation material '{entry}' must not be a link.");
            }
            if (attributes.HasFlag(FileAttributes.Directory))
            {
                continue;
            }
            var relative = Path.GetRelativePath(
                    temporaryRoot,
                    entry)
                .Replace(
                    Path.DirectorySeparatorChar,
                    '/');
            actual.Add(
                relative,
                HashFile(entry));
        }
        var expected = new SortedDictionary<string, string>(
            expectedFiles
                .Where(pair => pair.Key.StartsWith(
                    $"{directoryName}/",
                    StringComparison.Ordinal))
                .ToDictionary(
                    pair => pair.Key,
                    pair => pair.Value,
                    StringComparer.Ordinal),
            StringComparer.Ordinal);
        if (!FileMapsEqual(expected, actual))
        {
            throw new InvalidDataException(
                $"Staged generation {directoryName} material does not match " +
                "the transition journal.");
        }
    }

    private static void ValidateGenerationFileMap(
        GenerationManifest generation)
    {
        var required = GenerationMaterialFiles.ToHashSet(StringComparer.Ordinal);
        if (generation.TsaRotationOperationId is not null)
        {
            required.Remove(TsaRootPrivateKeyPath);
        }
        var actual = generation.Files.Keys.ToHashSet(StringComparer.Ordinal);
        if (!required.IsSubsetOf(actual))
        {
            throw new InvalidDataException(
                "The generation manifest omits required private/public files.");
        }
        foreach (var path in actual.Except(required, StringComparer.Ordinal))
        {
            if (!IsRetainedOidcKeyPath(path))
            {
                throw new InvalidDataException(
                    $"The generation manifest contains unexpected file '{path}'.");
            }
        }
        foreach (var pair in generation.Files)
        {
            ValidateSha256(
                pair.Value,
                $"generation file '{pair.Key}'");
        }
    }

    private static void ValidateTsaRotationMetadata(
        GenerationManifest generation)
    {
        if (generation.TsaRotationOperationId is null)
        {
            if (generation.TsaPriorGeneration != 0
                || generation.TsaPriorGenerationId is not null
                || generation.TsaPriorRootSha256 is not null
                || generation.TsaPriorLeafSha256 is not null)
            {
                throw new InvalidDataException(
                    "Generation contains partial TSA rotation metadata.");
            }
            return;
        }

        if (!Guid.TryParseExact(
                generation.TsaRotationOperationId,
                "N",
                out _)
            || generation.TsaRotationOperationId.Any(char.IsUpper)
            || generation.TsaPriorGeneration < InitialGeneration
            || generation.TsaPriorGeneration >= generation.Generation
            || generation.TsaPriorGenerationId
                != GenerationId(generation.TsaPriorGeneration))
        {
            throw new InvalidDataException(
                "Generation contains invalid TSA rotation identity metadata.");
        }
        ValidateSha256(
            generation.TsaPriorRootSha256,
            "prior TSA root");
        ValidateSha256(
            generation.TsaPriorLeafSha256,
            "prior TSA leaf");
        if (generation.TsaPriorRootSha256 == generation.TsaRootSha256
            || generation.TsaPriorLeafSha256 == generation.TsaLeafSha256)
        {
            throw new InvalidDataException(
                "TSA rotation did not replace both chain certificates.");
        }
    }

    /// <summary>
    /// Fulcio rotation metadata is optional: generations that never rotated
    /// their certificate authority carry no rotation identity at all, and a
    /// rotated generation must carry a complete, self-consistent binding to
    /// the operation and the immutable prior generation it replaced.
    /// </summary>
    private static void ValidateFulcioRotationMetadata(
        GenerationManifest generation)
    {
        if (generation.FulcioRotationOperationId is null)
        {
            if (generation.FulcioPriorGeneration != 0
                || generation.FulcioPriorGenerationId is not null
                || generation.FulcioPriorRootSha256 is not null)
            {
                throw new InvalidDataException(
                    "Generation contains partial Fulcio rotation metadata.");
            }
            return;
        }

        if (!Guid.TryParseExact(
                generation.FulcioRotationOperationId,
                "N",
                out _)
            || generation.FulcioRotationOperationId.Any(char.IsUpper)
            || generation.FulcioPriorGeneration < InitialGeneration
            || generation.FulcioPriorGeneration >= generation.Generation
            || generation.FulcioPriorGenerationId
                != GenerationId(generation.FulcioPriorGeneration))
        {
            throw new InvalidDataException(
                "Generation contains invalid Fulcio rotation identity " +
                "metadata.");
        }
        ValidateSha256(
            generation.FulcioPriorRootSha256,
            "prior Fulcio root");
        if (generation.FulcioPriorRootSha256 == generation.FulcioRootSha256)
        {
            throw new InvalidDataException(
                "Fulcio rotation did not replace the certificate authority.");
        }
    }

    private static void ValidateOidcRotationMetadata(
            GenerationManifest generation)
        {
            if (generation.OidcRotationOperationId is null)
            {
                if (generation.OidcPriorGeneration != 0
                    || generation.OidcPriorGenerationId is not null
                    || generation.OidcPriorKeyId is not null
                    || generation.OidcOverlapExpiresAtUtc is not null)
                {
                    throw new InvalidDataException(
                        "Generation contains partial OIDC rotation metadata.");
                }
                return;
            }

            if (!Guid.TryParseExact(
                    generation.OidcRotationOperationId,
                    "N",
                    out _)
                || generation.OidcRotationOperationId.Any(char.IsUpper)
                || generation.OidcPriorGeneration != generation.Generation - 1
                || generation.OidcPriorGenerationId
                    != GenerationId(generation.OidcPriorGeneration)
                || !IsOidcKeyId(generation.OidcPriorKeyId)
                || generation.OidcOverlapExpiresAtUtc is null)
            {
                throw new InvalidDataException(
                    "Generation contains invalid OIDC rotation metadata.");
            }
        }

        private static void ValidateOidcRetainedKeys(
            string generationPath,
            GenerationManifest generation)
        {
            using var document = JsonDocument.Parse(
                File.ReadAllText(Resolve(generationPath, OidcJwksPath)));
            var keys = document.RootElement.GetProperty("keys")
                .EnumerateArray()
                .ToArray();
            var expectedPaths = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var key in keys)
            {
                var kid = key.GetProperty("kid").GetString();
                if (!IsOidcKeyId(kid) || !seen.Add(kid!))
                {
                    throw new InvalidDataException(
                        "OIDC JWKS key IDs must be unique valid SHA-256 IDs.");
                }
                EnsureEqual("OIDC key type", "RSA", key.GetProperty("kty").GetString());
                EnsureEqual("OIDC key use", "sig", key.GetProperty("use").GetString());
                EnsureEqual("OIDC algorithm", "RS256", key.GetProperty("alg").GetString());

                var parameters = new RSAParameters
                {
                    Modulus = DecodeBase64Url(key.GetProperty("n").GetString()),
                    Exponent = DecodeBase64Url(key.GetProperty("e").GetString())
                };
                using var publicKey = RSA.Create();
                try
                {
                    publicKey.ImportParameters(parameters);
                }
                catch (CryptographicException exception)
                {
                    throw new InvalidDataException(
                        $"OIDC JWK '{kid}' is not a valid RSA key.",
                        exception);
                }
                EnsureEqual(
                    "OIDC key ID",
                    kid!,
                    Base64UrlEncode(
                        SHA256.HashData(publicKey.ExportSubjectPublicKeyInfo())));

                if (kid == generation.OidcKeyId)
                {
                    continue;
                }
                var relativePath =
                    $"private/oidc/retained/signer-{kid}.key";
                expectedPaths.Add(relativePath);
                using var retained = LoadRsaKey(
                    Resolve(generationPath, relativePath));
                EnsureKeyBytesEqual(
                    $"retained OIDC key '{kid}'",
                    publicKey.ExportSubjectPublicKeyInfo(),
                    retained.ExportSubjectPublicKeyInfo());
            }

            expectedPaths.Sort(StringComparer.Ordinal);
            var actualPaths = (generation.OidcRetainedPrivateKeyPaths ?? [])
                .Order(StringComparer.Ordinal)
                .ToArray();
            if (!expectedPaths.SequenceEqual(actualPaths, StringComparer.Ordinal))
            {
                throw new InvalidDataException(
                    "OIDC retained private-key paths do not exactly match JWKS history.");
            }
        }

        private static bool IsRetainedOidcKeyPath(string path)
        {
            const string prefix = "private/oidc/retained/signer-";
            const string suffix = ".key";
            return path.StartsWith(prefix, StringComparison.Ordinal)
                && path.EndsWith(suffix, StringComparison.Ordinal)
                && IsOidcKeyId(
                    path[prefix.Length..^suffix.Length]);
        }

        private static bool IsOidcKeyId(string? keyId) =>
            keyId is { Length: 43 }
            && keyId.All(character =>
                char.IsAsciiLetterOrDigit(character)
                || character is '-' or '_');

        private static byte[] DecodeBase64Url(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                throw new InvalidDataException(
                    "OIDC JWK contains an empty key parameter.");
            }
            var padded = value.Replace('-', '+').Replace('_', '/');
            padded += (padded.Length % 4) switch
            {
                0 => string.Empty,
                2 => "==",
                3 => "=",
                _ => throw new InvalidDataException(
                    "OIDC JWK contains invalid base64url data.")
            };
            try
            {
                return Convert.FromBase64String(padded);
            }
            catch (FormatException exception)
            {
                throw new InvalidDataException(
                    "OIDC JWK contains invalid base64url data.",
                    exception);
            }
        }
    private static bool FileMapsEqual(
        SortedDictionary<string, string> expected,
        SortedDictionary<string, string> actual)
        => expected.Count == actual.Count
            && expected.SequenceEqual(actual);

    private static void ValidateLegacyRootEntries(
        TrustStateLayout layout)
    {
        EnsureOnlyEntries(
            layout.Root,
            [
                StateFileLock.FileName,
                LegacyLockFileName,
                ManifestFileName,
                "private",
                "public",
                "data",
                "tuf"
            ],
            allowMissing: true);
    }

    private static void ValidateCurrentRootEntries(
        TrustStateLayout layout,
        GenerationManifest generation)
    {
        var allowed = new List<string>
        {
            StateFileLock.FileName,
            TrustDomainFileName,
            ActiveGenerationName,
            GenerationsDirectoryName,
            TransitionDirectoryName,
            MigrationDirectoryName,
            RuntimeDirectoryName,
            "data"
        };
        if (Directory.Exists(
                Path.Combine(
                    layout.Root,
                    "tuf")))
        {
            allowed.Add("tuf");
        }
        if (Directory.Exists(Path.Combine(layout.Root, OidcRotationDirectoryName)))
        {
            allowed.Add(OidcRotationDirectoryName);
        }
        if (File.Exists(Path.Combine(layout.Root, OidcRotationCompletionFileName)))
        {
            allowed.Add(OidcRotationCompletionFileName);
        }
        if (Directory.Exists(Path.Combine(layout.Root, TsaRotationDirectoryName)))
        {
            allowed.Add(TsaRotationDirectoryName);
        }
        if (File.Exists(Path.Combine(layout.Root, TsaRotationCompletionFileName)))
        {
            allowed.Add(TsaRotationCompletionFileName);
        }
        if (File.Exists(Path.Combine(layout.Root, TsaRotationRequestFileName)))
        {
            allowed.Add(TsaRotationRequestFileName);
        }
        if (Directory.Exists(
                Path.Combine(layout.Root, FulcioRotationDirectoryName)))
        {
            allowed.Add(FulcioRotationDirectoryName);
        }
        if (File.Exists(
                Path.Combine(layout.Root, FulcioRotationCompletionFileName)))
        {
            allowed.Add(FulcioRotationCompletionFileName);
        }
        if (File.Exists(
                Path.Combine(layout.Root, FulcioRotationRequestFileName)))
        {
            allowed.Add(FulcioRotationRequestFileName);
        }
        EnsureOnlyEntries(
            layout.Root,
            allowed);
        EnsureOnlyEntries(
            layout.Generations,
            Enumerable.Range(InitialGeneration, generation.Generation)
                .Select(GenerationId));
        EnsureOnlyEntries(
            layout.Transition,
            [TransitionStateFileName]);
        var migrationExpected = File.Exists(
            layout.LegacyManifestArchive)
            ? new[] { LegacyManifestArchiveFileName }
            : [];
        EnsureOnlyEntries(
            layout.Migration,
            migrationExpected);
    }

    /// <summary>
    /// Describes the fixed component-scoped runtime projection files and the
    /// generation material each one mirrors. The projection paths never change
    /// as generations advance, which is what lets long-lived containers
    /// bind-mount them once at startup. Fulcio additionally receives the CT log
    /// public key because it must verify SCTs; publishing a public key there is
    /// safe and keeps Fulcio's mount to a single stable directory.
    /// </summary>
    private static IEnumerable<(string Name, string Source, bool IsPrivate)>
        FulcioRuntimeSources(string generationPath)
    {
        yield return (
            RuntimeFulcioRootCertificateFileName,
            Resolve(generationPath, FulcioRootCertificatePath),
            false);
        yield return (
            RuntimeFulcioRootKeyFileName,
            Resolve(generationPath, FulcioPrivateKeyPath),
            true);
        yield return (
            RuntimeFulcioPasswordFileName,
            Resolve(generationPath, FulcioPrivateKeyPasswordPath),
            true);
        yield return (
            RuntimeFulcioCtLogPublicKeyFileName,
            Resolve(generationPath, CtLogPublicKeyPath),
            false);
    }

    private static IEnumerable<(string Name, string Source, bool IsPrivate)>
        TesseractRuntimeSources(string generationPath)
    {
        yield return (
            RuntimeTesseractPrivateKeyFileName,
            Resolve(generationPath, CtLogPrivateKeyPath),
            true);
    }

    /// <summary>
    /// Atomically promotes the staged Fulcio runtime projection onto the
    /// stable <c>runtime/fulcio</c> path. This is the only place the active
    /// certificate authority a running Fulcio serves is allowed to change, and
    /// Hosting must call it only after clients and Tesseract have restarted
    /// and the old CA has been proven to still issue — otherwise an unexpected
    /// Fulcio recreation could activate the candidate before the log accepts
    /// it. The promotion is bound to the operation and the active generation,
    /// is idempotent on replay, and repairs only the recognized partial state
    /// where some projected files were already replaced. The caller must
    /// already hold the shared state lock.
    /// </summary>
    internal static FulcioRuntimeProjectionInfo
        ActivateFulcioRuntimeProjection(
            string statePath,
            string operationId,
            string expectedOldRootSha256,
            string expectedNewRootSha256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        if (!Guid.TryParseExact(operationId, "N", out _)
            || operationId.Any(char.IsUpper))
        {
            throw new InvalidDataException(
                $"Fulcio rotation operation ID '{operationId}' is invalid.");
        }
        ValidateSha256(expectedOldRootSha256, "expected old Fulcio root");
        ValidateSha256(expectedNewRootSha256, "expected new Fulcio root");
        if (expectedOldRootSha256 == expectedNewRootSha256)
        {
            throw new InvalidDataException(
                "Fulcio runtime activation must change the certificate " +
                "authority.");
        }

        var layout = CreateTrustStateLayout(Path.GetFullPath(statePath));
        var generation = ReadActiveGenerationManifest(
            layout,
            out var generationPath);
        if (generation.FulcioRotationOperationId != operationId
            || generation.FulcioPriorRootSha256 != expectedOldRootSha256
            || generation.FulcioRootSha256 != expectedNewRootSha256
            || generation.FulcioPriorGenerationId is null)
        {
            throw new InvalidDataException(
                "The active generation is not bound to this Fulcio rotation " +
                "operation.");
        }
        var priorGenerationPath = Path.Combine(
            layout.Generations,
            generation.FulcioPriorGenerationId);

        EnsureRuntimeProjectionDirectories(
            layout,
            includeStaged: false);
        var stagedExists = PathExists(layout.RuntimeFulcioStaged);
        if (stagedExists)
        {
            EnsureRealDirectory(
                layout.RuntimeFulcioStaged,
                "staged Fulcio runtime projection");
            if (!RuntimeComponentMatches(
                    layout.RuntimeFulcioStaged,
                    FulcioRuntimeSources(generationPath)))
            {
                throw new InvalidDataException(
                    "The staged Fulcio runtime projection does not match the " +
                    "rotated generation.");
            }
        }

        // Only two per-file states are recognized: still serving the prior
        // generation, or already promoted. Anything else is tampering and is
        // never silently overwritten.
        var pending = new List<(string Path, string Source, bool IsPrivate)>();
        foreach (var (name, source, isPrivate) in FulcioRuntimeSources(
            generationPath))
        {
            var projectedPath = Path.Combine(layout.RuntimeFulcio, name);
            EnsureRegularFile(
                projectedPath,
                "runtime projection");
            var projected = File.ReadAllBytes(projectedPath);
            if (projected.SequenceEqual(File.ReadAllBytes(source)))
            {
                continue;
            }
            var priorSource = Resolve(
                priorGenerationPath,
                RuntimeFulcioGenerationPath(name));
            if (!projected.SequenceEqual(File.ReadAllBytes(priorSource)))
            {
                throw new InvalidDataException(
                    $"Runtime projection '{projectedPath}' matches neither " +
                    "the prior nor the rotated generation.");
            }
            pending.Add((projectedPath, source, isPrivate));
        }
        if (pending.Count != 0 && !stagedExists)
        {
            throw new InvalidDataException(
                "The rotated Fulcio runtime projection is pending promotion " +
                "but was never staged.");
        }

        EnsureOnlyEntries(
            layout.RuntimeFulcio,
            RuntimeFulcioFileNames);
        foreach (var (path, source, isPrivate) in pending)
        {
            WriteRuntimeFile(
                path,
                File.ReadAllBytes(source),
                isPrivate);
        }
        if (stagedExists)
        {
            Directory.Delete(
                layout.RuntimeFulcioStaged,
                recursive: true);
        }

        return CreateFulcioRuntimeProjectionInfo(
            layout,
            generationPath,
            generation);
    }

    /// <summary>
    /// Reads and strictly validates the component-scoped Fulcio runtime
    /// projection: the certificate authority Fulcio is actually serving (its
    /// root fingerprint, public key, subject and validity window, proven
    /// against the projected encrypted private key and password), the CT log
    /// public key Fulcio verifies SCTs with, the staged rotation candidate if
    /// a promotion is outstanding, and the ordered accepted-root bundle
    /// Tesseract enforces. An unrecognized projection is an error rather than
    /// a status. The caller must already hold the shared state lock.
    /// </summary>
    internal static FulcioRuntimeProjectionInfo
        ReadFulcioRuntimeProjection(string statePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(statePath);
        var layout = CreateTrustStateLayout(Path.GetFullPath(statePath));
        var generation = ReadActiveGenerationManifest(
            layout,
            out var generationPath);
        return CreateFulcioRuntimeProjectionInfo(
            layout,
            generationPath,
            generation);
    }

    private static FulcioRuntimeProjectionInfo
        CreateFulcioRuntimeProjectionInfo(
            TrustStateLayout layout,
            string generationPath,
            GenerationManifest generation)
    {
        ValidateRuntimeProjection(
            layout,
            generationPath,
            generation);

        var serving = ValidateFulcioCertificateAuthority(
            Path.Combine(
                layout.RuntimeFulcio,
                RuntimeFulcioRootKeyFileName),
            Path.Combine(
                layout.RuntimeFulcio,
                RuntimeFulcioPasswordFileName),
            Path.Combine(
                layout.RuntimeFulcio,
                RuntimeFulcioRootCertificateFileName));
        using var ctLogPublicKey = LoadEcdsaKey(
            Path.Combine(
                layout.RuntimeFulcio,
                RuntimeFulcioCtLogPublicKeyFileName));

        var acceptedRootsPath = Path.Combine(
            layout.RuntimeTesseract,
            RuntimeAcceptedRootsFileName);
        var acceptedRoots = ReadAcceptedRootsBundle(acceptedRootsPath);
        return new FulcioRuntimeProjectionInfo(
            serving.RootSha256,
            serving.PublicKeySha256,
            serving.SubjectDistinguishedName,
            serving.NotBeforeUtc,
            serving.NotAfterUtc,
            Fingerprint(ctLogPublicKey.ExportSubjectPublicKeyInfo()),
            PathExists(layout.RuntimeFulcioStaged)
                ? generation.FulcioRootSha256
                : null,
            serving.RootSha256 != generation.FulcioRootSha256,
            Fingerprint(File.ReadAllBytes(acceptedRootsPath)),
            acceptedRoots
                .Select(certificate => Fingerprint(certificate.RawData))
                .ToArray());
    }

    /// <summary>
    /// Loads the active generation manifest for the runtime projection APIs
    /// and binds it to the transition journal exactly as the bootstrap
    /// validation path does: the journal must be stable and internally
    /// consistent, the active-generation link must select the journaled
    /// candidate, the manifest bytes on disk must hash to the journaled
    /// candidate hash, and the journaled copy must describe the same
    /// generation. That keeps tamper detection identical whether the
    /// generation was written by C# or by the Go rotation worker.
    /// </summary>
    private static GenerationManifest ReadActiveGenerationManifest(
        TrustStateLayout layout,
        out string generationPath)
    {
        var journal = ReadTransitionJournal(layout);
        ValidateTransitionJournal(journal);
        if (journal.Status is not (
            TransitionStatusCommitted
            or TransitionStatusRecovered)
            || journal.LastCheckpoint != CheckpointName(
                TrustTransitionCheckpoint.TransitionFinalized))
        {
            throw new InvalidDataException(
                "The trust transition has not reached a stable state.");
        }

        var generationId = ReadActiveGeneration(layout.ActiveGeneration);
        EnsureEqual(
            "active generation",
            journal.Candidate.GenerationId,
            generationId);
        generationPath = Path.Combine(
            layout.Generations,
            generationId);
        var generation = ReadPortableJson<GenerationManifest>(
            Path.Combine(
                generationPath,
                GenerationManifestFileName));
        // Binds the read-only manifest bytes to the journaled candidate hash
        // and the manifest's file map to the material actually on disk.
        ValidateGenerationDirectory(
            generationPath,
            generation,
            journal.Candidate.ManifestSha256);
        if (!GenerationManifestsEqual(journal.CandidateManifest, generation))
        {
            throw new InvalidDataException(
                "The active generation does not match the transition journal.");
        }
        ValidateGenerationIdentity(
            journal.TrustDomain,
            generation);
        return generation;
    }

    private static string RuntimeFulcioGenerationPath(string name)
        => name switch
        {
            RuntimeFulcioRootCertificateFileName => FulcioRootCertificatePath,
            RuntimeFulcioRootKeyFileName => FulcioPrivateKeyPath,
            RuntimeFulcioPasswordFileName => FulcioPrivateKeyPasswordPath,
            RuntimeFulcioCtLogPublicKeyFileName => CtLogPublicKeyPath,
            _ => throw new InvalidOperationException(
                $"Unknown Fulcio runtime projection file '{name}'.")
        };

    private static X509Certificate2Collection ReadAcceptedRootsBundle(
        string bundlePath)
    {
        EnsureRegularFile(
            bundlePath,
            "accepted Fulcio roots");
        var certificates = new X509Certificate2Collection();
        try
        {
            certificates.ImportFromPem(
                File.ReadAllText(bundlePath));
        }
        catch (CryptographicException exception)
        {
            throw new InvalidDataException(
                $"Accepted Fulcio roots '{bundlePath}' are not valid PEM " +
                "certificates.",
                exception);
        }
        if (certificates.Count == 0)
        {
            throw new InvalidDataException(
                $"Accepted Fulcio roots '{bundlePath}' contain no " +
                "certificates.");
        }
        return certificates;
    }

    private static void EnsureRuntimeProjectionDirectories(
        TrustStateLayout layout,
        bool includeStaged)
    {
        var directories = new List<string>
        {
            layout.Runtime,
            layout.RuntimeFulcio,
            layout.RuntimeTesseract
        };
        if (includeStaged)
        {
            directories.Add(layout.RuntimeFulcioStaged);
        }
        foreach (var directory in directories)
        {
            if (PathExists(directory))
            {
                EnsureRealDirectory(
                    directory,
                    "runtime projection");
            }
            else
            {
                Directory.CreateDirectory(directory);
            }
        }
    }

    /// <summary>
    /// Materializes the component-scoped runtime projection under
    /// <c>runtime/</c>. These are stable, real directories (never links) that
    /// containers bind-mount, so their paths must not change when the active
    /// generation advances. The Fulcio component is only (re)written when it
    /// is not deliberately serving a prior generation while a rotation awaits
    /// Hosting promotion; the accepted-root bundle is created with the single
    /// active root at bootstrap and is thereafter owned by the rotation
    /// worker, which appends historical roots.
    /// </summary>
    private static void EnsureRuntimeProjection(
        TrustStateLayout layout,
        string generationPath,
        GenerationManifest generation)
    {
        EnsureRuntimeProjectionDirectories(
            layout,
            includeStaged: false);

        if (!IsFulcioPromotionPending(
                layout,
                generation))
        {
            foreach (var (name, source, isPrivate) in FulcioRuntimeSources(
                generationPath))
            {
                WriteRuntimeFile(
                    Path.Combine(layout.RuntimeFulcio, name),
                    File.ReadAllBytes(source),
                    isPrivate);
            }
        }
        foreach (var (name, source, isPrivate) in TesseractRuntimeSources(
            generationPath))
        {
            WriteRuntimeFile(
                Path.Combine(layout.RuntimeTesseract, name),
                File.ReadAllBytes(source),
                isPrivate);
        }

        var acceptedRootsPath = Path.Combine(
            layout.RuntimeTesseract,
            RuntimeAcceptedRootsFileName);
        if (!PathExists(acceptedRootsPath))
        {
            using var root = X509Certificate2.CreateFromPem(
                File.ReadAllText(
                    Resolve(generationPath, FulcioRootCertificatePath)));
            WriteRuntimeFile(
                acceptedRootsPath,
                Encoding.UTF8.GetBytes(NormalizeCertificatePem(root)),
                isPrivate: false);
        }

        ValidateRuntimeProjection(
            layout,
            generationPath,
            generation);
    }

    private static bool IsFulcioPromotionPending(
        TrustStateLayout layout,
        GenerationManifest generation)
    {
        if (generation.FulcioRotationOperationId is null
            || generation.FulcioPriorGenerationId is null
            || !PathExists(layout.RuntimeFulcio))
        {
            return false;
        }
        var priorGenerationPath = Path.Combine(
            layout.Generations,
            generation.FulcioPriorGenerationId);
        return Directory.Exists(priorGenerationPath)
            && RuntimeComponentMatches(
                layout.RuntimeFulcio,
                FulcioRuntimeSources(priorGenerationPath));
    }

    /// <summary>
    /// Validates the runtime projection against the two recognized states: the
    /// steady state, where <c>runtime/fulcio</c> tracks the active generation,
    /// and the post-rotation state, where it deliberately still serves the
    /// prior certificate authority while <c>runtime/fulcio.next</c> stages the
    /// rotated one for Hosting to promote after proof.
    /// </summary>
    private static void ValidateRuntimeProjection(
        TrustStateLayout layout,
        string generationPath,
        GenerationManifest generation)
    {
        var promoted = RuntimeComponentMatches(
            layout.RuntimeFulcio,
            FulcioRuntimeSources(generationPath));
        var servingGenerationPath = generationPath;
        if (!promoted)
        {
            if (generation.FulcioRotationOperationId is null
                || generation.FulcioPriorGenerationId is null)
            {
                throw new InvalidDataException(
                    "The Fulcio runtime projection does not match the active " +
                    "generation.");
            }
            servingGenerationPath = Path.Combine(
                layout.Generations,
                generation.FulcioPriorGenerationId);
            if (!RuntimeComponentMatches(
                    layout.RuntimeFulcio,
                    FulcioRuntimeSources(servingGenerationPath)))
            {
                throw new InvalidDataException(
                    "The Fulcio runtime projection matches neither the prior " +
                    "nor the rotated generation.");
            }
        }

        var allowedRuntimeEntries = new List<string>
        {
            RuntimeFulcioComponentName,
            RuntimeTesseractComponentName
        };
        var stagedExists = PathExists(layout.RuntimeFulcioStaged);
        if (stagedExists)
        {
            allowedRuntimeEntries.Add(RuntimeFulcioStagedComponentName);
            if (!RuntimeComponentMatches(
                    layout.RuntimeFulcioStaged,
                    FulcioRuntimeSources(generationPath)))
            {
                throw new InvalidDataException(
                    "The staged Fulcio runtime projection does not match the " +
                    "rotated generation.");
            }
        }
        else if (!promoted)
        {
            throw new InvalidDataException(
                "The rotated Fulcio runtime projection is pending promotion " +
                "but was never staged.");
        }

        EnsureOnlyEntries(
            layout.Runtime,
            allowedRuntimeEntries);
        EnsureOnlyEntries(
            layout.RuntimeTesseract,
            RuntimeTesseractFileNames);
        foreach (var (name, source, _) in TesseractRuntimeSources(
            generationPath))
        {
            var projectedPath = Path.Combine(layout.RuntimeTesseract, name);
            EnsureRegularFile(
                projectedPath,
                "runtime projection");
            if (!File.ReadAllBytes(projectedPath).SequenceEqual(
                    File.ReadAllBytes(source)))
            {
                throw new InvalidDataException(
                    $"Runtime projection '{projectedPath}' does not match " +
                    "the active generation.");
            }
        }

        ValidateAcceptedRootsBundle(
            Path.Combine(
                layout.RuntimeTesseract,
                RuntimeAcceptedRootsFileName),
            Resolve(generationPath, FulcioRootCertificatePath),
            Resolve(servingGenerationPath, FulcioRootCertificatePath));
    }

    /// <summary>
    /// Reports whether a projected component carries exactly a generation's
    /// material. An unexpected file set is always rejected; carrying a
    /// different generation's bytes merely returns false, because that is the
    /// legitimate pending-promotion state.
    /// </summary>
    private static bool RuntimeComponentMatches(
        string componentPath,
        IEnumerable<(string Name, string Source, bool IsPrivate)> sources)
    {
        var materialized = sources.ToArray();
        EnsureOnlyEntries(
            componentPath,
            materialized.Select(source => source.Name));
        foreach (var (name, source, _) in materialized)
        {
            var projectedPath = Path.Combine(componentPath, name);
            EnsureRegularFile(
                projectedPath,
                "runtime projection");
            if (!File.ReadAllBytes(projectedPath).SequenceEqual(
                    File.ReadAllBytes(source)))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// The accepted-root bundle must be a deterministic, normalized PEM
    /// concatenation of distinct certificates whose final entry is the
    /// currently active Fulcio root, and which still contains the root the
    /// runtime projection is serving. Re-encoding and comparing byte-for-byte
    /// rejects trailing junk, duplicate roots, and non-normalized encodings
    /// that would otherwise let unrelated material ride along.
    /// </summary>
    private static void ValidateAcceptedRootsBundle(
        string bundlePath,
        string activeRootPath,
        string servingRootPath)
    {
        var bundleBytes = File.ReadAllBytes(bundlePath);
        var certificates = ReadAcceptedRootsBundle(bundlePath);

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var builder = new StringBuilder();
        foreach (var certificate in certificates)
        {
            if (!seen.Add(Fingerprint(certificate.RawData)))
            {
                throw new InvalidDataException(
                    $"Accepted Fulcio roots '{bundlePath}' contain duplicate " +
                    "certificates.");
            }
            builder.Append(NormalizeCertificatePem(certificate));
        }
        if (!Encoding.UTF8.GetBytes(builder.ToString())
            .SequenceEqual(bundleBytes))
        {
            throw new InvalidDataException(
                $"Accepted Fulcio roots '{bundlePath}' are not a normalized " +
                "certificate bundle.");
        }

        using var activeRoot = X509Certificate2.CreateFromPem(
            File.ReadAllText(activeRootPath));
        if (!certificates[^1].RawData.SequenceEqual(activeRoot.RawData))
        {
            throw new InvalidDataException(
                $"Accepted Fulcio roots '{bundlePath}' do not end with the " +
                "active Fulcio root.");
        }
        using var servingRoot = X509Certificate2.CreateFromPem(
            File.ReadAllText(servingRootPath));
        if (!seen.Contains(Fingerprint(servingRoot.RawData)))
        {
            throw new InvalidDataException(
                $"Accepted Fulcio roots '{bundlePath}' omit the Fulcio root " +
                "the runtime projection is serving.");
        }
    }

    private static string NormalizeCertificatePem(
        X509Certificate2 certificate)
        => certificate.ExportCertificatePem() + "\n";

    private static void WriteRuntimeFile(
        string path,
        byte[] contents,
        bool isPrivate)
    {
        if (PathExists(path))
        {
            EnsureRegularFile(
                path,
                "runtime projection");
            if (File.ReadAllBytes(path).SequenceEqual(contents))
            {
                SetRuntimeFileMode(path, isPrivate);
                return;
            }
        }
        WriteAtomicBytes(
            path,
            contents,
            isReadOnly: false);
        SetRuntimeFileMode(path, isPrivate);
    }

    private static void SetRuntimeFileMode(
        string path,
        bool isPrivate)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }
        File.SetUnixFileMode(
            path,
            isPrivate
                ? UnixFileMode.UserRead | UnixFileMode.UserWrite
                : UnixFileMode.UserRead
                    | UnixFileMode.UserWrite
                    | UnixFileMode.GroupRead
                    | UnixFileMode.OtherRead);
    }

    private static void EnsureRegularFile(
        string path,
        string description)
    {
        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.Directory)
            || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                $"{description} '{path}' must be a regular file.");
        }
    }
    private static void EnsureFreshRootIsEmpty(
        TrustStateLayout layout)
    {
        EnsureOnlyEntries(
            layout.Root,
            [StateFileLock.FileName]);
    }

    private static void EnsureOnlyEntries(
        string directory,
        IEnumerable<string> allowedEntries,
        bool allowMissing = false)
    {
        EnsureRealDirectory(
            directory,
            "state");
        var allowed = allowedEntries.ToHashSet(
            StringComparer.Ordinal);
        var entries = Directory
            .EnumerateFileSystemEntries(directory)
            .Select(Path.GetFileName)
            .ToArray();
        foreach (var entry in entries)
        {
            if (entry is null || !allowed.Contains(entry))
            {
                throw new InvalidDataException(
                    $"Unexpected Sigstore state entry '{entry}' in " +
                    $"'{directory}'.");
            }
        }
        if (!allowMissing && entries.Length != allowed.Count)
        {
            var missing = allowed.Except(
                entries!,
                StringComparer.Ordinal);
            throw new InvalidDataException(
                $"Sigstore state directory '{directory}' is missing: " +
                $"{string.Join(", ", missing)}.");
        }
    }

    private static void EnsureTrustStateLayout(
        TrustStateLayout layout)
    {
        foreach (var directory in new[]
        {
            layout.Generations,
            layout.Transition,
            layout.Migration
        })
        {
            if (PathExists(directory))
            {
                EnsureRealDirectory(
                    directory,
                    "trust state");
            }
            else
            {
                Directory.CreateDirectory(directory);
            }
        }
    }

    private static void CleanupFreshUnjournaledScratch(
        TrustStateLayout layout)
    {
        if (File.Exists(layout.TransitionState)
            || File.Exists(layout.TrustDomain)
            || PathExists(layout.ActiveGeneration)
            || File.Exists(layout.LegacyManifest))
        {
            return;
        }

        foreach (var path in new[]
        {
            layout.TrustDomainPending,
            layout.ActiveGenerationNext
        })
        {
            if (PathExists(path))
            {
                File.Delete(path);
            }
        }
        foreach (var path in new[]
        {
            layout.Candidate,
            layout.Generations,
            layout.Transition,
            layout.Migration,
            Path.Combine(layout.Root, "data")
        })
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(
                    path,
                    recursive: true);
            }
        }
    }

    private static TrustStateLayout CreateTrustStateLayout(
        string rootPath)
    {
        var generations = Path.Combine(
            rootPath,
            GenerationsDirectoryName);
        var transition = Path.Combine(
            rootPath,
            TransitionDirectoryName);
        var migration = Path.Combine(
            rootPath,
            MigrationDirectoryName);
        var runtime = Path.Combine(
            rootPath,
            RuntimeDirectoryName);
        return new TrustStateLayout(
            rootPath,
            Path.Combine(rootPath, TrustDomainFileName),
            Path.Combine(rootPath, $".{TrustDomainFileName}.pending"),
            Path.Combine(rootPath, ActiveGenerationName),
            Path.Combine(rootPath, $"{ActiveGenerationName}.next"),
            generations,
            Path.Combine(generations, InitialGenerationId),
            transition,
            Path.Combine(transition, "candidate"),
            Path.Combine(transition, TransitionStateFileName),
            migration,
            Path.Combine(rootPath, ManifestFileName),
            Path.Combine(migration, LegacyManifestArchiveFileName),
            runtime,
            Path.Combine(runtime, RuntimeFulcioComponentName),
            Path.Combine(runtime, RuntimeFulcioStagedComponentName),
            Path.Combine(runtime, RuntimeTesseractComponentName));
    }

    private static string ReadActiveGeneration(
        string path)
    {
        var target = ReadRelativeLink(path);
        var expectedDirectory = Path.GetDirectoryName(target);
        var generationId = Path.GetFileName(target);
        if (expectedDirectory != GenerationsDirectoryName
            || !TryParseGenerationId(generationId, out _))
        {
            throw new InvalidDataException(
                $"Active generation link '{path}' has unsafe target " +
                $"'{target}'.");
        }
        return generationId;
    }

    private static string GenerationId(int generation) =>
        $"generation-{generation:D8}";

    private static bool TryParseGenerationId(
        string generationId,
        out int generation)
    {
        generation = 0;
        return generationId.Length == "generation-00000000".Length
            && generationId.StartsWith("generation-", StringComparison.Ordinal)
            && int.TryParse(
                generationId.AsSpan("generation-".Length),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out generation)
            && generation >= InitialGeneration
            && generationId == GenerationId(generation);
    }

    private static string ReadRelativeLink(string path)
    {
        var info = new DirectoryInfo(path);
        var target = info.LinkTarget;
        if (target is null)
        {
            throw new InvalidDataException(
                $"Trust state reference '{path}' is not a symbolic link.");
        }
        if (Path.IsPathFullyQualified(target)
            || target != Path.GetRelativePath(
                Directory.GetParent(path)?.FullName
                    ?? throw new InvalidOperationException(
                        $"Cannot determine parent for '{path}'."),
                Path.GetFullPath(
                    target,
                    Directory.GetParent(path)!.FullName)))
        {
            throw new InvalidDataException(
                $"Trust state reference '{path}' must use a normalized " +
                "relative target.");
        }
        return target;
    }

    /// <summary>
    /// Validates an immutable generation manifest that may have been written
    /// by either the C# bootstrapper or the Go worker. Integrity is bound to
    /// the SHA-256 of the bytes on disk — the value the transition journal
    /// records — and to the semantic content of the manifest, rather than to
    /// one language's JSON encoding. The two encoders legitimately differ in
    /// property order, in whether absent optional fields are emitted as null,
    /// and in timestamp formatting, so requiring byte-identical
    /// re-serialization would reject valid cross-language state while adding
    /// no tamper resistance the hash does not already provide.
    /// </summary>
    private static void ValidateImmutableGenerationManifest(
        string path,
        GenerationManifest expected,
        string expectedHash)
    {
        EnsureReadOnlyRegularFile(
            path,
            Path.GetFileName(path));
        EnsureEqual(
            $"{Path.GetFileName(path)} hash",
            expectedHash,
            HashFile(path));
        if (!GenerationManifestsEqual(
                expected,
                ReadPortableJson<GenerationManifest>(path)))
        {
            throw new InvalidDataException(
                $"Immutable metadata '{path}' does not describe the expected " +
                "generation.");
        }
    }

    private static void ValidateImmutableTrustDomain(
        string path,
        TrustDomainManifest expected,
        string expectedHash)
    {
        EnsureReadOnlyRegularFile(
            path,
            Path.GetFileName(path));
        EnsureEqual(
            $"{Path.GetFileName(path)} hash",
            expectedHash,
            HashFile(path));
        if (!TrustDomainManifestsEqual(
                expected,
                ReadPortableJson<TrustDomainManifest>(path)))
        {
            throw new InvalidDataException(
                $"Immutable metadata '{path}' does not describe the expected " +
                "trust domain.");
        }
    }

    /// <summary>
    /// Reads a document that either language may have produced. Unknown
    /// members are still rejected, so injected fields cannot ride along, but
    /// property order and omitted optional members are accepted.
    /// </summary>
    private static T ReadPortableJson<T>(string path)
        => JsonSerializer.Deserialize<T>(
            File.ReadAllBytes(path),
            PortableJsonOptions)
            ?? throw new InvalidDataException(
                $"Metadata '{path}' is empty.");

    private static bool TrustDomainManifestsEqual(
        TrustDomainManifest expected,
        TrustDomainManifest actual)
        => expected.SchemaVersion == actual.SchemaVersion
            && string.Equals(
                expected.TrustDomainId,
                actual.TrustDomainId,
                StringComparison.Ordinal)
            && expected.CreatedAtUtc.ToUniversalTime()
                == actual.CreatedAtUtc.ToUniversalTime()
            && string.Equals(
                expected.CtLogStateId,
                actual.CtLogStateId,
                StringComparison.Ordinal)
            && string.Equals(
                expected.RekorStateId,
                actual.RekorStateId,
                StringComparison.Ordinal);

    /// <summary>
    /// Compares two generation manifests by value. The compiler-generated
    /// record equality cannot be used because it compares the file map and
    /// the retained-key list by reference, and because an absent optional
    /// list must compare equal to an empty one: Go omits empty slices while
    /// C# writes an explicit null.
    /// </summary>
    private static bool GenerationManifestsEqual(
        GenerationManifest expected,
        GenerationManifest actual)
        => expected.SchemaVersion == actual.SchemaVersion
            && expected.Generation == actual.Generation
            && OrdinalEquals(expected.GenerationId, actual.GenerationId)
            && OrdinalEquals(expected.TrustDomainId, actual.TrustDomainId)
            && expected.CreatedAtUtc.ToUniversalTime()
                == actual.CreatedAtUtc.ToUniversalTime()
            && expected.SourceSchemaVersion == actual.SourceSchemaVersion
            && OrdinalEquals(
                expected.SourceManifestSha256,
                actual.SourceManifestSha256)
            && OrdinalEquals(
                expected.FulcioRootSha256,
                actual.FulcioRootSha256)
            && OrdinalEquals(
                expected.CtLogPublicKeySha256,
                actual.CtLogPublicKeySha256)
            && OrdinalEquals(
                expected.RekorPublicKeySha256,
                actual.RekorPublicKeySha256)
            && OrdinalEquals(expected.TsaRootSha256, actual.TsaRootSha256)
            && OrdinalEquals(expected.TsaLeafSha256, actual.TsaLeafSha256)
            && OrdinalEquals(expected.OidcKeyId, actual.OidcKeyId)
            && OrdinalEquals(
                expected.OidcRotationOperationId,
                actual.OidcRotationOperationId)
            && expected.OidcPriorGeneration == actual.OidcPriorGeneration
            && OrdinalEquals(
                expected.OidcPriorGenerationId,
                actual.OidcPriorGenerationId)
            && OrdinalEquals(expected.OidcPriorKeyId, actual.OidcPriorKeyId)
            && expected.OidcOverlapExpiresAtUtc?.ToUniversalTime()
                == actual.OidcOverlapExpiresAtUtc?.ToUniversalTime()
            && PathListsEqual(
                expected.OidcRetainedPrivateKeyPaths,
                actual.OidcRetainedPrivateKeyPaths)
            && OrdinalEquals(
                expected.TsaRotationOperationId,
                actual.TsaRotationOperationId)
            && expected.TsaPriorGeneration == actual.TsaPriorGeneration
            && OrdinalEquals(
                expected.TsaPriorGenerationId,
                actual.TsaPriorGenerationId)
            && OrdinalEquals(
                expected.TsaPriorRootSha256,
                actual.TsaPriorRootSha256)
            && OrdinalEquals(
                expected.TsaPriorLeafSha256,
                actual.TsaPriorLeafSha256)
            && OrdinalEquals(
                expected.FulcioRotationOperationId,
                actual.FulcioRotationOperationId)
            && expected.FulcioPriorGeneration == actual.FulcioPriorGeneration
            && OrdinalEquals(
                expected.FulcioPriorGenerationId,
                actual.FulcioPriorGenerationId)
            && OrdinalEquals(
                expected.FulcioPriorRootSha256,
                actual.FulcioPriorRootSha256)
            && FileMapsEqual(expected.Files, actual.Files);

    private static bool OrdinalEquals(string? expected, string? actual)
        => string.Equals(expected, actual, StringComparison.Ordinal);

    private static bool PathListsEqual(
        IReadOnlyList<string>? expected,
        IReadOnlyList<string>? actual)
        => (expected ?? []).SequenceEqual(
            actual ?? [],
            StringComparer.Ordinal);

    private static TrustTransitionJournal ReadTransitionJournal(
        TrustStateLayout layout)
        => ReadPortableJson<TrustTransitionJournal>(
            layout.TransitionState);

    private static void WriteTransitionJournal(
        TrustStateLayout layout,
        TrustTransitionJournal journal)
        => WriteAtomicBytes(
            layout.TransitionState,
            SerializeCanonical(journal),
            isReadOnly: false);

    private static void WriteImmutableJson<T>(
        string path,
        T value)
        => WriteAtomicBytes(
            path,
            SerializeCanonical(value),
            isReadOnly: true);

    private static void WriteAtomicBytes(
        string path,
        byte[] contents,
        bool isReadOnly)
    {
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidOperationException(
                $"Cannot determine directory for '{path}'.");
        Directory.CreateDirectory(directory);
        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(path)}.{Environment.ProcessId}." +
            $"{Guid.NewGuid():N}.tmp");
        try
        {
            using (var stream = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None))
            {
                stream.Write(contents);
                stream.Flush(flushToDisk: true);
            }
            if (isReadOnly)
            {
                SetReadOnly(temporaryPath);
            }
            File.Move(
                temporaryPath,
                path,
                overwrite: true);
        }
        finally
        {
            if (File.Exists(temporaryPath))
            {
                File.Delete(temporaryPath);
            }
        }
    }

    private static byte[] SerializeCanonical<T>(T value)
        => Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(
                value,
                JsonOptions)
            + "\n");

    private static string HashSerialized<T>(T value)
        => Fingerprint(SerializeCanonical(value));

    private static string HashFile(string path)
        => Fingerprint(File.ReadAllBytes(path));

    private static void ValidateSha256(
        string? value,
        string description)
    {
        if (value is null
            || value.Length != 64
            || !value.All(character =>
                character is >= '0' and <= '9'
                or >= 'a' and <= 'f'))
        {
            throw new InvalidDataException(
                $"{description} SHA-256 value '{value}' is invalid.");
        }
    }

    private static void EnsureReadOnlyRegularFile(
        string path,
        string description)
    {
        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.Directory)
            || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                $"{description} '{path}' must be a regular file.");
        }
        if (!OperatingSystem.IsWindows()
            && (File.GetUnixFileMode(path)
                & (UnixFileMode.UserWrite
                    | UnixFileMode.GroupWrite
                    | UnixFileMode.OtherWrite)) != 0)
        {
            throw new InvalidDataException(
                $"{description} '{path}' must be read-only.");
        }
    }

    private static void SetReadOnly(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead
                | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead);
        }
        else
        {
            File.SetAttributes(
                path,
                File.GetAttributes(path)
                | FileAttributes.ReadOnly);
        }
    }

    private static void EnsureRealDirectory(
        string path,
        string description)
    {
        var attributes = File.GetAttributes(path);
        if (!attributes.HasFlag(FileAttributes.Directory)
            || attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new InvalidDataException(
                $"{description} path '{path}' must be a real directory.");
        }
    }

    private static bool PathExists(string path)
    {
        var directory = new DirectoryInfo(path);
        if (directory.Exists || directory.LinkTarget is not null)
        {
            return true;
        }
        var file = new FileInfo(path);
        return file.Exists || file.LinkTarget is not null;
    }

    private static string CheckpointName(
        TrustTransitionCheckpoint checkpoint)
        => string.Concat(
            checkpoint
                .ToString()
                .SelectMany(
                    (character, index) =>
                        char.IsUpper(character) && index > 0
                            ? new[]
                            {
                                '-',
                                char.ToLowerInvariant(character)
                            }
                            : new[]
                            {
                                char.ToLowerInvariant(character)
                            }));
}
