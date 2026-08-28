using System.Globalization;
using System.Security.Cryptography;
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
    private const string GenerationAdvanceOperation = "generation-advance";
    private const string OidcRotationDirectoryName = "oidc-rotation";
    private const string OidcRotationCompletionFileName =
        "rotate-oidc-signing-key.completed";

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
        string LegacyManifestArchive);

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

        var domain = ReadCanonicalJson<TrustDomainManifest>(
            layout.TrustDomain);
        ValidateTrustDomain(
            layout,
            domain);
        var domainHash = HashFile(layout.TrustDomain);
        EnsureEqual(
            "trust-domain manifest hash",
            journal.TrustDomainManifestSha256,
            domainHash);

        var activeGeneration = ReadActiveGeneration(
            layout.ActiveGeneration);
        EnsureEqual(
            "active generation",
            journal.Candidate.GenerationId,
            activeGeneration);

        var generationPath = Path.Combine(
            layout.Generations,
            activeGeneration);
        var generation = ReadCanonicalJson<GenerationManifest>(
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
        ValidateCurrentRootEntries(layout, generation);

        if (HashSerialized(journal.CandidateManifest)
            != journal.Candidate.ManifestSha256)
        {
            throw new InvalidDataException(
                "The journaled candidate generation manifest hash is invalid.");
        }
        if (HashSerialized(generation)
            != journal.Candidate.ManifestSha256)
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
        if (journal.Operation is OidcRotationOperation or GenerationAdvanceOperation)
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
        EnsureEqual(
            "journaled candidate manifest hash",
            journal.Candidate.ManifestSha256,
            HashSerialized(journal.CandidateManifest));
        EnsureEqual(
            "journaled trust-domain manifest hash",
            journal.TrustDomainManifestSha256,
            HashSerialized(journal.TrustDomain));
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
            ValidateImmutableJson(
                layout.TrustDomain,
                journal.TrustDomain,
                journal.TrustDomainManifestSha256);
            if (File.Exists(layout.TrustDomainPending))
            {
                ValidateImmutableJson(
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
        ValidateImmutableJson(
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
        ValidateImmutableJson(
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
        ValidateGenerationFileMap(generation.Files);
        ValidateOidcRotationMetadata(generation);
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
        ValidateImmutableJson(
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
        SortedDictionary<string, string> files)
    {
        var required = GenerationMaterialFiles.ToHashSet(StringComparer.Ordinal);
        var actual = files.Keys.ToHashSet(StringComparer.Ordinal);
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
        foreach (var pair in files)
        {
            ValidateSha256(
                pair.Value,
                $"generation file '{pair.Key}'");
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
            Path.Combine(migration, LegacyManifestArchiveFileName));
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

    private static void ValidateImmutableJson<T>(
        string path,
        T expected,
        string expectedHash)
    {
        EnsureReadOnlyRegularFile(
            path,
            Path.GetFileName(path));
        EnsureEqual(
            $"{Path.GetFileName(path)} hash",
            expectedHash,
            HashFile(path));
        var expectedBytes = SerializeCanonical(expected);
        var actualBytes = File.ReadAllBytes(path);
        if (!actualBytes.SequenceEqual(expectedBytes))
        {
            throw new InvalidDataException(
                $"Immutable metadata '{path}' is not the expected canonical " +
                "document.");
        }
    }

    private static T ReadCanonicalJson<T>(string path)
    {
        var data = File.ReadAllBytes(path);
        var value = JsonSerializer.Deserialize<T>(
            data,
            JsonOptions)
            ?? throw new InvalidDataException(
                $"Metadata '{path}' is empty.");
        if (!data.SequenceEqual(SerializeCanonical(value)))
        {
            throw new InvalidDataException(
                $"Metadata '{path}' is not in canonical form.");
        }
        return value;
    }

    private static TrustTransitionJournal ReadTransitionJournal(
        TrustStateLayout layout)
        => ReadCanonicalJson<TrustTransitionJournal>(
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
