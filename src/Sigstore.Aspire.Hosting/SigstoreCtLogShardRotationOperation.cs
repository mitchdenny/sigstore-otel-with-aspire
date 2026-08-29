using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Sigstore.Bootstrap;

namespace Aspire.Hosting.ApplicationModel;

/// <summary>
/// Implements <c>rotate-ct-log-shard</c>: a bounded, one-time rotation of
/// the certificate-transparency log from the single historical primary
/// Tesseract shard to exactly one predeclared secondary shard.
/// </summary>
/// <remarks>
/// <para>
/// The historical primary shard is never mutated or restarted. It keeps
/// its canonical URL, origin, immutable signer, storage and checkpoint
/// history forever, and its compute stays running and required so its
/// append-only tiles and signed checkpoint remain live and verifiable.
/// </para>
/// <para>
/// The secondary shard is created with an isolated immutable signer,
/// its own log ID, its own origin, its own canonical stable URL, its own
/// storage and checkpoint, and the complete accepted Fulcio root bundle
/// the primary already enforces. It is started explicitly and proven
/// healthy — including a verified checkpoint signature and log ID —
/// before any trust publication or Fulcio route change.
/// </para>
/// <para>
/// The ordering is fixed and every step is journaled: create and prove the
/// secondary, publish additive CT trust through TUF (both
/// <c>TransparencyLogInstance</c> entries, SigningConfig untouched),
/// converge all six clients, prove the still-running old Fulcio issues a
/// valid old-shard SCT under the new trust, promote the Fulcio CT runtime
/// selection, restart Fulcio exactly once, prove the same Fulcio CA
/// identity now issues an SCT from the secondary shard, and verify the old
/// and new artifacts in all six languages. Before the cutover a failure
/// leaves the old route intact; after it, recovery is forward-only.
/// </para>
/// </remarks>
internal sealed partial class SigstoreOperationExecutor
{
    private const string CtRequestedStatus =
        SigstoreCtLogShard.StatusRequested;
    private const string CtCandidateGeneratedStatus =
        SigstoreCtLogShard.StatusCandidateGenerated;
    private const string CtSecondaryPreparedStatus =
        SigstoreCtLogShard.StatusSecondaryPrepared;
    private const string CtSecondaryStartedStatus =
        SigstoreCtLogShard.StatusSecondaryStarted;
    private const string CtSecondaryProvedStatus =
        SigstoreCtLogShard.StatusSecondaryProved;
    private const string CtWorkerCommittedStatus =
        SigstoreCtLogShard.StatusWorkerCommitted;
    private const string CtClientsConvergedStatus =
        SigstoreCtLogShard.StatusClientsConverged;
    private const string CtOldShardProvedStatus =
        SigstoreCtLogShard.StatusOldShardProved;
    private const string CtRuntimeActivatedStatus =
        SigstoreCtLogShard.StatusRuntimeActivated;
    private const string CtFulcioRestartedStatus =
        SigstoreCtLogShard.StatusFulcioRestarted;
    private const string CtNewShardProvedStatus =
        SigstoreCtLogShard.StatusNewShardProved;
    private const string CtCompletedStatus =
        SigstoreCtLogShard.StatusCompleted;

    private const int CtRotationTotalSteps = 26;

    public async Task<ExecuteCommandResult> ExecuteRotateCtLogShardAsync(
        CancellationToken requestCancellationToken)
    {
        requestCancellationToken.ThrowIfCancellationRequested();
        if (CreateRecoveryBlockResult(
                SigstoreOperationCommand.RotateCtLogShardCommand) is { } blocked)
        {
            return blocked;
        }
        if (!resource.TryBeginOperation(
                SigstoreOperationCommand.RotateCtLogShardCommand,
                "Rotating CT Log Shard",
                out var lease,
                out var active))
        {
            return CreateContentionResult(
                SigstoreOperationCommand.RotateCtLogShardCommand,
                active!);
        }

        var execution = new OperationExecution(
            resource,
            runtime,
            logger,
            lease!,
            total: CtRotationTotalSteps);
        try
        {
            return await ExecuteRotateCtLogShardCoreAsync(
                execution,
                requestCancellationToken);
        }
        catch (Exception exception)
            when (IsExpectedOperationFailure(exception)
                || exception is CryptographicException)
        {
            execution.AddError(
                execution.Phase,
                resource.Name,
                null,
                exception.Message);
            return CreateCtLogShardResult(
                execution,
                false,
                $"{SigstoreOperationCommand.RotateCtLogShardCommand} " +
                $"failed during {execution.Phase}.",
                null);
        }
        finally
        {
            lease!.Dispose();
            await runtime.PublishParentStateAsync(resource);
        }
    }

    private async Task<ExecuteCommandResult>
        ExecuteRotateCtLogShardCoreAsync(
            OperationExecution execution,
            CancellationToken requestCancellationToken)
    {
        await execution.ReportAsync(
            "preflight",
            0,
            "Validating durable trust, resources, and the CT shard " +
            "catalog.");

        CtLogShardRotationCommandJournal operation;
        SigstoreOperationSnapshot before;
        SigstoreResourceInstanceSnapshot workerBefore;
        SigstoreResourceInstanceSnapshot secondaryBefore;
        var workerStarted = false;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-rotate-ct-log-shard-preflight"))
        {
            requestCancellationToken.ThrowIfCancellationRequested();
            workerBefore = runtime.GetRequiredSnapshot(
                resource.Components.TufBootstrap.Resource);
            var primaryBefore = runtime.GetRequiredSnapshot(
                resource.Components.Tesseract.Resource);
            var fulcioBefore = runtime.GetRequiredSnapshot(
                resource.Components.Fulcio.Resource);
            secondaryBefore = runtime.GetRequiredSnapshot(
                resource.Components.TesseractSecondary.Resource);
            if (!execution.Check(
                    "worker-restartable",
                    IsTerminal(workerBefore)
                        && HasContainerIdentity(workerBefore),
                    "terminal with container identity",
                    Describe(workerBefore),
                    "preflight",
                    workerBefore.Resource)
                || !execution.Check(
                    "primary-ct-log-running",
                    IsRunningHealthy(primaryBefore)
                        && HasContainerIdentity(primaryBefore),
                    "Running/Healthy with container identity",
                    Describe(primaryBefore),
                    "preflight",
                    primaryBefore.Resource)
                || !execution.Check(
                    "fulcio-running",
                    IsRunningHealthy(fulcioBefore)
                        && HasContainerIdentity(fulcioBefore),
                    "Running/Healthy with container identity",
                    Describe(fulcioBefore),
                    "preflight",
                    fulcioBefore.Resource))
            {
                return CreateCtLogShardResult(
                    execution,
                    false,
                    "CT log shard rotation resource preconditions are not " +
                    "satisfied.",
                    null);
            }

            var incomplete = LoadIncompleteCtLogShardRotation(
                resource.StatePath);
            var recovering = incomplete is not null;
            if (incomplete is null)
            {
                var existingCatalog =
                    SigstoreCtLogShard.TryReadShardCatalog(
                        resource.StatePath);
                if (existingCatalog is { Shards.Count: 2 }
                    || resource.IsConditionalResourceActive(
                        resource.Components.TesseractSecondary
                            .Resource.Name))
                {
                    execution.AddError(
                        "preflight",
                        resource.Name,
                        null,
                        "A bounded CT log shard rotation has already " +
                        "completed. Repeated invocation is rejected " +
                        "without mutation.");
                    return CreateCtLogShardResult(
                        execution,
                        false,
                        "CT log shard rotation has already completed.",
                        null);
                }
                if (!await ValidatePreconditionsAsync(
                        execution,
                        requestCancellationToken))
                {
                    return CreateCtLogShardResult(
                        execution,
                        false,
                        "CT log shard rotation preconditions are not " +
                        "satisfied.",
                        null);
                }
            }

            operation = incomplete
                ?? await CreateCtLogShardRotationOperationAsync(
                    primaryBefore,
                    fulcioBefore,
                    requestCancellationToken);
            before = operation.StartingSnapshot;
            execution.Before = before;

            if (operation.StartingGenerationManifestSha256
                != ReadGenerationManifestSha256(
                    resource.StatePath,
                    operation.StartingGenerationId))
            {
                execution.AddError(
                    "preflight",
                    resource.Name,
                    null,
                    "Durable CT log shard rotation state does not match " +
                    "its immutable starting generation.");
                return CreateCtLogShardResult(
                    execution,
                    false,
                    "CT log shard rotation recovery validation failed.",
                    null);
            }
            if (recovering
                && (!ValidateProtectedResources(
                        execution,
                        operation.ProtectedResources,
                        "preflight")
                    || !ValidatePrimaryCtLogUnchanged(
                        execution,
                        operation,
                        "preflight")))
            {
                return CreateCtLogShardResult(
                    execution,
                    false,
                    "A protected Sigstore service changed during CT log " +
                    "shard rotation.",
                    null);
            }

            var candidatePath = SigstoreCtLogShard.CandidatePath(
                resource.StatePath,
                operation.OperationId);

            if (operation.Status == CtRequestedStatus)
            {
                await execution.ReportAsync(
                    "generate-candidate",
                    2,
                    "Generating or validating the operation-bound CT log " +
                    "shard signer.");
                var candidate = stateInspector
                    .EnsureCtLogShardRotationCandidate(candidatePath);
                if (candidate.PublicKeySha256
                    == operation.StartingCtLogPublicKeySha256)
                {
                    throw new InvalidDataException(
                        "The CT log rotation candidate must use a distinct " +
                        "signer from the active shard.");
                }
                if (operation.CandidatePublicKeySha256 is not null
                    && operation.CandidatePublicKeySha256
                        != candidate.PublicKeySha256)
                {
                    throw new InvalidDataException(
                        "The CT log rotation candidate changed during " +
                        "replay.");
                }
                operation = operation with
                {
                    Status = CtCandidateGeneratedStatus,
                    CandidatePublicKeySha256 = candidate.PublicKeySha256,
                    CandidateLogId = candidate.LogId,
                    CandidateShardId = candidate.ShardId,
                    CandidateStateId = operation.CandidateStateId
                        ?? Guid.NewGuid().ToString("D"),
                    CandidateCreatedAtUtc = operation.CandidateCreatedAtUtc
                        ?? DateTimeOffset.UtcNow
                };
                WriteCtLogShardRotationJournal(
                    resource.StatePath,
                    operation);
            }

            if (operation.Status == CtCandidateGeneratedStatus)
            {
                await execution.ReportAsync(
                    "prepare-secondary",
                    3,
                    "Staging the isolated secondary CT log signer, its " +
                    "accepted Fulcio roots, and its durable shard data.");
                var runtimeMaterial =
                    stateInspector.StageCtLogShardRuntime(
                        resource.StatePath,
                        candidatePath);
                if (runtimeMaterial.PublicKeySha256
                    != operation.CandidatePublicKeySha256)
                {
                    throw new InvalidDataException(
                        "The staged secondary CT log signer does not match " +
                        "the rotation candidate.");
                }
                // The secondary shard must accept exactly the complete
                // Fulcio root bundle the primary already enforces, which
                // after prior Fulcio CA rotations is several roots.
                var primaryRoots =
                    SigstoreCtLogShard.ReadRuntimeAcceptedRoots(
                        resource.StatePath,
                        SigstoreCtLogShard.PrimarySlot);
                if (runtimeMaterial.AcceptedRootsSha256
                        != primaryRoots.BundleSha256
                    || !runtimeMaterial.AcceptedRootFingerprints
                        .SequenceEqual(
                            primaryRoots.Fingerprints,
                            StringComparer.Ordinal))
                {
                    throw new InvalidDataException(
                        "The staged secondary CT log shard does not accept " +
                        "exactly the Fulcio roots the historical primary " +
                        "shard accepts.");
                }
                operation = operation with
                {
                    CandidateAcceptedRootsSha256 =
                        runtimeMaterial.AcceptedRootsSha256,
                    CandidateAcceptedRootFingerprints =
                        runtimeMaterial.AcceptedRootFingerprints
                };
                PrepareSecondaryCtShardData(operation);
                var staged = stateInspector
                    .StageFulcioCtRuntimeProjection(
                        resource.StatePath,
                        candidatePath);
                if (staged.StagedCtLogPublicKeySha256
                    != operation.CandidatePublicKeySha256)
                {
                    throw new InvalidDataException(
                        "The staged Fulcio CT selection does not match the " +
                        "rotation candidate.");
                }
                operation = operation with
                {
                    Status = CtSecondaryPreparedStatus
                };
                WriteCtLogShardRotationJournal(
                    resource.StatePath,
                    operation);
            }
        }

        if (operation.Status == CtSecondaryPreparedStatus)
        {
            await execution.ReportAsync(
                "start-secondary",
                5,
                "Starting the secondary CT log shard.");
            ExecuteCommandResult startResult;
            using (var startToken = new CancellationTokenSource(
                WorkerTimeout))
            {
                startResult = await runtime.ExecuteCommandAsync(
                    resource.Components.TesseractSecondary.Resource,
                    KnownResourceCommands.StartCommand,
                    startToken.Token);
            }
            if (!startResult.Success)
            {
                resource.SetOperationRecovery(
                    SigstoreOperationCommand.RotateCtLogShardCommand,
                    "start-secondary",
                    "CT Log Shard Recovery Pending",
                    "The secondary CT log shard could not be started; " +
                    "replay is required.");
                await runtime.PublishParentStateAsync(resource);
                execution.AddError(
                    "start-secondary",
                    resource.Components.TesseractSecondary.Resource.Name,
                    null,
                    startResult.Message
                        ?? "Aspire rejected the secondary CT log shard " +
                            "start.");
                return CreateCtLogShardResult(
                    execution,
                    false,
                    "The secondary CT log shard could not be started.",
                    null);
            }
            SigstoreResourceInstanceSnapshot secondaryAfter;
            using (var waitToken = new CancellationTokenSource(
                ClientTimeout))
            {
                secondaryAfter = await runtime.WaitForSnapshotAsync(
                    resource.Components.TesseractSecondary.Resource,
                    snapshot => IsRunningHealthy(snapshot)
                        && HasContainerIdentity(snapshot),
                    ClientTimeout,
                    waitToken.Token);
            }
            execution.Resources.Add(
                CreateLifecycleResult(
                    secondaryAfter.Resource,
                    KnownResourceCommands.StartCommand,
                    secondaryBefore,
                    secondaryAfter,
                    null));
            operation = operation with
            {
                Status = CtSecondaryStartedStatus,
                SecondaryResourceId = secondaryAfter.ResourceId,
                SecondaryContainerId = secondaryAfter.ContainerId,
                SecondaryStartTimeUtc = secondaryAfter.StartTimeUtc
            };
            WriteCtLogShardRotationJournal(resource.StatePath, operation);
        }

        if (operation.Status == CtSecondaryStartedStatus)
        {
            await execution.ReportAsync(
                "prove-secondary",
                6,
                "Proving the secondary CT log shard is healthy and " +
                "serving a signed checkpoint bound to its own log ID.");
            using var proveToken = new CancellationTokenSource(
                ClientTimeout);
            await runtime.ProbeCtLogShardHealthAsync(
                SigstoreCtLogShard.SecondarySlot,
                proveToken.Token);
            var checkpoint = await runtime.WaitForCtShardCheckpointAsync(
                SigstoreCtLogShard.SecondarySlot,
                SigstoreCtLogShard.CandidatePath(
                    resource.StatePath,
                    operation.OperationId),
                proveToken.Token);
            execution.Check(
                "secondary-checkpoint-log-id",
                checkpoint.LogId == operation.CandidatePublicKeySha256
                    && checkpoint.Origin
                        == SigstoreCtLogShard.SecondaryOrigin,
                $"{SigstoreCtLogShard.SecondaryOrigin}/" +
                    operation.CandidatePublicKeySha256,
                $"{checkpoint.Origin}/{checkpoint.LogId}",
                "prove-secondary",
                resource.Components.TesseractSecondary.Resource.Name);
            execution.Check(
                "secondary-checkpoint-distinct-from-primary",
                checkpoint.LogId
                    != operation.StartingCtLogPublicKeySha256,
                "a log ID distinct from the historical primary shard",
                checkpoint.LogId,
                "prove-secondary",
                resource.Components.TesseractSecondary.Resource.Name);
            if (execution.HasFailures)
            {
                return CreateCtLogShardResult(
                    execution,
                    false,
                    "The secondary CT log shard checkpoint is not bound to " +
                    "its own isolated identity.",
                    null);
            }
            operation = operation with
            {
                Status = CtSecondaryProvedStatus,
                SecondaryCheckpoint = checkpoint
            };
            WriteCtLogShardRotationJournal(resource.StatePath, operation);
        }

        if (operation.Status == CtSecondaryProvedStatus)
        {
            await execution.ReportAsync(
                "write-signal",
                8,
                "Writing the operation-bound CT log shard rotation worker " +
                "request.");
            WriteCtLogShardRotationRequest(resource.StatePath, operation);
            resource.SetOperationRecovery(
                SigstoreOperationCommand.RotateCtLogShardCommand,
                "request-written",
                "CT Log Shard Recovery Pending",
                "The operation-bound worker request must be completed " +
                "before other trust mutations.");
            workerStarted = true;
        }

        if (workerStarted)
        {
            await execution.ReportAsync(
                "start-worker",
                9,
                "Starting the dedicated TUF worker for the additive CT " +
                "trust generation.");
            ExecuteCommandResult workerStart;
            using (var workerCritical = new CancellationTokenSource(
                WorkerTimeout))
            {
                workerStart = await runtime.ExecuteCommandAsync(
                    resource.Components.TufBootstrap.Resource,
                    KnownResourceCommands.StartCommand,
                    workerCritical.Token);
            }
            if (!workerStart.Success)
            {
                resource.SetOperationRecovery(
                    SigstoreOperationCommand.RotateCtLogShardCommand,
                    "start-worker",
                    "CT Log Shard Recovery Pending",
                    "The durable CT log shard request exists and must be " +
                    "replayed.");
                await runtime.PublishParentStateAsync(resource);
                execution.AddError(
                    "start-worker",
                    resource.Components.TufBootstrap.Resource.Name,
                    null,
                    workerStart.Message
                        ?? "Aspire rejected the TUF worker start.");
                return CreateCtLogShardResult(
                    execution,
                    false,
                    "The CT log shard rotation worker could not be " +
                    "started.",
                    null);
            }

            await execution.ReportAsync(
                "wait-worker",
                10,
                "Waiting for additive TUF publication of both " +
                "certificate-transparency logs.");
            SigstoreResourceInstanceSnapshot workerAfter;
            using (var workerWait = new CancellationTokenSource(
                WorkerTimeout))
            {
                workerAfter = await runtime.WaitForSnapshotAsync(
                    resource.Components.TufBootstrap.Resource,
                    snapshot => IsNewInstance(workerBefore, snapshot)
                        && IsTerminal(snapshot),
                    WorkerTimeout,
                    workerWait.Token);
            }
            execution.Resources.Add(
                CreateLifecycleResult(
                    workerAfter.Resource,
                    KnownResourceCommands.StartCommand,
                    workerBefore,
                    workerAfter,
                    null));
            if (!IsSuccessfulTerminal(workerAfter))
            {
                resource.SetOperationRecovery(
                    SigstoreOperationCommand.RotateCtLogShardCommand,
                    "worker-failed",
                    "CT Log Shard Recovery Pending",
                    "The durable CT log shard request must be replayed " +
                    "before other trust mutations.");
                await runtime.PublishParentStateAsync(resource);
                execution.AddError(
                    "wait-worker",
                    workerAfter.Resource,
                    null,
                    $"Worker completed as {Describe(workerAfter)}. " +
                    "Reinvoke the command to replay the durable request.");
                return CreateCtLogShardResult(
                    execution,
                    false,
                    "The CT log shard rotation worker did not complete " +
                    "successfully.",
                    null);
            }
        }

        await execution.ReportAsync(
            "worker-postconditions",
            11,
            "Validating additive CT trust and the committed TUF " +
            "publication.");
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateCtLogShardCommand,
            "worker-completion-validation",
            "CT Log Shard Recovery Pending",
            "The durable worker result must be validated before the " +
            "Fulcio route may change.");
        await runtime.PublishParentStateAsync(resource);

        SigstoreOperationSnapshot after;
        IReadOnlyList<SigstoreCtLogTrustEntry> ctlogEntries;
        CtLogShardCatalog catalog;
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-rotate-ct-log-shard-postconditions"))
        {
            using var postToken = new CancellationTokenSource(
                WorkerTimeout);
            after = await CaptureAsync(postToken.Token);
            execution.After = after;
            var completion = ReadCtLogShardRotationWorkerCompletion(
                resource.StatePath)
                ?? throw new InvalidDataException(
                    "The CT log shard rotation worker completion record " +
                    "is missing.");
            ValidateCtLogShardRotationCompletion(
                completion,
                operation,
                after);
            ctlogEntries = SigstoreCtLogShard.ReadCtlogEntries(
                resource.StatePath);
            catalog = SigstoreCtLogShard.ReadShardCatalog(
                resource.StatePath);
            operation = operation with
            {
                Status = CtWorkerCommittedStatus,
                WorkerCompletion = completion
            };
            WriteCtLogShardRotationJournal(resource.StatePath, operation);
        }
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateCtLogShardCommand,
            "worker-committed",
            "CT Log Shard Cutover Pending",
            "Additive CT trust is committed; all clients must converge " +
            "and the old shard must be re-proven before Fulcio moves.");
        await runtime.PublishParentStateAsync(resource);

        ValidateCtLogShardPublicationPostconditions(
            execution,
            operation,
            before,
            after,
            ctlogEntries,
            catalog);
        foreach (var shard in catalog.Shards)
        {
            execution.Check(
                $"{shard.Slot}-ct-shard-accepted-roots-bound",
                SigstoreCtLogShard.AcceptedRootsMatchRuntime(
                    resource.StatePath,
                    shard),
                $"{shard.AcceptedRootCount} accepted Fulcio roots " +
                    $"({shard.AcceptedRootsSha256}) enforced by the shard " +
                    "runtime projection",
                "the shard runtime projection does not render its recorded " +
                    "accepted-root bundle",
                "worker-postconditions",
                shard.ResourceName);
        }
        if (execution.HasFailures)
        {
            return CreateCtLogShardResult(
                execution,
                false,
                "Additive CT trust was published, but postconditions " +
                "failed.",
                null);
        }

        // The secondary shard only joins aggregate health once its trust is
        // committed. The historical primary shard is deliberately never
        // marked historical: it keeps serving its append-only tiles and
        // signed checkpoint, so it stays required forever.
        await execution.ReportAsync(
            "activate-secondary",
            11,
            "Activating the secondary CT log shard for aggregate health " +
            "while the historical primary shard stays required.");
        if (!execution.Check(
                "primary-ct-log-still-required",
                resource.GetRegistrations().RequiredResources
                    .Any(
                        required => ReferenceEquals(
                            required,
                            resource.Components.Tesseract.Resource)),
                "historical primary CT shard still required",
                "historical primary CT shard already historical",
                "activate-secondary",
                resource.Components.Tesseract.Resource.Name))
        {
            return CreateCtLogShardResult(
                execution,
                false,
                "The historical primary CT log shard must remain a " +
                "required resource.",
                null);
        }
        resource.ActivateConditionalResource(
            resource.Components.TesseractSecondary.Resource);
        await runtime.PublishParentStateAsync(resource);

        var clients = resource.GetRegistrations().Clients
            .OrderBy(client => client.Resource.Name, StringComparer.Ordinal)
            .ToArray();
        if (!execution.Check(
                "six-clients-registered",
                clients.Length == 6,
                "6",
                clients.Length.ToString(CultureInfo.InvariantCulture),
                "restart-clients",
                resource.Name))
        {
            return CreateCtLogShardResult(
                execution,
                false,
                "The Sigstore parent does not have exactly six clients.",
                null);
        }

        await execution.ReportAsync(
            "restart-clients",
            12,
            "Converging all six clients on the additive CT trust.");
        using (var clientCritical = new CancellationTokenSource(
            TimeSpan.FromMinutes(20)))
        {
            foreach (var (client, index) in clients.Select(
                (client, index) => (client, index)))
            {
                var clientBefore = runtime.GetRequiredSnapshot(
                    client.Resource);
                if (!execution.Check(
                        $"{client.Resource.Name}-ready",
                        IsRunningHealthy(clientBefore)
                            && HasContainerIdentity(clientBefore),
                        "Running/Healthy with container identity",
                        Describe(clientBefore),
                        "restart-client",
                        client.Resource.Name))
                {
                    return CreateCtLogShardResult(
                        execution,
                        false,
                        $"{client.Resource.Name} is not ready for " +
                        "convergence.",
                        null);
                }

                SigstoreClientTrustStatus? currentStatus = null;
                try
                {
                    currentStatus = await runtime.ReadClientStatusAsync(
                        client,
                        clientCritical.Token);
                }
                catch (Exception exception)
                    when (IsExpectedOperationFailure(exception))
                {
                    logger.LogInformation(
                        exception,
                        "{Client} requires restart before CT trust " +
                        "convergence.",
                        client.Resource.Name);
                }

                SigstoreResourceInstanceSnapshot clientAfter;
                string lifecycleCommand;
                if (currentStatus is not null
                    && MatchesDisk(after.Tuf.Trust, currentStatus))
                {
                    clientAfter = clientBefore;
                    lifecycleCommand = "already-converged";
                }
                else
                {
                    await execution.ReportAsync(
                        "restart-client",
                        12 + index,
                        $"Restarting {client.Resource.Name} on the " +
                        "additive certificate-transparency trust.");
                    var restart = await runtime.ExecuteCommandAsync(
                        client.Resource,
                        KnownResourceCommands.RestartCommand,
                        clientCritical.Token);
                    if (!restart.Success)
                    {
                        execution.AddError(
                            "restart-client",
                            client.Resource.Name,
                            null,
                            restart.Message
                                ?? "Aspire rejected the client restart.");
                        return CreateCtLogShardResult(
                            execution,
                            false,
                            $"{client.Resource.Name} could not be " +
                            "restarted.",
                            null);
                    }
                    clientAfter = await runtime.WaitForSnapshotAsync(
                        client.Resource,
                        snapshot => IsNewInstance(clientBefore, snapshot)
                            && IsRunningHealthy(snapshot),
                        ClientTimeout,
                        clientCritical.Token);
                    currentStatus = await runtime.ReadClientStatusAsync(
                        client,
                        clientCritical.Token);
                    lifecycleCommand = KnownResourceCommands.RestartCommand;
                }

                if (!execution.Check(
                        $"{client.Resource.Name}-trust-status",
                        currentStatus is not null
                            && MatchesDisk(after.Tuf.Trust, currentStatus),
                        DescribeTrust(after.Tuf.Trust),
                        currentStatus is null
                            ? "unavailable"
                            : DescribeTrust(currentStatus),
                        "restart-client",
                        client.Resource.Name))
                {
                    return CreateCtLogShardResult(
                        execution,
                        false,
                        $"{client.Resource.Name} did not converge on " +
                        "additive CT trust.",
                        null);
                }
                execution.Resources.Add(
                    CreateLifecycleResult(
                        client.Resource.Name,
                        lifecycleCommand,
                        clientBefore,
                        clientAfter,
                        currentStatus));
                operation = operation with
                {
                    Clients = UpsertCtClientConvergence(
                        operation.Clients,
                        new CtLogShardClientConvergence(
                            client.Resource.Name,
                            clientAfter.ContainerId!,
                            clientAfter.StartTimeUtc,
                            DateTimeOffset.UtcNow,
                            currentStatus!))
                };
                WriteCtLogShardRotationJournal(
                    resource.StatePath,
                    operation);
            }
        }
        operation = operation with
        {
            Status = CtClientsConvergedStatus,
            ClientsConvergedAtUtc = operation.ClientsConvergedAtUtc
                ?? DateTimeOffset.UtcNow
        };
        WriteCtLogShardRotationJournal(resource.StatePath, operation);
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateCtLogShardCommand,
            "clients-converged",
            "CT Log Shard Cutover Pending",
            "All clients trust both CT shards; the old shard must be " +
            "re-proven before Fulcio moves.");
        await runtime.PublishParentStateAsync(resource);

        // Once the cutover begins, user cancellation must never leave the
        // Fulcio route ambiguous: recovery from here is forward-only.
        using var critical =
            new CancellationTokenSource(TimeSpan.FromMinutes(30));
        var cancellationToken = critical.Token;

        await execution.ReportAsync(
            "prove-old-shard",
            18,
            "Proving the still-running Fulcio issues a valid old-shard " +
            "SCT under the new additive trust.");
        if (operation.OldShardProof is null)
        {
            var overlap = await runtime.ReadFulcioStatusAsync(
                cancellationToken);
            if (overlap.LiveRootSha256 != operation.FulcioRootSha256
                || overlap.CtLogId
                    != operation.StartingCtLogPublicKeySha256)
            {
                throw new InvalidDataException(
                    "Fulcio is not still bound to the historical primary " +
                    "CT shard before the overlap proof.");
            }
            var (jwt, _) = await runtime.CaptureOidcTokenAsync(
                cancellationToken);
            var proof = await runtime.ProveFulcioIssuanceForCtShardAsync(
                jwt
                    ?? throw new InvalidDataException(
                        "OIDC token response was empty."),
                SigstoreDefaults.ExpectedIdentity,
                operation.FulcioRootSha256,
                SigstoreCtLogShard.ResolveShardGenerationPath(
                    resource.StatePath,
                    "primary",
                    operation.StartingGenerationId),
                cancellationToken);
            operation = operation with
            {
                Status = CtOldShardProvedStatus,
                OldShardProof = proof,
                OldShardProvedAtUtc = DateTimeOffset.UtcNow
            };
            WriteCtLogShardRotationJournal(resource.StatePath, operation);
        }
        ValidateCtIssuanceProof(
            operation.OldShardProof!,
            operation.FulcioRootSha256,
            operation.StartingCtLogPublicKeySha256,
            operation.OldShardProvedAtUtc,
            "old-shard-proof");
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateCtLogShardCommand,
            "old-shard-proved",
            "CT Log Shard Cutover Pending",
            "The old shard still issues; the Fulcio CT selection must be " +
            "promoted forward.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "activate-runtime",
            19,
            "Promoting the operation-bound Fulcio certificate-transparency " +
            "runtime selection.");
        using (stateInspector.AcquireLock(
            resource.StatePath,
            "dashboard-activate-fulcio-ct-runtime"))
        {
            _ = stateInspector.ActivateFulcioCtRuntimeProjection(
                resource.StatePath,
                operation.OperationId,
                operation.StartingCtLogPublicKeySha256,
                operation.CandidatePublicKeySha256
                    ?? throw new InvalidDataException(
                        "The CT log rotation candidate is missing."));
            operation = operation with
            {
                Status = CtRuntimeActivatedStatus,
                RuntimeActivatedAtUtc = operation.RuntimeActivatedAtUtc
                    ?? DateTimeOffset.UtcNow
            };
            WriteCtLogShardRotationJournal(resource.StatePath, operation);
        }
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateCtLogShardCommand,
            "runtime-activated",
            "Fulcio Restart Pending",
            "The new CT selection is promoted; recovery must restart " +
            "Fulcio forward.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "restart-fulcio",
            20,
            "Restarting Fulcio exactly once onto the secondary CT log " +
            "shard.");
        var fulcioCurrent = runtime.GetRequiredSnapshot(
            resource.Components.Fulcio.Resource);
        var activationStatus = await runtime.ReadFulcioStatusAsync(
            cancellationToken);
        // The promoted selection is durable state, so it flips the moment
        // the manifest is replaced and can never prove that the running
        // Fulcio process moved. The restart is therefore gated purely on
        // journaled container identity and start time — exactly like the
        // Fulcio CA rotation gates its Tesseract restart — and the proof
        // that the new process really switched shards is the live issuance
        // with an embedded SCT verified against the secondary shard's
        // signer, origin and log ID in the next step.
        if (activationStatus.CtLogShardSlot != SigstoreCtLogShard.SecondarySlot
            || activationStatus.CtLogId != operation.CandidatePublicKeySha256
            || activationStatus.CtLogOrigin
                != SigstoreCtLogShard.SecondaryOrigin
            || activationStatus.CtLogPromotionPending)
        {
            throw new InvalidDataException(
                "The promoted Fulcio certificate-transparency selection " +
                "does not name the secondary CT log shard.");
        }
        var journaledFulcio = SnapshotFromJournal(
            operation.FulcioResourceId,
            resource.Components.Fulcio.Resource.Name,
            operation.FulcioContainerId,
            operation.FulcioStartTimeUtc);
        var runtimeActivatedAtUtc = operation.RuntimeActivatedAtUtc
            ?? throw new InvalidDataException(
                "The CT log runtime activation is not journaled.");
        SigstoreResourceInstanceSnapshot fulcioAfter;
        if (operation.FulcioAfterContainerId is not null)
        {
            if (fulcioCurrent.ContainerId
                    != operation.FulcioAfterContainerId
                || fulcioCurrent.StartTimeUtc
                    != operation.FulcioAfterStartTimeUtc
                || !IsRunningHealthy(fulcioCurrent))
            {
                throw new InvalidDataException(
                    "The recovered Fulcio CT activation does not match its " +
                    "durable evidence.");
            }
            fulcioAfter = fulcioCurrent;
        }
        else if (SameInstance(journaledFulcio, fulcioCurrent))
        {
            // The journaled instance is still running, so it is still bound
            // to the historical primary shard: restart it exactly once.
            var restart = await runtime.ExecuteCommandAsync(
                resource.Components.Fulcio.Resource,
                KnownResourceCommands.RestartCommand,
                cancellationToken);
            if (!restart.Success)
            {
                throw new InvalidOperationException(
                    restart.Message
                    ?? "Aspire rejected the Fulcio restart.");
            }
            fulcioAfter = await runtime.WaitForSnapshotAsync(
                resource.Components.Fulcio.Resource,
                snapshot => IsNewInstance(fulcioCurrent, snapshot)
                    && IsRunningHealthy(snapshot),
                ClientTimeout,
                cancellationToken);
            execution.Resources.Add(
                CreateLifecycleResult(
                    fulcioAfter.Resource,
                    KnownResourceCommands.RestartCommand,
                    fulcioCurrent,
                    fulcioAfter,
                    null));
        }
        else if (IsNewInstance(journaledFulcio, fulcioCurrent)
            && IsRunningHealthy(fulcioCurrent)
            && fulcioCurrent.StartTimeUtc is { } startedAtUtc
            && new DateTimeOffset(startedAtUtc, TimeSpan.Zero)
                >= runtimeActivatedAtUtc)
        {
            // The restart happened but the journal write was lost. The
            // replacement instance started after the selection was
            // promoted, so it can only have booted on the secondary shard;
            // recover it as already restarted and let the mandatory live
            // issuance proof below confirm the shard cryptographically.
            fulcioAfter = fulcioCurrent;
        }
        else
        {
            throw new InvalidDataException(
                "Fulcio cannot be moved to the secondary CT shard or " +
                "recovered in the required order.");
        }
        operation = operation with
        {
            Status = CtFulcioRestartedStatus,
            FulcioAfterContainerId = fulcioAfter.ContainerId,
            FulcioAfterStartTimeUtc = fulcioAfter.StartTimeUtc
        };
        WriteCtLogShardRotationJournal(resource.StatePath, operation);
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateCtLogShardCommand,
            "fulcio-restarted",
            "New CT Shard Proof Pending",
            "Fulcio is on the secondary shard; new issuance and artifact " +
            "proofs remain.");
        await runtime.PublishParentStateAsync(resource);

        await execution.ReportAsync(
            "prove-new-shard",
            21,
            "Proving the same Fulcio CA identity now issues an SCT from " +
            "the secondary CT log shard.");
        if (operation.NewShardProof is null)
        {
            var live = await runtime.ReadFulcioStatusAsync(
                cancellationToken);
            if (live.LiveRootSha256 != operation.FulcioRootSha256
                || live.CtLogId != operation.CandidatePublicKeySha256)
            {
                throw new InvalidDataException(
                    "Fulcio does not serve the unchanged CA on the " +
                    "secondary CT shard after restart.");
            }
            var (jwt, _) = await runtime.CaptureOidcTokenAsync(
                cancellationToken);
            var proof = await runtime.ProveFulcioIssuanceForCtShardAsync(
                jwt
                    ?? throw new InvalidDataException(
                        "OIDC token response was empty."),
                SigstoreDefaults.ExpectedIdentity,
                operation.FulcioRootSha256,
                SigstoreCtLogShard.ResolveShardGenerationPath(
                    resource.StatePath,
                    "secondary",
                    operation.StartingGenerationId),
                cancellationToken);
            operation = operation with
            {
                Status = CtNewShardProvedStatus,
                NewShardProof = proof,
                NewShardProvedAtUtc = DateTimeOffset.UtcNow
            };
            WriteCtLogShardRotationJournal(resource.StatePath, operation);
        }
        ValidateCtIssuanceProof(
            operation.NewShardProof!,
            operation.FulcioRootSha256,
            operation.CandidatePublicKeySha256!,
            operation.NewShardProvedAtUtc,
            "new-shard-proof");
        execution.Check(
            "fulcio-ca-identity-unchanged",
            operation.NewShardProof!.RootSha256
                == operation.OldShardProof!.RootSha256
                && operation.NewShardProof.CertificateIssuer
                    == operation.OldShardProof.CertificateIssuer,
            operation.OldShardProof.RootSha256,
            operation.NewShardProof.RootSha256,
            "prove-new-shard",
            resource.Components.Fulcio.Resource.Name);
        if (execution.HasFailures)
        {
            return CreateCtLogShardResult(
                execution,
                false,
                "The Fulcio certificate authority identity changed across " +
                "the CT log shard cutover.",
                null);
        }

        await execution.ReportAsync(
            "verify-old-artifact",
            22,
            "Verifying the retained old-shard artifact in all six " +
            "clients.");
        operation = operation with
        {
            OldArtifactValidations = await VerifyCtArtifactWithAllClientsAsync(
                operation.OldArtifact,
                clients,
                after.Tuf.Trust,
                operation.OldArtifactValidations,
                operation,
                isOld: true,
                cancellationToken)
        };
        WriteCtLogShardRotationJournal(resource.StatePath, operation);

        await execution.ReportAsync(
            "capture-new-artifact",
            23,
            "Retaining a real post-cutover artifact sealed under the " +
            "secondary CT log shard.");
        if (operation.NewArtifact is null)
        {
            operation = operation with
            {
                NewArtifact = await WaitForArtifactAsync(
                    operation.OldArtifact.ArtifactId,
                    operation.FulcioRootSha256,
                    cancellationToken)
            };
            WriteCtLogShardRotationJournal(resource.StatePath, operation);
        }

        await execution.ReportAsync(
            "verify-new-artifact",
            24,
            "Verifying the new secondary-shard artifact in all six " +
            "clients.");
        operation = operation with
        {
            NewArtifactValidations = await VerifyCtArtifactWithAllClientsAsync(
                operation.NewArtifact,
                clients,
                after.Tuf.Trust,
                operation.NewArtifactValidations,
                operation,
                isOld: false,
                cancellationToken)
        };
        WriteCtLogShardRotationJournal(resource.StatePath, operation);

        await execution.ReportAsync(
            "aggregate-status",
            25,
            "Verifying aggregate trust status, both shards, and unchanged " +
            "protected resources.");
        await runtime.WaitForAggregateHealthyAsync(
            AggregateTimeout,
            cancellationToken);
        var aggregate = await runtime.CollectStatusAsync(
            cancellationToken);
        execution.Check(
            "aggregate-status-ready",
            IsReadyForCtLogFinalization(
                aggregate,
                operation.OperationId,
                operation.Status)
                && aggregate.Clients.Count == clients.Length
                && aggregate.CtLog is
                {
                    FulcioCtPromotionPending: false,
                    SelectedFulcioShardSlot: "secondary"
                }
                && aggregate.CtLog.Shards.Count == 2,
            "ready=true with six clients and two certificate-transparency " +
                "shards",
            aggregate.Reason
                ?? $"ready={aggregate.Ready}, " +
                    $"clients={aggregate.Clients.Count}",
            "aggregate-status",
            resource.Name);
        execution.Check(
            "protected-services-not-restarted",
            ValidateProtectedResources(
                execution,
                operation.ProtectedResources,
                "final-verification"),
            "all protected service container identities unchanged",
            "see per-resource postconditions",
            "final-verification",
            resource.Name);
        ValidatePrimaryCtLogUnchanged(
            execution,
            operation,
            "final-verification");
        if (execution.HasFailures)
        {
            return CreateCtLogShardResult(
                execution,
                false,
                "CT log shard cutover completed, but final convergence " +
                "checks failed.",
                null);
        }

        var recovered = operation.StartedAtUtc
            < execution.Progress[0].ObservedAtUtc;
        operation = operation with
        {
            Status = CtCompletedStatus,
            CompletedAtUtc = DateTimeOffset.UtcNow
        };
        WriteCtLogShardRotationJournal(resource.StatePath, operation);
        resource.ClearOperationRecovery(
            SigstoreOperationCommand.RotateCtLogShardCommand);
        await execution.ReportAsync(
            "complete",
            CtRotationTotalSteps,
            "Certificate-transparency log rotated to the new bounded " +
            "secondary shard.");
        return CreateCtLogShardResult(
            execution,
            true,
            $"CT log shard rotated: {operation.PriorShardId} -> " +
            $"{operation.CandidateShardId}.",
            BuildCtLogShardRotationEvidence(operation, recovered));
    }

    internal static bool IsReadyForCtLogFinalization(
        SigstoreAggregateTrustStatus status,
        string operationId,
        string operationStatus)
    {
        var ctLog = status.CtLog;
        return status.Operation is
            {
                Command: SigstoreOperationCommand.RotateCtLogShardCommand
            }
            && status.Recovery is
            {
                Command: SigstoreOperationCommand.RotateCtLogShardCommand
            } recovery
            && recovery.Phase == operationStatus
            && ctLog is not null
            && ctLog.IncompleteRotationOperationId == operationId
            && ctLog.IncompleteRotationStatus == operationStatus
            && !ctLog.FulcioCtPromotionPending
            && ctLog.TrustedRootCtlogCount == ctLog.Shards.Count
            && ctLog.Shards.Count == 2
            && ctLog.Shards.All(
                shard => shard.InTrustedRoot
                    && (!shard.ComputeRequired
                        || shard.ComputeHealthy == true)
                    && shard.AcceptedRootsMatchRuntime)
            && status.Errors.Count == 2
            && status.Errors.Count(error => error.Source == "ctlog") == 1
            && status.Errors.Count(error => error.Source == "operation") == 1;
    }

    private async Task<CtLogShardRotationCommandJournal>
        CreateCtLogShardRotationOperationAsync(
            SigstoreResourceInstanceSnapshot primary,
            SigstoreResourceInstanceSnapshot fulcio,
            CancellationToken cancellationToken)
    {
        var starting = await CaptureAsync(cancellationToken);
        if (!MatchesServed(starting.Tuf, starting.Served))
        {
            throw new InvalidDataException(
                "Disk and served TUF state differ before CT log shard " +
                "rotation.");
        }
        var active = SigstoreCtLogShard.ReadActiveMaterial(
            resource.StatePath);
        var ctlogEntries = SigstoreCtLogShard.ReadCtlogEntries(
            resource.StatePath);
        if (ctlogEntries.Count != 1
            || ctlogEntries[0].PublicKeySha256 != active.PublicKeySha256
            || ctlogEntries[0].BaseUrl != SigstoreCtLogShard.PrimaryUrl)
        {
            throw new InvalidDataException(
                "TrustedRoot certificate-transparency routing does not " +
                "match the canonical single-shard state.");
        }
        var fulcioStatus = await runtime.ReadFulcioStatusAsync(
            cancellationToken);
        if (fulcioStatus.CtLogId != active.PublicKeySha256
            || !fulcioStatus.LiveRootMatchesActive
            || !fulcioStatus.TesseractAcceptedRootsMatch
            || fulcioStatus.RuntimePromotionPending)
        {
            throw new InvalidDataException(
                "Fulcio, Tesseract and TrustedRoot do not agree before CT " +
                "log shard rotation.");
        }
        var oldArtifact = await WaitForArtifactAsync(
            0,
            fulcioStatus.ActiveRootSha256,
            cancellationToken);

        var operationId = Guid.NewGuid().ToString("N");
        var operation = new CtLogShardRotationCommandJournal(
            SchemaVersion: 1,
            OperationId: operationId,
            Status: CtRequestedStatus,
            StartedAtUtc: DateTimeOffset.UtcNow,
            CompletedAtUtc: null,
            TrustDomainId: starting.Tuf.Trust.TrustDomainId,
            StartingGeneration: starting.Tuf.Trust.Generation,
            StartingGenerationId: starting.Tuf.Trust.GenerationId,
            StartingGenerationManifestSha256:
                starting.Tuf.Trust.GenerationManifestSha256,
            StartingCtLogPublicKeySha256: active.PublicKeySha256,
            StartingCtLogStateId: fulcioStatus.CtLogStateId,
            StartingCheckpoint: fulcioStatus.Checkpoint,
            PriorShardId: active.ShardId,
            PriorShardUrl: SigstoreCtLogShard.PrimaryUrl,
            PriorShardOrigin: SigstoreCtLogShard.PrimaryOrigin,
            StartingSnapshot: starting,
            PrimaryResourceId: primary.ResourceId,
            PrimaryContainerId: primary.ContainerId!,
            PrimaryStartTimeUtc: primary.StartTimeUtc,
            FulcioResourceId: fulcio.ResourceId,
            FulcioContainerId: fulcio.ContainerId!,
            FulcioStartTimeUtc: fulcio.StartTimeUtc,
            ProtectedResources: CaptureCtProtectedResources(),
            FulcioRootSha256: fulcioStatus.ActiveRootSha256,
            OldArtifact: oldArtifact,
            CandidatePublicKeySha256: null,
            CandidateLogId: null,
            CandidateShardId: null,
            CandidateStateId: null,
            CandidateCreatedAtUtc: null,
            CandidateAcceptedRootsSha256: null,
            CandidateAcceptedRootFingerprints: [],
            SecondaryResourceId: null,
            SecondaryContainerId: null,
            SecondaryStartTimeUtc: null,
            SecondaryCheckpoint: null,
            WorkerCompletion: null,
            Clients: [],
            ClientsConvergedAtUtc: null,
            OldShardProof: null,
            OldShardProvedAtUtc: null,
            RuntimeActivatedAtUtc: null,
            FulcioAfterContainerId: null,
            FulcioAfterStartTimeUtc: null,
            NewShardProof: null,
            NewShardProvedAtUtc: null,
            OldArtifactValidations: [],
            NewArtifact: null,
            NewArtifactValidations: []);
        WriteCtLogShardRotationJournal(resource.StatePath, operation);
        resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateCtLogShardCommand,
            "requested",
            "CT Log Shard Recovery Pending",
            "The durable old-shard artifact and CT identity are captured; " +
            "candidate generation or replay must complete before other " +
            "trust mutations.");
        return operation;
    }

    /// <summary>
    /// Captures every required resource except the six clients and Fulcio
    /// itself. Fulcio is excluded because it is deliberately restarted
    /// exactly once by this operation; the historical primary Tesseract
    /// shard is deliberately included, because it must never be restarted.
    /// </summary>
    private IReadOnlyList<SigstoreResourceInstanceSnapshot>
        CaptureCtProtectedResources()
    {
        var excluded = resource.GetRegistrations().Clients
            .Select(client => client.Resource.Name)
            .ToHashSet(StringComparer.Ordinal);
        excluded.Add(resource.Components.Fulcio.Resource.Name);
        return resource.GetRegistrations().RequiredResources
            .Where(required => !excluded.Contains(required.Name))
            .OrderBy(required => required.Name, StringComparer.Ordinal)
            .Select(
                required =>
                {
                    var snapshot = runtime.GetRequiredSnapshot(required);
                    if (!IsRunningHealthy(snapshot)
                        || !HasContainerIdentity(snapshot))
                    {
                        throw new InvalidOperationException(
                            $"Protected resource '{required.Name}' is " +
                            $"{Describe(snapshot)}.");
                    }
                    return snapshot;
                })
            .ToArray();
    }

    /// <summary>
    /// Directly proves the historical primary Tesseract shard's container
    /// identity and health have not changed since the rotation started.
    /// This check must always pass: the primary CT shard is never
    /// restarted or mutated by this rotation, before or after cutover, and
    /// its compute stays required so its append-only tiles and signed
    /// checkpoint remain live.
    /// </summary>
    private bool ValidatePrimaryCtLogUnchanged(
        OperationExecution execution,
        CtLogShardRotationCommandJournal operation,
        string phase)
    {
        var current = runtime.GetRequiredSnapshot(
            resource.Components.Tesseract.Resource);
        return execution.Check(
            "primary-ct-log-not-restarted",
            current.ContainerId == operation.PrimaryContainerId
                && current.StartTimeUtc == operation.PrimaryStartTimeUtc
                && IsRunningHealthy(current),
            $"container {operation.PrimaryContainerId}, started " +
                $"{operation.PrimaryStartTimeUtc:O}, Running/Healthy",
            Describe(current),
            phase,
            resource.Components.Tesseract.Resource.Name);
    }

    /// <summary>
    /// Materializes the secondary shard's isolated durable storage: its own
    /// state marker (never the trust domain's primary CT state ID) and its
    /// operation-bound shard metadata. Replay re-validates instead of
    /// rewriting.
    /// </summary>
    private void PrepareSecondaryCtShardData(
        CtLogShardRotationCommandJournal operation)
    {
        var dataPath = SigstoreCtLogShard.SecondaryDataPath(
            resource.StatePath);
        Directory.CreateDirectory(dataPath);
        var stateId = operation.CandidateStateId
            ?? throw new InvalidDataException(
                "The CT log rotation candidate state ID is missing.");
        if (stateId == operation.StartingCtLogStateId)
        {
            throw new InvalidDataException(
                "The secondary CT log shard must not reuse the primary " +
                "shard's state identity.");
        }
        WriteCreateNewBytes(
            Path.Combine(dataPath, "bootstrap-state"),
            Encoding.UTF8.GetBytes(stateId));

        var metadata = new CtLogShardMetadataFile(
            SchemaVersion: 1,
            OperationId: operation.OperationId,
            TrustDomainId: operation.TrustDomainId,
            ShardId: operation.CandidateShardId
                ?? throw new InvalidDataException(
                    "The CT log rotation candidate shard ID is missing."),
            Slot: "secondary",
            BaseUrl: SigstoreCtLogShard.SecondaryUrl,
            Origin: SigstoreCtLogShard.SecondaryOrigin,
            PublicKeySha256: operation.CandidatePublicKeySha256
                ?? throw new InvalidDataException(
                    "The CT log rotation candidate public key is missing."),
            LogIdSha256: operation.CandidateLogId
                ?? throw new InvalidDataException(
                    "The CT log rotation candidate log ID is missing."),
            StateId: stateId,
            DataPath: SigstoreCtLogShard.SecondaryDataRelativePath,
            ResourceName:
                resource.Components.TesseractSecondary.Resource.Name,
            CreatedAtUtc: operation.CandidateCreatedAtUtc
                ?? throw new InvalidDataException(
                    "The CT log rotation candidate creation time is " +
                    "missing."),
            AcceptedRootsSha256: operation.CandidateAcceptedRootsSha256
                ?? throw new InvalidDataException(
                    "The secondary CT shard accepted-root bundle identity " +
                    "is missing."),
            AcceptedRootCount:
                operation.CandidateAcceptedRootFingerprints.Count,
            AcceptedRootFingerprints:
                operation.CandidateAcceptedRootFingerprints);
        ReplayOrWriteCtLogShardMetadata(
            Path.Combine(dataPath, "shard.json"),
            metadata);
    }

    /// <summary>
    /// Writes the secondary shard's metadata file exactly once. On replay
    /// — when <paramref name="metadataPath"/> already exists because a
    /// prior attempt at this operation reached this step — the durable
    /// copy is re-validated against the freshly recomputed
    /// <paramref name="metadata"/> using full structural equality
    /// (including fingerprint order) rather than being rewritten, so a
    /// legitimate replay is idempotent while a tampered or reordered
    /// durable copy is still rejected.
    /// </summary>
    internal static void ReplayOrWriteCtLogShardMetadata(
        string metadataPath,
        CtLogShardMetadataFile metadata)
    {
        if (File.Exists(metadataPath))
        {
            var existing = JsonSerializer.Deserialize<
                CtLogShardMetadataFile>(
                    File.ReadAllText(metadataPath),
                    JsonOptions);
            if (existing != metadata)
            {
                throw new InvalidDataException(
                    "The secondary CT shard metadata changed during " +
                    "replay.");
            }
            return;
        }
        WriteCreateNewJson(metadataPath, metadata);
    }

    private async Task<IReadOnlyList<CtLogShardArtifactValidation>>
        VerifyCtArtifactWithAllClientsAsync(
            SigstoreArtifactEvidence? artifact,
            IReadOnlyList<SigstoreClientRegistration> clients,
            SigstoreDiskTrustStatus trust,
            IReadOnlyList<CtLogShardArtifactValidation> existing,
            CtLogShardRotationCommandJournal operation,
            bool isOld,
            CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        var results = existing.ToList();
        foreach (var client in clients)
        {
            var prior = results.SingleOrDefault(
                result => result.Resource == client.Resource.Name);
            if (prior is not null
                && prior.Evidence.ArtifactId == artifact.ArtifactId
                && prior.Evidence.ArtifactSha256
                    == artifact.ArtifactSha256
                && prior.Evidence.BundleSha256 == artifact.BundleSha256
                && prior.Evidence.Generation == trust.Generation
                && prior.Evidence.GenerationId == trust.GenerationId
                && prior.Evidence.TrustedRootSha256
                    == trust.TrustedRootSha256)
            {
                continue;
            }
            var evidence = await runtime.VerifyArtifactAsync(
                client,
                artifact,
                cancellationToken);
            if (evidence.Generation != trust.Generation
                || evidence.GenerationId != trust.GenerationId
                || evidence.TrustedRootSha256
                    != trust.TrustedRootSha256)
            {
                throw new InvalidDataException(
                    $"{client.Resource.Name} verified artifact " +
                    $"{artifact.ArtifactId} with stale trust.");
            }
            results.RemoveAll(
                result => result.Resource == client.Resource.Name);
            results.Add(
                new CtLogShardArtifactValidation(
                    client.Resource.Name,
                    DateTimeOffset.UtcNow,
                    evidence));
            var ordered = results
                .OrderBy(item => item.Resource, StringComparer.Ordinal)
                .ToArray();
            WriteCtLogShardRotationJournal(
                resource.StatePath,
                isOld
                    ? operation with { OldArtifactValidations = ordered }
                    : operation with { NewArtifactValidations = ordered });
        }
        return results
            .OrderBy(result => result.Resource, StringComparer.Ordinal)
            .ToArray();
    }

    /// <summary>
    /// Validates an issuance proof's binding to the expected CA, identity
    /// and certificate-transparency log shard, and that the proof's short
    /// -lived certificate was valid at the moment the proof was durably
    /// recorded — <paramref name="provedAtUtc"/> — rather than at the
    /// current wall clock. The proof is captured once and journaled; every
    /// later replay of this step (including long after the certificate's
    /// <c>NotAfter</c> has passed) must accept the same durable evidence,
    /// so validity is a property of when the proof was made, not of when
    /// it is re-checked.
    /// </summary>
    internal static void ValidateCtIssuanceProof(
        SigstoreFulcioIssuanceProof proof,
        string expectedRoot,
        string expectedCtLogId,
        DateTimeOffset? provedAtUtc,
        string description)
    {
        if (!proof.SctVerified
            || proof.RootSha256 != expectedRoot
            || proof.CtLogId != expectedCtLogId
            || proof.Identity != SigstoreDefaults.ExpectedIdentity
            || provedAtUtc is not { } provedAt
            || provedAt < proof.NotBeforeUtc
            || provedAt > proof.NotAfterUtc)
        {
            throw new InvalidDataException(
                $"{description} is not bound to the expected CA, identity, " +
                "and certificate-transparency log shard.");
        }
    }

    private static string CtLogShardHostingJournalPath(
        string statePath,
        string operationId) =>
        Path.Combine(
            statePath,
            "ct-log-shard-rotation",
            operationId,
            "hosting-state.json");

    private static CtLogShardRotationCommandJournal?
        LoadIncompleteCtLogShardRotation(string statePath)
    {
        var journals = SigstoreCtLogShard.ReadRotationJournals(statePath)
            .Where(journal => journal.Status != CtCompletedStatus)
            .ToArray();
        return journals.Length switch
        {
            0 => null,
            1 => journals[0],
            _ => throw new InvalidDataException(
                "Multiple incomplete CT log shard rotation operations " +
                "exist.")
        };
    }

    private static void WriteCtLogShardRotationJournal(
        string statePath,
        CtLogShardRotationCommandJournal operation)
    {
        var path = CtLogShardHostingJournalPath(
            statePath,
            operation.OperationId);
        var directory = Path.GetDirectoryName(path)
            ?? throw new InvalidDataException(
                $"Path '{path}' has no parent directory.");
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(
            directory,
            $".hosting-state.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp");
        var data = JsonSerializer.Serialize(operation, JsonOptions) + "\n";
        using (var stream = new FileStream(
            temporary,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough))
        {
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    temporary,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
            stream.Write(Encoding.UTF8.GetBytes(data));
            stream.Flush(flushToDisk: true);
        }
        File.Move(temporary, path, overwrite: true);
        SyncParentDirectory(path);
    }

    private static void WriteCtLogShardRotationRequest(
        string statePath,
        CtLogShardRotationCommandJournal operation)
    {
        var request = new CtLogShardRotationWorkerRequest(
            SchemaVersion: 1,
            OperationId: operation.OperationId,
            TrustDomainId: operation.TrustDomainId,
            StartingGeneration: operation.StartingGeneration,
            StartingGenerationId: operation.StartingGenerationId,
            StartingGenerationManifestSha256:
                operation.StartingGenerationManifestSha256,
            StartingCtLogPublicKeySha256:
                operation.StartingCtLogPublicKeySha256,
            PriorShardId: operation.PriorShardId,
            PriorShardUrl: operation.PriorShardUrl,
            CandidateShardId: operation.CandidateShardId
                ?? throw new InvalidDataException(
                    "The CT log rotation candidate shard ID is missing."),
            CandidateShardUrl: SigstoreCtLogShard.SecondaryUrl,
            CandidateOrigin: SigstoreCtLogShard.SecondaryOrigin,
            CandidatePublicKeySha256: operation.CandidatePublicKeySha256
                ?? throw new InvalidDataException(
                    "The CT log rotation candidate public key is missing."),
            CandidateStateId: operation.CandidateStateId
                ?? throw new InvalidDataException(
                    "The CT log rotation candidate state ID is missing."),
            CandidateCreatedAtUtc: operation.CandidateCreatedAtUtc
                ?? throw new InvalidDataException(
                    "The CT log rotation candidate creation time is " +
                    "missing."));
        var path = Path.Combine(statePath, "rotate-ct-log-shard.request");
        if (File.Exists(path))
        {
            var existing = JsonSerializer.Deserialize<
                CtLogShardRotationWorkerRequest>(
                    File.ReadAllText(path),
                    JsonOptions);
            if (existing != request)
            {
                throw new InvalidDataException(
                    "The surviving CT log shard rotation worker request " +
                    "belongs to another operation or candidate.");
            }
            return;
        }
        WriteCreateNewJson(path, request);
    }

    private static CtLogShardRotationWorkerCompletion?
        ReadCtLogShardRotationWorkerCompletion(string statePath)
    {
        var path = Path.Combine(statePath, "rotate-ct-log-shard.completed");
        if (!File.Exists(path))
        {
            return null;
        }
        var completion = JsonSerializer.Deserialize<
            CtLogShardRotationWorkerCompletion>(
                File.ReadAllText(path),
                JsonOptions)
            ?? throw new InvalidDataException(
                "The CT log shard rotation worker completion is empty.");
        if (completion.SchemaVersion != 1
            || !Guid.TryParseExact(completion.OperationId, "N", out _)
            || completion.OperationId.Any(char.IsUpper)
            || completion.PriorGeneration < 1
            || completion.NewGeneration != completion.PriorGeneration + 1
            || completion.PriorGenerationId
                != $"generation-{completion.PriorGeneration:D8}"
            || completion.NewGenerationId
                != $"generation-{completion.NewGeneration:D8}"
            || !IsLowerHexSha256(completion.PriorGenerationManifestSha256)
            || !IsLowerHexSha256(completion.GenerationManifestSha256)
            || !IsLowerHexSha256(completion.PriorPublicKeySha256)
            || !IsLowerHexSha256(completion.NewPublicKeySha256)
            || completion.PriorShardId
                != $"sha256-{completion.PriorPublicKeySha256}"
            || completion.NewShardId
                != $"sha256-{completion.NewPublicKeySha256}"
            || completion.PriorBaseUrl != SigstoreCtLogShard.PrimaryUrl
            || completion.NewBaseUrl != SigstoreCtLogShard.SecondaryUrl
            || completion.PriorOrigin != SigstoreCtLogShard.PrimaryOrigin
            || completion.NewOrigin != SigstoreCtLogShard.SecondaryOrigin
            || string.IsNullOrWhiteSpace(completion.PriorStateId)
            || string.IsNullOrWhiteSpace(completion.NewStateId)
            || string.IsNullOrWhiteSpace(completion.PublicationId)
            || !IsLowerHexSha256(completion.PublicationManifestSha256)
            || !IsLowerHexSha256(completion.TrustedRootSha256)
            || !IsLowerHexSha256(completion.SigningConfigSha256)
            || completion.NewTrustedRootCtlogCount
                != completion.PriorTrustedRootCtlogCount + 1)
        {
            throw new InvalidDataException(
                "The CT log shard rotation worker completion is invalid.");
        }
        return completion;
    }

    private static void ValidateCtLogShardRotationCompletion(
        CtLogShardRotationWorkerCompletion completion,
        CtLogShardRotationCommandJournal operation,
        SigstoreOperationSnapshot after)
    {
        if (completion.OperationId != operation.OperationId
            || completion.TrustDomainId != operation.TrustDomainId
            || completion.PriorGeneration != operation.StartingGeneration
            || completion.PriorGenerationId
                != operation.StartingGenerationId
            || completion.PriorGenerationManifestSha256
                != operation.StartingGenerationManifestSha256
            || completion.PriorPublicKeySha256
                != operation.StartingCtLogPublicKeySha256
            || completion.PriorShardId != operation.PriorShardId
            || completion.PriorBaseUrl != operation.PriorShardUrl
            || completion.PriorStateId != operation.StartingCtLogStateId
            || completion.NewGeneration
                != operation.StartingGeneration + 1
            || completion.NewGenerationId != after.Tuf.Trust.GenerationId
            || completion.GenerationManifestSha256
                != after.Tuf.Trust.GenerationManifestSha256
            || completion.NewPublicKeySha256
                != operation.CandidatePublicKeySha256
            || completion.NewShardId != operation.CandidateShardId
            || completion.NewStateId != operation.CandidateStateId
            || completion.PublicationId != after.Tuf.Trust.PublicationId
            || completion.PublicationManifestSha256
                != after.Tuf.Trust.PublicationManifestSha256
            || completion.TrustedRootSha256
                != after.Tuf.Trust.TrustedRootSha256
            || completion.SigningConfigSha256
                != after.Tuf.Trust.SigningConfigSha256)
        {
            throw new InvalidDataException(
                "The CT log shard rotation worker completion does not " +
                "match the durable operation or committed trust state.");
        }
    }

    private static void ValidateCtLogShardPublicationPostconditions(
        OperationExecution execution,
        CtLogShardRotationCommandJournal operation,
        SigstoreOperationSnapshot before,
        SigstoreOperationSnapshot after,
        IReadOnlyList<SigstoreCtLogTrustEntry> ctlogEntries,
        CtLogShardCatalog catalog)
    {
        var completion = operation.WorkerCompletion
            ?? throw new InvalidDataException(
                "CT log shard rotation worker completion is missing.");
        execution.Check(
            "generation-advanced",
            after.Tuf.Trust.Generation
                    == before.Tuf.Trust.Generation + 1
                && after.Tuf.Trust.GenerationId
                    != before.Tuf.Trust.GenerationId,
            $"generation {before.Tuf.Trust.Generation + 1}",
            $"generation {after.Tuf.Trust.Generation}",
            "worker-postconditions",
            "tuf-bootstrap");
        CheckEqual(
            execution,
            "trust-domain-unchanged",
            before.Tuf.Trust.TrustDomainId,
            after.Tuf.Trust.TrustDomainId);
        CheckEqual(
            execution,
            "tuf-root-unchanged",
            before.Tuf.Metadata.Root,
            after.Tuf.Metadata.Root);
        CheckEqual(
            execution,
            "bootstrap-root-unchanged",
            before.Tuf.BootstrapRootSha256,
            after.Tuf.BootstrapRootSha256);
        CheckEqual(
            execution,
            "signing-config-unchanged",
            before.Tuf.Trust.SigningConfigSha256,
            after.Tuf.Trust.SigningConfigSha256);
        execution.Check(
            "trusted-root-additive-change",
            before.Tuf.Trust.TrustedRootSha256
                != after.Tuf.Trust.TrustedRootSha256,
            "changed TrustedRoot hash",
            after.Tuf.Trust.TrustedRootSha256,
            "worker-postconditions",
            "tuf-bootstrap");
        execution.Check(
            "publication-advanced-with-prior-history",
            after.Tuf.Trust.PublicationId
                    != before.Tuf.Trust.PublicationId
                && after.Tuf.PreviousPublicationId
                    == before.Tuf.Trust.PublicationId
                && after.Tuf.PreviousPublicationManifestSha256
                    == before.Tuf.Trust.PublicationManifestSha256,
            $"{before.Tuf.Trust.PublicationId}/" +
                before.Tuf.Trust.PublicationManifestSha256,
            $"{after.Tuf.Trust.PublicationId}/" +
                $"{after.Tuf.Trust.PublicationManifestSha256} previous=" +
                $"{after.Tuf.PreviousPublicationId}/" +
                after.Tuf.PreviousPublicationManifestSha256,
            "worker-postconditions",
            "tuf-bootstrap");
        CheckAdvanced(
            execution,
            "targets-advanced",
            before.Tuf.Metadata.Targets,
            after.Tuf.Metadata.Targets);
        CheckAdvanced(
            execution,
            "snapshot-advanced",
            before.Tuf.Metadata.Snapshot,
            after.Tuf.Metadata.Snapshot);
        CheckAdvanced(
            execution,
            "timestamp-metadata-advanced",
            before.Tuf.Metadata.Timestamp,
            after.Tuf.Metadata.Timestamp);

        var priorEntry = ctlogEntries.SingleOrDefault(
            entry => entry.PublicKeySha256
                    == operation.StartingCtLogPublicKeySha256
                && entry.BaseUrl == operation.PriorShardUrl);
        execution.Check(
            "old-ct-trust-preserved",
            priorEntry is not null,
            $"{operation.PriorShardUrl}/" +
                operation.StartingCtLogPublicKeySha256,
            priorEntry is null
                ? "missing"
                : $"{priorEntry.BaseUrl}/{priorEntry.PublicKeySha256}",
            "worker-postconditions",
            "trusted_root.json");
        var newEntry = ctlogEntries.Count > 0
            ? ctlogEntries[^1]
            : null;
        execution.Check(
            "new-ct-trust-appended",
            ctlogEntries.Count == completion.NewTrustedRootCtlogCount
                && completion.NewTrustedRootCtlogCount
                    == completion.PriorTrustedRootCtlogCount + 1
                && newEntry is not null
                && newEntry.PublicKeySha256
                    == completion.NewPublicKeySha256
                && newEntry.BaseUrl == SigstoreCtLogShard.SecondaryUrl,
            $"{completion.PriorTrustedRootCtlogCount + 1} entries ending " +
                "in the new shard",
            $"{ctlogEntries.Count} entries ending in " +
                $"{newEntry?.BaseUrl}/{newEntry?.PublicKeySha256}",
            "worker-postconditions",
            "trusted_root.json");
        execution.Check(
            "ct-shard-catalog-switched",
            catalog.Shards.Count == 2
                && catalog.ActiveShardId == operation.CandidateShardId
                && catalog.Shards[0].Status == "historical"
                && catalog.Shards[0].PublicKeySha256
                    == operation.StartingCtLogPublicKeySha256
                && catalog.Shards[0].StateId
                    == operation.StartingCtLogStateId
                && catalog.Shards[1].Status == "active"
                && catalog.Shards[1].PublicKeySha256
                    == operation.CandidatePublicKeySha256
                && catalog.Shards[1].StateId == operation.CandidateStateId,
            $"two shards active on {operation.CandidateShardId}",
            $"{catalog.Shards.Count} shards active on " +
                catalog.ActiveShardId,
            "worker-postconditions",
            "ct-log-shard-catalog");
        execution.Check(
            "ct-shard-accepted-roots-recorded",
            catalog.Shards.Count == 2
                && catalog.Shards[1].AcceptedRootsSha256
                    == operation.CandidateAcceptedRootsSha256
                && catalog.Shards[1].AcceptedRootFingerprints.SequenceEqual(
                    operation.CandidateAcceptedRootFingerprints,
                    StringComparer.Ordinal)
                && catalog.Shards[0].AcceptedRootsSha256
                    == catalog.Shards[1].AcceptedRootsSha256
                && catalog.Shards[0].AcceptedRootFingerprints.SequenceEqual(
                    catalog.Shards[1].AcceptedRootFingerprints,
                    StringComparer.Ordinal),
            $"{operation.CandidateAcceptedRootFingerprints.Count} accepted " +
                $"Fulcio roots ({operation.CandidateAcceptedRootsSha256})",
            catalog.Shards.Count == 2
                ? $"{catalog.Shards[1].AcceptedRootCount} accepted Fulcio " +
                    $"roots ({catalog.Shards[1].AcceptedRootsSha256})"
                : "no secondary shard entry",
            "worker-postconditions",
            "ct-log-shard-catalog");
        execution.Check(
            "disk-served-after-ct-publish",
            MatchesServed(after.Tuf, after.Served),
            Describe(after.Tuf),
            Describe(after.Served),
            "worker-postconditions",
            after.TufServer.Resource);
        execution.Check(
            "tuf-server-not-restarted",
            SameInstance(before.TufServer, after.TufServer)
                && IsRunningHealthy(after.TufServer),
            Describe(before.TufServer),
            Describe(after.TufServer),
            "worker-postconditions",
            after.TufServer.Resource);
    }

    private static IReadOnlyList<CtLogShardClientConvergence>
        UpsertCtClientConvergence(
            IReadOnlyList<CtLogShardClientConvergence> existing,
            CtLogShardClientConvergence current) =>
        existing
            .Where(item => item.Resource != current.Resource)
            .Append(current)
            .OrderBy(item => item.Resource, StringComparer.Ordinal)
            .ToArray();

    private static CtLogShardRotationEvidence
        BuildCtLogShardRotationEvidence(
            CtLogShardRotationCommandJournal operation,
            bool recovered) =>
        new(
            operation.OperationId,
            operation.Status,
            recovered,
            operation.StartingGeneration,
            operation.StartingGenerationId,
            operation.WorkerCompletion?.NewGeneration,
            operation.WorkerCompletion?.NewGenerationId,
            operation.PriorShardId,
            operation.PriorShardUrl,
            operation.PriorShardOrigin,
            operation.StartingCtLogPublicKeySha256,
            operation.StartingCtLogStateId,
            operation.StartingCheckpoint,
            operation.CandidateShardId,
            operation.CandidateShardId is null
                ? null
                : SigstoreCtLogShard.SecondaryUrl,
            operation.CandidateShardId is null
                ? null
                : SigstoreCtLogShard.SecondaryOrigin,
            operation.CandidatePublicKeySha256,
            operation.CandidateStateId,
            operation.SecondaryCheckpoint,
            operation.WorkerCompletion?.PublicationId,
            operation.WorkerCompletion?.GenerationManifestSha256,
            operation.WorkerCompletion?.PriorTrustedRootCtlogCount,
            operation.WorkerCompletion?.NewTrustedRootCtlogCount,
            operation.FulcioRootSha256,
            operation.FulcioContainerId,
            operation.FulcioAfterContainerId,
            operation.PrimaryContainerId,
            operation.SecondaryContainerId,
            operation.OldShardProof,
            operation.NewShardProof,
            operation.OldArtifact,
            operation.NewArtifact,
            operation.Clients,
            operation.OldArtifactValidations,
            operation.NewArtifactValidations);

    private static ExecuteCommandResult CreateCtLogShardResult(
        OperationExecution execution,
        bool success,
        string message,
        CtLogShardRotationEvidence? evidence)
    {
        var startedAtUtc = execution.Progress.Count > 0
            ? execution.Progress[0].ObservedAtUtc
            : DateTimeOffset.UtcNow;
        var result = new CtLogShardRotationOperationResult(
            1,
            SigstoreOperationCommand.RotateCtLogShardCommand,
            execution.OperationId.ToString("N"),
            success,
            execution.Phase,
            message,
            startedAtUtc,
            DateTimeOffset.UtcNow,
            execution.Progress,
            execution.Before,
            execution.After,
            execution.Resources,
            execution.Checks,
            execution.CommittedStatePreserved,
            execution.Errors,
            evidence);
        var json = JsonSerializer.Serialize(result, JsonOptions);
        return new ExecuteCommandResult
        {
            Success = success,
            Message = message,
            Data = new CommandResultData
            {
                Value = json,
                Format = CommandResultFormat.Json,
                DisplayImmediately = true
            }
        };
    }
}

internal sealed record CtLogShardRotationWorkerRequest(
    int SchemaVersion,
    string OperationId,
    string TrustDomainId,
    int StartingGeneration,
    string StartingGenerationId,
    string StartingGenerationManifestSha256,
    string StartingCtLogPublicKeySha256,
    string PriorShardId,
    string PriorShardUrl,
    string CandidateShardId,
    string CandidateShardUrl,
    string CandidateOrigin,
    string CandidatePublicKeySha256,
    string CandidateStateId,
    DateTimeOffset CandidateCreatedAtUtc);

internal sealed record CtLogShardRotationWorkerCompletion(
    int SchemaVersion,
    string OperationId,
    string TrustDomainId,
    DateTimeOffset CompletedAtUtc,
    int PriorGeneration,
    string PriorGenerationId,
    string PriorGenerationManifestSha256,
    string PriorPublicKeySha256,
    string PriorShardId,
    string PriorBaseUrl,
    string PriorOrigin,
    string PriorStateId,
    int NewGeneration,
    string NewGenerationId,
    string GenerationManifestSha256,
    string NewPublicKeySha256,
    string NewShardId,
    string NewBaseUrl,
    string NewOrigin,
    string NewStateId,
    string PublicationId,
    string PublicationManifestSha256,
    string TrustedRootSha256,
    string SigningConfigSha256,
    int PriorTrustedRootCtlogCount,
    int NewTrustedRootCtlogCount,
    string Action);

internal sealed record CtLogShardMetadataFile(
    int SchemaVersion,
    string OperationId,
    string TrustDomainId,
    string ShardId,
    string Slot,
    string BaseUrl,
    string Origin,
    string PublicKeySha256,
    string LogIdSha256,
    string StateId,
    string DataPath,
    string ResourceName,
    DateTimeOffset CreatedAtUtc,
    string AcceptedRootsSha256,
    int AcceptedRootCount,
    IReadOnlyList<string> AcceptedRootFingerprints)
{
    // The compiler-synthesized record equality compares
    // AcceptedRootFingerprints as an IReadOnlyList<string>, which has no
    // value-equality implementation and therefore falls back to reference
    // equality. That makes every replay — which always deserializes a
    // brand-new list instance from shard.json — spuriously look "changed"
    // even when every fingerprint is identical and in the same order. This
    // override restores real structural equality, including fingerprint
    // order, so replay is idempotent and tampering (content or order) is
    // still rejected.
    public bool Equals(CtLogShardMetadataFile? other) =>
        other is not null
        && SchemaVersion == other.SchemaVersion
        && string.Equals(
            OperationId, other.OperationId, StringComparison.Ordinal)
        && string.Equals(
            TrustDomainId, other.TrustDomainId, StringComparison.Ordinal)
        && string.Equals(ShardId, other.ShardId, StringComparison.Ordinal)
        && string.Equals(Slot, other.Slot, StringComparison.Ordinal)
        && string.Equals(BaseUrl, other.BaseUrl, StringComparison.Ordinal)
        && string.Equals(Origin, other.Origin, StringComparison.Ordinal)
        && string.Equals(
            PublicKeySha256,
            other.PublicKeySha256,
            StringComparison.Ordinal)
        && string.Equals(
            LogIdSha256, other.LogIdSha256, StringComparison.Ordinal)
        && string.Equals(StateId, other.StateId, StringComparison.Ordinal)
        && string.Equals(DataPath, other.DataPath, StringComparison.Ordinal)
        && string.Equals(
            ResourceName, other.ResourceName, StringComparison.Ordinal)
        && CreatedAtUtc == other.CreatedAtUtc
        && string.Equals(
            AcceptedRootsSha256,
            other.AcceptedRootsSha256,
            StringComparison.Ordinal)
        && AcceptedRootCount == other.AcceptedRootCount
        && AcceptedRootFingerprints.SequenceEqual(
            other.AcceptedRootFingerprints,
            StringComparer.Ordinal);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.Add(SchemaVersion);
        hash.Add(OperationId, StringComparer.Ordinal);
        hash.Add(TrustDomainId, StringComparer.Ordinal);
        hash.Add(ShardId, StringComparer.Ordinal);
        hash.Add(Slot, StringComparer.Ordinal);
        hash.Add(BaseUrl, StringComparer.Ordinal);
        hash.Add(Origin, StringComparer.Ordinal);
        hash.Add(PublicKeySha256, StringComparer.Ordinal);
        hash.Add(LogIdSha256, StringComparer.Ordinal);
        hash.Add(StateId, StringComparer.Ordinal);
        hash.Add(DataPath, StringComparer.Ordinal);
        hash.Add(ResourceName, StringComparer.Ordinal);
        hash.Add(CreatedAtUtc);
        hash.Add(AcceptedRootsSha256, StringComparer.Ordinal);
        hash.Add(AcceptedRootCount);
        foreach (var fingerprint in AcceptedRootFingerprints)
        {
            hash.Add(fingerprint, StringComparer.Ordinal);
        }
        return hash.ToHashCode();
    }
}

internal sealed record CtLogShardClientConvergence(
    string Resource,
    string ContainerId,
    DateTime? StartTimeUtc,
    DateTimeOffset ConvergedAtUtc,
    SigstoreClientTrustStatus Status);

internal sealed record CtLogShardArtifactValidation(
    string Resource,
    DateTimeOffset VerifiedAtUtc,
    SigstoreClientArtifactVerification Evidence);

internal sealed record CtLogShardRotationCommandJournal(
    int SchemaVersion,
    string OperationId,
    string Status,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset? CompletedAtUtc,
    string TrustDomainId,
    int StartingGeneration,
    string StartingGenerationId,
    string StartingGenerationManifestSha256,
    string StartingCtLogPublicKeySha256,
    string StartingCtLogStateId,
    SigstoreCtCheckpoint StartingCheckpoint,
    string PriorShardId,
    string PriorShardUrl,
    string PriorShardOrigin,
    SigstoreOperationSnapshot StartingSnapshot,
    string PrimaryResourceId,
    string PrimaryContainerId,
    DateTime? PrimaryStartTimeUtc,
    string FulcioResourceId,
    string FulcioContainerId,
    DateTime? FulcioStartTimeUtc,
    IReadOnlyList<SigstoreResourceInstanceSnapshot> ProtectedResources,
    string FulcioRootSha256,
    SigstoreArtifactEvidence OldArtifact,
    string? CandidatePublicKeySha256,
    string? CandidateLogId,
    string? CandidateShardId,
    string? CandidateStateId,
    DateTimeOffset? CandidateCreatedAtUtc,
    string? CandidateAcceptedRootsSha256,
    IReadOnlyList<string> CandidateAcceptedRootFingerprints,
    string? SecondaryResourceId,
    string? SecondaryContainerId,
    DateTime? SecondaryStartTimeUtc,
    SigstoreCtCheckpoint? SecondaryCheckpoint,
    CtLogShardRotationWorkerCompletion? WorkerCompletion,
    IReadOnlyList<CtLogShardClientConvergence> Clients,
    DateTimeOffset? ClientsConvergedAtUtc,
    SigstoreFulcioIssuanceProof? OldShardProof,
    DateTimeOffset? OldShardProvedAtUtc,
    DateTimeOffset? RuntimeActivatedAtUtc,
    string? FulcioAfterContainerId,
    DateTime? FulcioAfterStartTimeUtc,
    SigstoreFulcioIssuanceProof? NewShardProof,
    DateTimeOffset? NewShardProvedAtUtc,
    IReadOnlyList<CtLogShardArtifactValidation> OldArtifactValidations,
    SigstoreArtifactEvidence? NewArtifact,
    IReadOnlyList<CtLogShardArtifactValidation> NewArtifactValidations);

internal sealed record CtLogShardRotationEvidence(
    string OperationId,
    string Status,
    bool Recovered,
    int StartingGeneration,
    string StartingGenerationId,
    int? NewGeneration,
    string? NewGenerationId,
    string PriorShardId,
    string PriorShardUrl,
    string PriorShardOrigin,
    string PriorPublicKeySha256,
    string PriorStateId,
    SigstoreCtCheckpoint PriorCheckpoint,
    string? NewShardId,
    string? NewShardUrl,
    string? NewShardOrigin,
    string? NewPublicKeySha256,
    string? NewStateId,
    SigstoreCtCheckpoint? NewShardCheckpoint,
    string? PublicationId,
    string? GenerationManifestSha256,
    int? PriorTrustedRootCtlogCount,
    int? NewTrustedRootCtlogCount,
    string FulcioRootSha256,
    string FulcioBeforeContainerId,
    string? FulcioAfterContainerId,
    string PrimaryCtLogContainerId,
    string? SecondaryCtLogContainerId,
    SigstoreFulcioIssuanceProof? OldShardProof,
    SigstoreFulcioIssuanceProof? NewShardProof,
    SigstoreArtifactEvidence OldArtifact,
    SigstoreArtifactEvidence? NewArtifact,
    IReadOnlyList<CtLogShardClientConvergence> Clients,
    IReadOnlyList<CtLogShardArtifactValidation> OldArtifactValidations,
    IReadOnlyList<CtLogShardArtifactValidation> NewArtifactValidations);

internal sealed record CtLogShardRotationOperationResult(
    int SchemaVersion,
    string Command,
    string OperationId,
    bool Success,
    string Phase,
    string Message,
    DateTimeOffset StartedAtUtc,
    DateTimeOffset CompletedAtUtc,
    IReadOnlyList<SigstoreOperationProgress> Progress,
    SigstoreOperationSnapshot? Before,
    SigstoreOperationSnapshot? After,
    IReadOnlyList<SigstoreResourceLifecycleResult> Resources,
    IReadOnlyList<SigstoreOperationCheck> Postconditions,
    bool? CommittedStatePreserved,
    IReadOnlyList<SigstoreOperationError> Errors,
    CtLogShardRotationEvidence? CtLogShardRotation);
