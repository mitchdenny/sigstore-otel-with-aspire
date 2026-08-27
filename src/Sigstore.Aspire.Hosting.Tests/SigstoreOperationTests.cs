using System.Collections.Concurrent;
using System.Text.Json;
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

namespace Sigstore.Aspire.Hosting.Tests;

public sealed class SigstoreOperationTests
{
    private static readonly DateTime ResourceBaseTime =
        new(2026, 8, 27, 0, 0, 0, DateTimeKind.Utc);

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    [Fact]
    public void CommandsRegisterConfirmationProgressAndDynamicState()
    {
        using var model = new OperationModelFixture();
        var annotations = model.Parent.Resource.Annotations
            .OfType<ResourceCommandAnnotation>()
            .ToDictionary(
                annotation => annotation.Name,
                StringComparer.Ordinal);

        Assert.Equal(
            [
                "status",
                SigstoreOperationCommand.RefreshTufCommand,
                SigstoreOperationCommand.RestartClientsCommand
            ],
            annotations.Keys);

        foreach (var name in new[]
        {
            SigstoreOperationCommand.RefreshTufCommand,
            SigstoreOperationCommand.RestartClientsCommand
        })
        {
            var annotation = annotations[name];
            Assert.False(
                string.IsNullOrWhiteSpace(annotation.ConfirmationMessage));
            Assert.False(
                string.IsNullOrWhiteSpace(annotation.DisplayDescription));
            Assert.NotNull(annotation.Progress);
            Assert.False(
                string.IsNullOrWhiteSpace(annotation.Progress!.Message));
            Assert.True(annotation.Progress.HideCancelButton);
            Assert.Equal(
                ResourceCommandState.Enabled,
                annotation.UpdateState(NewUpdateContext()));
        }

        Assert.True(
            model.Parent.Resource.TryBeginOperation(
                SigstoreOperationCommand.RefreshTufCommand,
                "Refreshing TUF",
                out var lease,
                out _));
        lease!.Report(
            "postconditions",
            3,
            6,
            "Checking metadata.");

        Assert.Equal(
            ResourceCommandState.Disabled,
            annotations[SigstoreOperationCommand.RefreshTufCommand]
                .UpdateState(NewUpdateContext()));
        Assert.Equal(
            ResourceCommandState.Disabled,
            annotations[SigstoreOperationCommand.RestartClientsCommand]
                .UpdateState(NewUpdateContext()));

        var snapshot = SigstoreParentHealthMonitor.CreateParentSnapshot(
            model.Parent.Resource,
            NewParentSnapshot());
        Assert.Equal("Refreshing TUF", snapshot.State?.Text);
        Assert.Contains(
            snapshot.Properties,
            property => property.Name == "Operation"
                && Equals(
                    property.Value,
                    SigstoreOperationCommand.RefreshTufCommand));
        Assert.Contains(
            snapshot.Properties,
            property => property.Name == "Operation progress"
                && property.Value?.ToString()?.StartsWith(
                    "3/6",
                    StringComparison.Ordinal) == true);

        lease.Dispose();
        snapshot = SigstoreParentHealthMonitor.CreateParentSnapshot(
            model.Parent.Resource,
            snapshot);
        Assert.Equal("Healthy", snapshot.State?.Text);
        Assert.DoesNotContain(
            snapshot.Properties,
            property => property.Name == "Operation");
    }

    [Fact]
    public async Task RefreshUsesLockedWorkerHandoffAndStructuredResults()
    {
        using var model = new OperationModelFixture();
        var before = NewTufState();
        var after = NewTufState(before, refresh: true);
        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        inspector.TufStates.Enqueue(before);
        inspector.TufStates.Enqueue(after);
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.TrustFingerprints.Enqueue(Hash('2'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));

        var runtime = NewRuntime(model, events, inspector);
        runtime.ServedStates.Enqueue(NewServed(before));
        runtime.ServedStates.Enqueue(NewServed(after));
        runtime.Statuses.Enqueue(NewAggregate(model, before));
        runtime.Statuses.Enqueue(NewAggregate(model, after));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-id"),
            Running("tuf", "tuf-id"),
            Running("tuf", "tuf-id"));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.TufBootstrap.Resource,
            Exited("tuf-bootstrap", "worker-before", 0));
        runtime.WaitResults[
            model.Parent.Resource.Components.TufBootstrap.Resource.Name] =
            Exited("tuf-bootstrap", "worker-after", 0, offsetSeconds: 10);

        var executor = NewExecutor(model, runtime, inspector);
        var result = await executor.ExecuteRefreshTufAsync(
            CancellationToken.None);
        var output = ReadResult(result);

        Assert.True(result.Success);
        Assert.True(output.Success);
        Assert.Equal(
            SigstoreOperationCommand.RefreshTufCommand,
            output.Command);
        Assert.Equal(1, output.Before!.Tuf.Metadata.Snapshot.Version);
        Assert.Equal(2, output.After!.Tuf.Metadata.Snapshot.Version);
        Assert.Equal(
            before.Trust.PublicationId,
            output.After.Tuf.PreviousPublicationId);
        Assert.Single(output.Resources);
        Assert.Equal("worker-before", output.Resources[0].BeforeContainerId);
        Assert.Equal("worker-after", output.Resources[0].AfterContainerId);
        Assert.All(
            output.Postconditions,
            check => Assert.True(check.Passed, check.Name));
        Assert.Equal(
            [
                "preflight",
                "start-worker",
                "wait-worker",
                "postconditions",
                "aggregate-status",
                "final-verification",
                "complete"
            ],
            output.Progress.Select(item => item.Phase));
        Assert.True(runtime.WorkerStartedWhileLockHeld);
        Assert.True(runtime.WorkerWaitedAfterLockHandoff);
        Assert.True(
            IndexOf(events, "lock:release:dashboard-refresh-tuf-preflight")
            < IndexOf(events, "wait:tuf-bootstrap"));
        Assert.Null(model.Parent.Resource.GetPresentation().Operation);
    }

    [Fact]
    public async Task ConcurrentCommandIsRejectedAndGateRecovers()
    {
        using var model = new OperationModelFixture();
        var before = NewTufState();
        var after = NewTufState(before, refresh: true);
        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        inspector.TufStates.Enqueue(before);
        inspector.TufStates.Enqueue(after);
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.TrustFingerprints.Enqueue(Hash('2'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        var runtime = NewRuntime(model, events, inspector);
        runtime.ServedStates.Enqueue(NewServed(before));
        runtime.ServedStates.Enqueue(NewServed(after));
        runtime.Statuses.Enqueue(NewAggregate(model, before));
        runtime.Statuses.Enqueue(NewAggregate(model, after));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-id"),
            Running("tuf", "tuf-id"),
            Running("tuf", "tuf-id"));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.TufBootstrap.Resource,
            Exited("tuf-bootstrap", "worker-before", 0));
        runtime.WaitResults["tuf-bootstrap"] =
            Exited("tuf-bootstrap", "worker-after", 0, offsetSeconds: 10);
        runtime.BlockWorkerStart = true;

        var executor = NewExecutor(model, runtime, inspector);
        var refresh = executor.ExecuteRefreshTufAsync(
            CancellationToken.None);
        await runtime.WorkerStartEntered.Task.WaitAsync(
            TimeSpan.FromSeconds(5));

        var contending = await executor.ExecuteRestartClientsAsync(
            CancellationToken.None);
        var contention = ReadResult(contending);
        Assert.False(contending.Success);
        Assert.Equal("contention", contention.Phase);
        Assert.Contains(
            "refresh-tuf is already active",
            contention.Message,
            StringComparison.Ordinal);

        runtime.ReleaseWorkerStart.SetResult();
        Assert.True((await refresh).Success);
        Assert.Null(model.Parent.Resource.GetPresentation().Operation);
        Assert.Equal(
            ResourceCommandState.Enabled,
            SigstoreOperationCommand.GetMutationCommandState(
                model.Parent.Resource));
    }

    [Fact]
    public async Task WorkerExitFailurePreservesCommittedRepository()
    {
        using var model = new OperationModelFixture();
        var before = NewTufState();
        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        inspector.TufStates.Enqueue(before);
        inspector.TufStates.Enqueue(before);
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        var runtime = NewRuntime(model, events, inspector);
        runtime.ServedStates.Enqueue(NewServed(before));
        runtime.ServedStates.Enqueue(NewServed(before));
        runtime.Statuses.Enqueue(NewAggregate(model, before));
        runtime.Statuses.Enqueue(NewAggregate(model, before));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-id"),
            Running("tuf", "tuf-id"));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.TufBootstrap.Resource,
            Exited("tuf-bootstrap", "worker-before", 0));
        runtime.WaitResults["tuf-bootstrap"] =
            Exited("tuf-bootstrap", "worker-after", 17, offsetSeconds: 10);

        var result = await NewExecutor(model, runtime, inspector)
            .ExecuteRefreshTufAsync(CancellationToken.None);
        var output = ReadResult(result);

        Assert.False(result.Success);
        Assert.True(output.CommittedStatePreserved);
        Assert.Contains(
            output.Postconditions,
            check => check.Name
                == "failed-worker-preserved-disk-publication"
                && check.Passed);
        Assert.Contains(
            runtime.WaitedResources,
            resourceName => resourceName == "tuf-bootstrap");
        Assert.Null(model.Parent.Resource.GetPresentation().Operation);
    }

    [Fact]
    public async Task RefreshFailsWhenSnapshotDoesNotAdvance()
    {
        using var model = new OperationModelFixture();
        var before = NewTufState();
        var after = NewTufState(before, refresh: true) with
        {
            Metadata = NewTufState(before, refresh: true).Metadata with
            {
                Snapshot = before.Metadata.Snapshot
            }
        };
        var (executor, _, _) = ConfigureRefresh(
            model,
            before,
            after);

        var result = await executor.ExecuteRefreshTufAsync(
            CancellationToken.None);
        var output = ReadResult(result);

        Assert.False(result.Success);
        Assert.Contains(
            output.Postconditions,
            check => check.Name == "snapshot-advanced"
                && !check.Passed);
        Assert.Contains(
            output.Errors,
            error => error.Postcondition == "snapshot-advanced");
        Assert.Null(model.Parent.Resource.GetPresentation().Operation);
    }

    [Fact]
    public async Task RefreshFailsWhenTufServerIdentityChanges()
    {
        using var model = new OperationModelFixture();
        var before = NewTufState();
        var after = NewTufState(before, refresh: true);
        var (executor, runtime, _) = ConfigureRefresh(
            model,
            before,
            after,
            configureServerSnapshots: false);
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-before"),
            Running("tuf", "tuf-after", offsetSeconds: 10),
            Running("tuf", "tuf-after", offsetSeconds: 10));

        var result = await executor.ExecuteRefreshTufAsync(
            CancellationToken.None);
        var output = ReadResult(result);

        Assert.False(result.Success);
        Assert.Contains(
            output.Postconditions,
            check => check.Name == "tuf-server-not-restarted"
                && !check.Passed);
        Assert.Null(model.Parent.Resource.GetPresentation().Operation);
    }

    [Fact]
    public async Task RestartClientsIsSortedHealthyAndTrustPreserving()
    {
        using var model = new OperationModelFixture();
        var tuf = NewTufState();
        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        inspector.TufStates.Enqueue(tuf);
        inspector.TufStates.Enqueue(tuf);
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        var runtime = NewRuntime(model, events, inspector);
        runtime.ServedStates.Enqueue(NewServed(tuf));
        runtime.ServedStates.Enqueue(NewServed(tuf));
        runtime.Statuses.Enqueue(NewAggregate(model, tuf));
        runtime.Statuses.Enqueue(NewAggregate(model, tuf));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-id"),
            Running("tuf", "tuf-id"));

        var clients = model.Parent.Resource
            .GetRegistrations()
            .Clients
            .OrderBy(client => client.Resource.Name, StringComparer.Ordinal)
            .ToArray();
        foreach (var client in clients)
        {
            var before = Running(
                client.Resource.Name,
                $"{client.Resource.Name}-before");
            var after = Running(
                client.Resource.Name,
                $"{client.Resource.Name}-after",
                offsetSeconds: 10);
            runtime.SetSnapshotSequence(
                client.Resource,
                before,
                after);
            runtime.WaitResults[client.Resource.Name] = after;
            runtime.ClientStatuses[client.Resource.Name] =
                NewClientStatus(client, tuf.Trust);
        }

        var result = await NewExecutor(model, runtime, inspector)
            .ExecuteRestartClientsAsync(CancellationToken.None);
        var output = ReadResult(result);

        Assert.True(result.Success);
        Assert.Equal(6, output.Resources.Count);
        Assert.All(
            output.Resources,
            lifecycle => Assert.NotEqual(
                lifecycle.BeforeContainerId,
                lifecycle.AfterContainerId));
        Assert.Equal(
            clients.Select(client => client.Resource.Name),
            runtime.ExecutedCommands.Select(call => call.Resource));
        Assert.All(
            runtime.ExecutedCommands,
            call => Assert.Equal(
                KnownResourceCommands.RestartCommand,
                call.Command));
        Assert.Equal(
            clients.Select(client => client.Resource.Name),
            runtime.WaitedResources.Where(name => name != "sigstore"));
        Assert.All(
            output.Postconditions,
            check => Assert.True(check.Passed, check.Name));
        Assert.Equal(
            output.Before!.TrustStateSha256,
            output.After!.TrustStateSha256);
        Assert.Null(model.Parent.Resource.GetPresentation().Operation);
    }

    [Fact]
    public async Task RestartFailurePreservesTrustAndRecoversCommandState()
    {
        using var model = new OperationModelFixture();
        var tuf = NewTufState();
        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        inspector.TufStates.Enqueue(tuf);
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        var runtime = NewRuntime(model, events, inspector);
        runtime.ServedStates.Enqueue(NewServed(tuf));
        runtime.Statuses.Enqueue(NewAggregate(model, tuf));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-id"));

        var firstClient = model.Parent.Resource
            .GetRegistrations()
            .Clients
            .OrderBy(client => client.Resource.Name, StringComparer.Ordinal)
            .First();
        runtime.SetSnapshotSequence(
            firstClient.Resource,
            Running(
                firstClient.Resource.Name,
                $"{firstClient.Resource.Name}-before"));
        runtime.WaitFailures[firstClient.Resource.Name] =
            new OperationCanceledException("Injected health timeout.");

        var result = await NewExecutor(model, runtime, inspector)
            .ExecuteRestartClientsAsync(CancellationToken.None);
        var output = ReadResult(result);

        Assert.False(result.Success);
        Assert.True(output.CommittedStatePreserved);
        Assert.Contains(
            "did not become healthy",
            output.Message,
            StringComparison.Ordinal);
        Assert.Null(model.Parent.Resource.GetPresentation().Operation);
        Assert.Equal(
            ResourceCommandState.Enabled,
            SigstoreOperationCommand.GetMutationCommandState(
                model.Parent.Resource));
    }

    [Fact]
    public async Task SharedStateLockContentionFailsPromptlyAndRecovers()
    {
        using var model = new OperationModelFixture();
        var inspector = new SigstoreFileStateInspector();
        using var held = inspector.AcquireLock(
            model.Parent.Resource.StatePath,
            "test-holder");
        var runtime = new FakeRuntime(
            new ConcurrentQueue<string>(),
            () => false);

        var result = await NewExecutor(model, runtime, inspector)
            .ExecuteRefreshTufAsync(CancellationToken.None);
        var output = ReadResult(result);

        Assert.False(result.Success);
        Assert.Contains(
            output.Errors,
            error => error.Message.Contains(
                "locked by another operation",
                StringComparison.Ordinal));
        Assert.Null(model.Parent.Resource.GetPresentation().Operation);
    }

    private static (
        SigstoreOperationExecutor Executor,
        FakeRuntime Runtime,
        FakeStateInspector Inspector) ConfigureRefresh(
        OperationModelFixture model,
        SigstoreTufStateSnapshot before,
        SigstoreTufStateSnapshot after,
        bool configureServerSnapshots = true)
    {
        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        inspector.TufStates.Enqueue(before);
        inspector.TufStates.Enqueue(after);
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.TrustFingerprints.Enqueue(Hash('2'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        var runtime = NewRuntime(model, events, inspector);
        runtime.ServedStates.Enqueue(NewServed(before));
        runtime.ServedStates.Enqueue(NewServed(after));
        runtime.Statuses.Enqueue(NewAggregate(model, before));
        runtime.Statuses.Enqueue(NewAggregate(model, after));
        if (configureServerSnapshots)
        {
            runtime.SetSnapshotSequence(
                model.Parent.Resource.Components.Tuf.Resource,
                Running("tuf", "tuf-id"),
                Running("tuf", "tuf-id"),
                Running("tuf", "tuf-id"));
        }
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.TufBootstrap.Resource,
            Exited("tuf-bootstrap", "worker-before", 0));
        runtime.WaitResults["tuf-bootstrap"] =
            Exited("tuf-bootstrap", "worker-after", 0, offsetSeconds: 10);
        return (
            NewExecutor(model, runtime, inspector),
            runtime,
            inspector);
    }

    private static FakeRuntime NewRuntime(
        OperationModelFixture model,
        ConcurrentQueue<string> events,
        FakeStateInspector inspector) =>
        new(
            events,
            () => inspector.LockHeld);

    private static SigstoreOperationExecutor NewExecutor(
        OperationModelFixture model,
        ISigstoreOperationRuntime runtime,
        ISigstoreStateInspector inspector) =>
        new(
            model.Parent.Resource,
            runtime,
            inspector,
            NullLogger.Instance);

    private static SigstoreOperationResult ReadResult(
        ExecuteCommandResult result) =>
        JsonSerializer.Deserialize<SigstoreOperationResult>(
            result.Data?.Value
                ?? throw new InvalidOperationException(
                    "Command result omitted JSON data."),
            JsonOptions)
        ?? throw new InvalidOperationException(
            "Command result JSON was empty.");

    private static UpdateCommandStateContext NewUpdateContext() =>
        new()
        {
            ResourceSnapshot = NewParentSnapshot(),
            Services = new EmptyServiceProvider()
        };

    private static CustomResourceSnapshot NewParentSnapshot() =>
        new()
        {
            ResourceType = "Sigstore",
            State = new ResourceStateSnapshot(
                "Healthy",
                KnownResourceStateStyles.Success),
            Properties = []
        };

    private static SigstoreTufStateSnapshot NewTufState(
        SigstoreTufStateSnapshot? prior = null,
        bool refresh = false)
    {
        var future = DateTimeOffset.UtcNow.AddDays(30);
        var root = prior?.Metadata.Root
            ?? new SigstoreTufMetadataRoleStatus(
                1,
                Hash('a'),
                future.AddDays(300));
        var targets = prior?.Metadata.Targets
            ?? new SigstoreTufMetadataRoleStatus(
                1,
                Hash('b'),
                future.AddDays(300));
        var snapshot = refresh
            ? new SigstoreTufMetadataRoleStatus(
                prior!.Metadata.Snapshot.Version + 1,
                Hash('e'),
                prior.Metadata.Snapshot.ExpiresAtUtc.AddMinutes(1))
            : new SigstoreTufMetadataRoleStatus(
                1,
                Hash('c'),
                future);
        var timestamp = refresh
            ? new SigstoreTufMetadataRoleStatus(
                prior!.Metadata.Timestamp.Version + 1,
                Hash('f'),
                prior.Metadata.Timestamp.ExpiresAtUtc.AddMinutes(1))
            : new SigstoreTufMetadataRoleStatus(
                1,
                Hash('d'),
                future);
        var manifest = refresh ? Hash('9') : Hash('8');
        var trust = new SigstoreDiskTrustStatus(
            "sha256-" + Hash('0'),
            1,
            "generation-00000001",
            Hash('1'),
            root.Version,
            targets.Version,
            Hash('6'),
            Hash('7'),
            "sha256-" + manifest,
            manifest);
        return new SigstoreTufStateSnapshot(
            trust,
            new SigstoreTufMetadataStatus(
                root,
                targets,
                snapshot,
                timestamp,
                trust.TrustedRootSha256,
                trust.SigningConfigSha256),
            Hash('2'),
            Hash('3'),
            Hash('4'),
            refresh ? prior!.Trust.PublicationId : null,
            refresh
                ? prior!.Trust.PublicationManifestSha256
                : null);
    }

    private static SigstoreServedTufSnapshot NewServed(
        SigstoreTufStateSnapshot state) =>
        new(
            new SigstoreServedTrustStatus(
                state.Trust.TrustDomainId,
                state.Trust.Generation,
                state.Trust.GenerationId,
                state.Trust.GenerationManifestSha256,
                state.Trust.TufRootVersion,
                state.Trust.TufTargetsVersion,
                state.Trust.TrustedRootSha256,
                state.Trust.SigningConfigSha256),
            state.Metadata);

    private static SigstoreAggregateTrustStatus NewAggregate(
        OperationModelFixture model,
        SigstoreTufStateSnapshot state)
    {
        var clients = model.Parent.Resource
            .GetRegistrations()
            .Clients
            .Select(client => NewClientStatus(client, state.Trust))
            .ToArray();
        return new SigstoreAggregateTrustStatus(
            1,
            "sigstore",
            true,
            "Healthy",
            null,
            DateTimeOffset.UtcNow,
            state.Trust,
            NewServed(state).Trust,
            clients,
            [],
            []);
    }

    private static SigstoreClientTrustStatus NewClientStatus(
        SigstoreClientRegistration client,
        SigstoreDiskTrustStatus trust) =>
        new(
            1,
            client.Resource.Name,
            client.Language,
            true,
            null,
            trust.TrustDomainId,
            trust.Generation,
            trust.GenerationId,
            trust.GenerationManifestSha256,
            trust.TufRootVersion,
            trust.TufTargetsVersion,
            trust.TrustedRootSha256,
            trust.SigningConfigSha256,
            DateTimeOffset.UtcNow);

    private static SigstoreResourceInstanceSnapshot Running(
        string resource,
        string containerId,
        int offsetSeconds = 0) =>
        new(
            resource,
            resource,
            KnownResourceStates.Running,
            nameof(HealthStatus.Healthy),
            null,
            ResourceBaseTime.AddSeconds(offsetSeconds),
            ResourceBaseTime.AddSeconds(offsetSeconds),
            null,
            containerId);

    private static SigstoreResourceInstanceSnapshot Exited(
        string resource,
        string containerId,
        int exitCode,
        int offsetSeconds = 0) =>
        new(
            resource,
            resource,
            KnownResourceStates.Exited,
            "Unknown",
            exitCode,
            ResourceBaseTime.AddSeconds(offsetSeconds),
            ResourceBaseTime.AddSeconds(offsetSeconds),
            ResourceBaseTime.AddSeconds(offsetSeconds + 1),
            containerId);

    private static string Hash(char value) =>
        new(value, 64);

    private static int IndexOf(
        ConcurrentQueue<string> events,
        string value) =>
        Array.IndexOf(events.ToArray(), value);

    private sealed class OperationModelFixture : IDisposable
    {
        public OperationModelFixture()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-operation-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
            Directory.CreateDirectory(
                System.IO.Path.Combine(Path, ".sigstore"));
            var sourcePath = System.IO.Path.Combine(
                FindRepositoryRoot(),
                "src");
            var builder = DistributedApplication.CreateBuilder(
                new DistributedApplicationOptions
                {
                    AssemblyName =
                        typeof(SigstoreOperationTests).Assembly.FullName,
                    ProjectDirectory = Path,
                    DisableDashboard = true
                });
            Parent = builder.AddSigstore(
                "sigstore",
                new SigstoreOptions
                {
                    SourcePath = sourcePath
                });
            foreach (var (name, language) in new[]
            {
                ("rust-client", "rust"),
                ("python-client", "python"),
                ("javascript-client", "javascript"),
                ("java-client", "java"),
                ("go-client", "go"),
                ("dotnet-client", "dotnet")
            })
            {
                builder
                    .AddContainer(name, "alpine")
                    .WithHttpEndpoint(targetPort: 8080, name: "http")
                    .WithReference(
                        Parent,
                        new SigstoreClientOptions
                        {
                            Language = language,
                            TrustStatusEndpointName = "http"
                        });
            }
            Parent.Resource.SetRuntimeHealth(
                new SigstoreRuntimeHealthSnapshot(
                    "Healthy",
                    null,
                    [],
                    14,
                    14));
        }

        public string Path { get; }

        public IResourceBuilder<SigstoreResource> Parent { get; }

        public void Dispose()
        {
            Directory.Delete(Path, recursive: true);
        }

        private static string FindRepositoryRoot()
        {
            for (var directory = new DirectoryInfo(
                    AppContext.BaseDirectory);
                directory is not null;
                directory = directory.Parent)
            {
                if (File.Exists(
                        System.IO.Path.Combine(
                            directory.FullName,
                            "apphost.cs"))
                    && Directory.Exists(
                        System.IO.Path.Combine(
                            directory.FullName,
                            "src",
                            "Sigstore.Bootstrap")))
                {
                    return directory.FullName;
                }
            }

            throw new DirectoryNotFoundException(
                "Unable to locate the repository root for hosting tests.");
        }
    }

    private sealed class FakeStateInspector(
        ConcurrentQueue<string> events) : ISigstoreStateInspector
    {
        private int _lockCount;

        public Queue<SigstoreTufStateSnapshot> TufStates { get; } = [];

        public Queue<string> TrustFingerprints { get; } = [];

        public Queue<string> MaterialFingerprints { get; } = [];

        public bool LockHeld => Volatile.Read(ref _lockCount) != 0;

        public IDisposable AcquireLock(
            string statePath,
            string operation)
        {
            if (Interlocked.Increment(ref _lockCount) != 1)
            {
                Interlocked.Decrement(ref _lockCount);
                throw new InvalidOperationException(
                    "Fake state lock was acquired recursively.");
            }
            events.Enqueue($"lock:acquire:{operation}");
            return new CallbackDisposable(
                () =>
                {
                    events.Enqueue($"lock:release:{operation}");
                    Interlocked.Decrement(ref _lockCount);
                });
        }

        public SigstoreTufStateSnapshot ReadTufState(string statePath) =>
            TufStates.Dequeue();

        public string ReadTrustStateFingerprint(string statePath) =>
            TrustFingerprints.Dequeue();

        public string ReadTrustMaterialFingerprint(string statePath) =>
            MaterialFingerprints.Dequeue();
    }

    private sealed class FakeRuntime(
        ConcurrentQueue<string> events,
        Func<bool> isLockHeld) : ISigstoreOperationRuntime
    {
        private readonly Dictionary<
            string,
            Queue<SigstoreResourceInstanceSnapshot>> _snapshots =
            new(StringComparer.Ordinal);

        public Queue<SigstoreAggregateTrustStatus> Statuses { get; } = [];

        public Queue<SigstoreServedTufSnapshot> ServedStates { get; } = [];

        public Dictionary<string, SigstoreResourceInstanceSnapshot>
            WaitResults { get; } = new(StringComparer.Ordinal);

        public Dictionary<string, Exception> WaitFailures { get; } =
            new(StringComparer.Ordinal);

        public Dictionary<string, SigstoreClientTrustStatus>
            ClientStatuses { get; } = new(StringComparer.Ordinal);

        public List<(string Resource, string Command)> ExecutedCommands
        {
            get;
        } = [];

        public List<string> WaitedResources { get; } = [];

        public ExecuteCommandResult CommandResult { get; set; } =
            CommandResults.Success();

        public bool BlockWorkerStart { get; set; }

        public bool WorkerStartedWhileLockHeld { get; private set; }

        public bool WorkerWaitedAfterLockHandoff { get; private set; }

        public TaskCompletionSource WorkerStartEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource ReleaseWorkerStart { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public void SetSnapshotSequence(
            IResource target,
            params SigstoreResourceInstanceSnapshot[] snapshots) =>
            _snapshots[target.Name] = new Queue<
                SigstoreResourceInstanceSnapshot>(snapshots);

        public SigstoreResourceInstanceSnapshot GetRequiredSnapshot(
            IResource target)
        {
            events.Enqueue($"get:{target.Name}");
            if (!_snapshots.TryGetValue(
                    target.Name,
                    out var snapshots)
                || snapshots.Count == 0)
            {
                throw new InvalidOperationException(
                    $"No fake snapshot remains for {target.Name}.");
            }
            return snapshots.Dequeue();
        }

        public async Task<ExecuteCommandResult> ExecuteCommandAsync(
            IResource target,
            string command,
            CancellationToken cancellationToken)
        {
            events.Enqueue($"execute:{target.Name}:{command}");
            ExecutedCommands.Add((target.Name, command));
            if (target.Name == "tuf-bootstrap")
            {
                WorkerStartedWhileLockHeld = isLockHeld();
                WorkerStartEntered.TrySetResult();
                if (BlockWorkerStart)
                {
                    await ReleaseWorkerStart.Task.WaitAsync(
                        cancellationToken);
                }
            }
            return CommandResult;
        }

        public Task<SigstoreResourceInstanceSnapshot> WaitForSnapshotAsync(
            IResource target,
            Func<SigstoreResourceInstanceSnapshot, bool> predicate,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            events.Enqueue($"wait:{target.Name}");
            WaitedResources.Add(target.Name);
            if (target.Name == "tuf-bootstrap")
            {
                WorkerWaitedAfterLockHandoff = !isLockHeld();
            }
            if (WaitFailures.TryGetValue(target.Name, out var failure))
            {
                return Task.FromException<
                    SigstoreResourceInstanceSnapshot>(failure);
            }
            var result = WaitResults[target.Name];
            if (!predicate(result))
            {
                throw new InvalidOperationException(
                    $"Fake wait result for {target.Name} failed its predicate.");
            }
            return Task.FromResult(result);
        }

        public Task WaitForAggregateHealthyAsync(
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            events.Enqueue("wait:sigstore");
            WaitedResources.Add("sigstore");
            return Task.CompletedTask;
        }

        public Task<SigstoreAggregateTrustStatus> CollectStatusAsync(
            CancellationToken cancellationToken)
        {
            events.Enqueue("status");
            return Task.FromResult(Statuses.Dequeue());
        }

        public Task<SigstoreServedTufSnapshot> ReadServedTufStateAsync(
            CancellationToken cancellationToken)
        {
            events.Enqueue("served");
            return Task.FromResult(ServedStates.Dequeue());
        }

        public Task<SigstoreClientTrustStatus> ReadClientStatusAsync(
            SigstoreClientRegistration client,
            CancellationToken cancellationToken)
        {
            events.Enqueue($"client-status:{client.Resource.Name}");
            return Task.FromResult(
                ClientStatuses[client.Resource.Name]);
        }

        public Task PublishParentStateAsync(SigstoreResource target)
        {
            events.Enqueue(
                $"publish:{target.GetPresentation().Operation?.Phase
                    ?? "idle"}");
            return Task.CompletedTask;
        }
    }

    private sealed class CallbackDisposable(Action callback) : IDisposable
    {
        private Action? _callback = callback;

        public void Dispose()
        {
            Interlocked.Exchange(ref _callback, null)?.Invoke();
        }
    }

    private sealed class EmptyServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
