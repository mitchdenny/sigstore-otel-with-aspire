using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Logging.Abstractions;
using Sigstore.Bootstrap;
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
                SigstoreOperationCommand.RotateTufRootCommand,
                SigstoreOperationCommand.RestartClientsCommand,
                SigstoreOperationCommand.PublishTrustedRootCommand,
                SigstoreOperationCommand.RotateOidcSigningKeyCommand,
                SigstoreOperationCommand.RotateTimestampAuthorityCommand,
                SigstoreOperationCommand.RotateFulcioCaCommand,
                SigstoreOperationCommand.RotateRekorShardCommand
            ],
            annotations.Keys);

        foreach (var name in new[]
        {
            SigstoreOperationCommand.RefreshTufCommand,
            SigstoreOperationCommand.RotateTufRootCommand,
            SigstoreOperationCommand.RestartClientsCommand,
            SigstoreOperationCommand.PublishTrustedRootCommand,
            SigstoreOperationCommand.RotateOidcSigningKeyCommand,
            SigstoreOperationCommand.RotateTimestampAuthorityCommand,
            SigstoreOperationCommand.RotateFulcioCaCommand,
            SigstoreOperationCommand.RotateRekorShardCommand
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

        model.Parent.Resource.SetOperationRecovery(
            SigstoreOperationCommand.RotateTimestampAuthorityCommand,
            "clients-converged",
            "TSA Activation Pending",
            "Timestamp restart remains pending.");
        snapshot = SigstoreParentHealthMonitor.CreateParentSnapshot(
            model.Parent.Resource,
            snapshot);
        Assert.Equal("TSA Activation Pending", snapshot.State?.Text);
        Assert.Equal(
            ResourceCommandState.Disabled,
            annotations[SigstoreOperationCommand.RestartClientsCommand]
                .UpdateState(NewUpdateContext()));
        Assert.Equal(
            ResourceCommandState.Enabled,
            annotations[
                SigstoreOperationCommand.RotateTimestampAuthorityCommand]
                .UpdateState(NewUpdateContext()));
        model.Parent.Resource.ClearOperationRecovery(
            SigstoreOperationCommand.RotateTimestampAuthorityCommand);

        var statePath = model.Parent.Resource.StatePath;
        var fulcioMounts = model.Parent.Resource.Components.Fulcio.Resource
            .Annotations
            .OfType<ContainerMountAnnotation>()
            .Where(
                mount => mount.Target
                    == "/var/lib/sigstore/fulcio")
            .ToArray();
        Assert.Single(fulcioMounts);
        Assert.Equal(
            System.IO.Path.Combine(
                statePath,
                "runtime",
                "fulcio"),
            fulcioMounts[0].Source);
        Assert.Equal(
            "/var/lib/sigstore/fulcio",
            fulcioMounts[0].Target);
        Assert.True(fulcioMounts[0].IsReadOnly);

        var tesseractMounts = model.Parent.Resource.Components.Tesseract
            .Resource
            .Annotations
            .OfType<ContainerMountAnnotation>()
            .OrderBy(mount => mount.Target, StringComparer.Ordinal)
            .ToArray();
        Assert.Equal(2, tesseractMounts.Length);
        Assert.Contains(
            tesseractMounts,
            mount => mount.Source == System.IO.Path.Combine(
                    statePath,
                    "runtime",
                    "tesseract")
                && mount.Target == "/var/lib/sigstore/tesseract"
                && mount.IsReadOnly);
        Assert.Contains(
            tesseractMounts,
            mount => mount.Source == System.IO.Path.Combine(
                    statePath,
                    "data",
                    "ctlog")
                && mount.Target == "/var/lib/sigstore/data/ctlog"
                && !mount.IsReadOnly);
    }

    [Fact]
    public async Task OidcRotationUsesOneWorkerOneIssuerRestartAndNoFulcioRestart()
    {
        using var model = new OperationModelFixture();
        var oldKid = new string('a', 43);
        var newKid = new string('b', 43);
        var before = NewTufState();
        var after = NewOidcRotationTufState(before);
        var statePath = model.Parent.Resource.StatePath;
        var activePath = System.IO.Path.Combine(
            statePath,
            "active-generation");
        Directory.CreateDirectory(activePath);
        File.WriteAllText(
            System.IO.Path.Combine(activePath, "manifest.json"),
            JsonSerializer.Serialize(new { oidcKeyId = oldKid }));

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
        runtime.Statuses.Enqueue(NewAggregate(model, after));
        runtime.OidcTokens.Enqueue((CreateOidcJwt(oldKid), oldKid));
        runtime.OidcTokens.Enqueue((CreateOidcJwt(oldKid), oldKid));
        runtime.OidcTokens.Enqueue((CreateOidcJwt(newKid), newKid));
        var now = DateTimeOffset.UtcNow;
        runtime.FulcioCertificates.Enqueue(new FulcioIssuanceEvidence(
            Hash('a'), "CN=leaf", "CN=fulcio", SigstoreDefaults.ExpectedIdentity,
            now.AddMinutes(-1), now.AddMinutes(9)));
        runtime.FulcioCertificates.Enqueue(new FulcioIssuanceEvidence(
            Hash('b'), "CN=leaf", "CN=fulcio", SigstoreDefaults.ExpectedIdentity,
            now.AddMinutes(-1), now.AddMinutes(9)));

        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-id"),
            Running("tuf", "tuf-id"));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.TufBootstrap.Resource,
            Exited("tuf-bootstrap", "worker-before", 0));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Oidc.Resource,
            Running("oidc", "oidc-before"),
            Running("oidc", "oidc-before"));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Fulcio.Resource,
            Running("fulcio", "fulcio-id"),
            Running("fulcio", "fulcio-id"),
            Running("fulcio", "fulcio-id"));
        runtime.WaitResults["tuf-bootstrap"] =
            Exited("tuf-bootstrap", "worker-after", 0, offsetSeconds: 10);
        runtime.WaitResults["oidc"] =
            Running("oidc", "oidc-after", offsetSeconds: 10);

        foreach (var client in model.Parent.Resource.GetRegistrations().Clients)
        {
            runtime.SetSnapshotSequence(
                client.Resource,
                Running(client.Resource.Name, $"{client.Resource.Name}-before"));
            runtime.WaitResults[client.Resource.Name] = Running(
                client.Resource.Name,
                $"{client.Resource.Name}-after",
                offsetSeconds: 10);
            runtime.ClientStatuses[client.Resource.Name] =
                NewClientStatus(client, after.Trust);
        }

        runtime.OnExecuteCommand = (target, command) =>
        {
            if (target.Name != "tuf-bootstrap"
                || command != KnownResourceCommands.StartCommand)
            {
                return;
            }
            var requestPath = System.IO.Path.Combine(
                statePath,
                "rotate-oidc-signing-key.request");
            using var request = JsonDocument.Parse(
                File.ReadAllText(requestPath));
            var operationId = request.RootElement
                .GetProperty("operationId")
                .GetString()!;
            File.WriteAllText(
                System.IO.Path.Combine(activePath, "manifest.json"),
                JsonSerializer.Serialize(new { oidcKeyId = newKid }));
            File.WriteAllText(
                System.IO.Path.Combine(
                    statePath,
                    "rotate-oidc-signing-key.completed"),
                JsonSerializer.Serialize(new
                {
                    schemaVersion = 2,
                    operationId,
                    trustDomainId = before.Trust.TrustDomainId,
                    priorGeneration = 1,
                    priorGenerationId = "generation-00000001",
                    priorOidcKeyId = oldKid,
                    newGeneration = 2,
                    newGenerationId = "generation-00000002",
                    newOidcKeyId = newKid,
                    publicationId = after.Trust.PublicationId,
                    manifestSha256 = after.Trust.GenerationManifestSha256,
                    jwksSha256 = Hash('4'),
                    jwksKeyIds = new[] { newKid, oldKid },
                    retainedKeyPaths = new[]
                    {
                        $"private/oidc/retained/signer-{oldKid}.key"
                    },
                    overlapExpiresAtUtc = now.AddMinutes(6).ToString("O")
                }));
            File.Delete(requestPath);
        };

        var result = await NewExecutor(model, runtime, inspector)
            .ExecuteRotateOidcSigningKeyAsync(CancellationToken.None);
        var output = ReadResult(result);

        Assert.True(
            result.Success,
            output.Message + ": " + string.Join(
                "; ",
                output.Errors.Select(
                    error => $"{error.Postcondition}: {error.Message}")));
        Assert.NotNull(output.OidcRotation);
        Assert.Equal(oldKid, output.OidcRotation.OldKid);
        Assert.Equal(newKid, output.OidcRotation.NewKid);
        Assert.Equal(2, output.OidcRotation.NewGeneration);
        Assert.Equal(
            1,
            runtime.ExecutedCommands.Count(item =>
                item.Resource == "tuf-bootstrap"
                && item.Command == KnownResourceCommands.StartCommand));
        Assert.Equal(
            1,
            runtime.ExecutedCommands.Count(item =>
                item.Resource == "oidc"
                && item.Command == KnownResourceCommands.RestartCommand));
        Assert.DoesNotContain(
            runtime.ExecutedCommands,
            item => item.Resource == "fulcio");
        Assert.Equal(
            6,
            runtime.ExecutedCommands.Count(item =>
                item.Resource.EndsWith("-client", StringComparison.Ordinal)
                && item.Command == KnownResourceCommands.RestartCommand));
        Assert.False(runtime.WorkerStartedWhileLockHeld);
        Assert.All(output.Postconditions, check =>
            Assert.True(check.Passed, check.Name));
        Assert.False(File.ReadAllText(
            System.IO.Path.Combine(
                statePath,
                "oidc-rotation",
                output.OidcRotation.OperationId,
                "command.json"))
            .Contains(CreateOidcJwt(oldKid), StringComparison.Ordinal));
    }

    [Fact]
    public async Task TimestampRotationConvergesClientsBeforeOneServiceRestart()
    {
        using var model = new OperationModelFixture();
        var statePath = model.Parent.Resource.StatePath;
        var bootstrap = SigstoreStateBootstrapper.EnsureInitialized(
            statePath);
        var oldMaterial =
            SigstoreStateBootstrapper.ValidateTimestampAuthority(
                System.IO.Path.Combine(
                    statePath,
                    "active-generation"));
        WriteTrustedRoot(
            statePath,
            [
                ReadTsaCertificates(
                    System.IO.Path.Combine(
                        statePath,
                        "active-generation"))
            ]);

        var before = NewTufState();
        var after = NewTsaRotationTufState(before);
        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        inspector.TufStates.Enqueue(before);
        inspector.TufStates.Enqueue(after);
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.TrustFingerprints.Enqueue(Hash('2'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        inspector.MaterialFingerprints.Enqueue(Hash('4'));
        var runtime = NewRuntime(model, events, inspector);
        runtime.ServedStates.Enqueue(NewServed(before));
        runtime.ServedStates.Enqueue(NewServed(after));
        runtime.Statuses.Enqueue(NewAggregate(model, before));
        runtime.Statuses.Enqueue(NewAggregate(model, after));

        var oldProof = NewTimestampProof(
            oldMaterial.RootSha256,
            oldMaterial.LeafSha256,
            'a') with
        {
            RequestSha256 = HashBytes([1, 2, 3]),
            ResponseSha256 = HashBytes([4, 5, 6])
        };
        var newRoot = string.Empty;
        var newLeaf = string.Empty;
        runtime.TimestampProbes.Enqueue(
            new SigstoreTimestampAuthorityProbe(
                [1, 2, 3],
                [4, 5, 6],
                oldProof));
        runtime.TimestampProbes.Enqueue(
            new SigstoreTimestampAuthorityProbe(
                [7],
                [8],
                oldProof));
        runtime.TimestampProbes.Enqueue(
            new SigstoreTimestampAuthorityProbe(
                [9],
                [10],
                oldProof));
        runtime.StoredTimestampProofs.Enqueue(oldProof);

        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.TufBootstrap.Resource,
            Exited("tuf-bootstrap", "worker-before", 0));
        runtime.WaitResults["tuf-bootstrap"] =
            Exited(
                "tuf-bootstrap",
                "worker-after",
                0,
                offsetSeconds: 10);
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Timestamp.Resource,
            Running("timestamp", "timestamp-before"),
            Running("timestamp", "timestamp-before"),
            Running("timestamp", "timestamp-before"));
        runtime.WaitResults["timestamp"] =
            Running(
                "timestamp",
                "timestamp-after",
                offsetSeconds: 30);

        foreach (var protectedResource in model.Parent.Resource
            .GetRegistrations()
            .RequiredResources
            .Where(
                item =>
                    item.Name != "timestamp"
                    && !item.Name.EndsWith(
                        "-client",
                        StringComparison.Ordinal)))
        {
            var snapshot = Running(
                protectedResource.Name,
                $"{protectedResource.Name}-stable");
            runtime.SetSnapshotSequence(
                protectedResource,
                snapshot,
                snapshot);
        }
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-stable"),
            Running("tuf", "tuf-stable"),
            Running("tuf", "tuf-stable"),
            Running("tuf", "tuf-stable"));

        var clients = model.Parent.Resource.GetRegistrations().Clients
            .OrderBy(
                client => client.Resource.Name,
                StringComparer.Ordinal)
            .ToArray();
        foreach (var client in clients)
        {
            var clientBefore = Running(
                client.Resource.Name,
                $"{client.Resource.Name}-before");
            var clientAfter = Running(
                client.Resource.Name,
                $"{client.Resource.Name}-after",
                offsetSeconds: 20);
            runtime.SetSnapshotSequence(
                client.Resource,
                clientBefore);
            runtime.WaitResults[client.Resource.Name] = clientAfter;
            runtime.ClientStatusSequences[client.Resource.Name] =
                new Queue<SigstoreClientTrustStatus>(
                    [
                        NewClientStatus(client, before.Trust),
                        NewClientStatus(client, after.Trust)
                    ]);
        }

        runtime.OnExecuteCommand = (target, command) =>
        {
            if (target.Name != "tuf-bootstrap"
                || command != KnownResourceCommands.StartCommand)
            {
                return;
            }
            using var request = JsonDocument.Parse(
                File.ReadAllBytes(
                    System.IO.Path.Combine(
                        statePath,
                        "rotate-timestamp-authority.request")));
            var operationId = request.RootElement
                .GetProperty("operationId")
                .GetString()!;
            var candidatePath = System.IO.Path.Combine(
                statePath,
                "tsa-rotation",
                operationId,
                "candidate");
            var candidate =
                SigstoreStateBootstrapper.ValidateTimestampAuthority(
                    candidatePath);
            newRoot = candidate.RootSha256;
            newLeaf = candidate.LeafSha256;

            var priorPath = System.IO.Path.Combine(
                statePath,
                "generations",
                bootstrap.Generation.GenerationId);
            var nextId = "generation-00000002";
            var nextPath = System.IO.Path.Combine(
                statePath,
                "generations",
                nextId);
            CopyDirectory(priorPath, nextPath);
            File.Delete(
                System.IO.Path.Combine(nextPath, "manifest.json"));
            Directory.Delete(
                System.IO.Path.Combine(nextPath, "private", "tsa"),
                recursive: true);
            Directory.Delete(
                System.IO.Path.Combine(nextPath, "public", "tsa"),
                recursive: true);
            CopyDirectory(candidatePath, nextPath);
            File.WriteAllText(
                System.IO.Path.Combine(nextPath, "manifest.json"),
                JsonSerializer.Serialize(
                    new
                    {
                        generation = 2,
                        generationId = nextId,
                        tsaRootSha256 = newRoot,
                        tsaLeafSha256 = newLeaf,
                        tsaRotationOperationId = operationId
                    }));
            Directory.Delete(
                System.IO.Path.Combine(
                    statePath,
                    "active-generation"));
            Directory.CreateSymbolicLink(
                System.IO.Path.Combine(
                    statePath,
                    "active-generation"),
                System.IO.Path.Combine("generations", nextId));
            WriteTrustedRoot(
                statePath,
                [
                    ReadTsaCertificates(priorPath),
                    ReadTsaCertificates(nextPath)
                ]);
            File.WriteAllText(
                System.IO.Path.Combine(
                    statePath,
                    "rotate-timestamp-authority.completed"),
                JsonSerializer.Serialize(
                    new
                    {
                        schemaVersion = 1,
                        operationId,
                        trustDomainId = before.Trust.TrustDomainId,
                        completedAtUtc = DateTimeOffset.UtcNow,
                        priorGeneration = 1,
                        priorGenerationId = "generation-00000001",
                        priorTsaRootSha256 = oldMaterial.RootSha256,
                        priorTsaLeafSha256 = oldMaterial.LeafSha256,
                        newGeneration = 2,
                        newGenerationId = nextId,
                        newTsaRootSha256 = newRoot,
                        newTsaLeafSha256 = newLeaf,
                        manifestSha256 =
                            after.Trust.GenerationManifestSha256,
                        publicationId = after.Trust.PublicationId,
                        publicationManifestSha256 =
                            after.Trust.PublicationManifestSha256,
                        trustedRootSha256 =
                            after.Trust.TrustedRootSha256,
                        signingConfigSha256 =
                            after.Trust.SigningConfigSha256,
                        tsaTrustEntryCount = 2
                    }));
            File.Delete(
                System.IO.Path.Combine(
                    statePath,
                    "rotate-timestamp-authority.request"));
            Directory.Delete(candidatePath, recursive: true);
            runtime.TimestampProbes.Enqueue(
                new SigstoreTimestampAuthorityProbe(
                    [11],
                    [12],
                    NewTimestampProof(newRoot, newLeaf, 'b')));
        };

        var result = await NewExecutor(model, runtime, inspector)
            .ExecuteRotateTimestampAuthorityAsync(
                CancellationToken.None);
        var output = ReadResult(result);

        Assert.True(
            result.Success,
            output.Message + ": " + string.Join(
                "; ",
                output.Errors.Select(
                    error => $"{error.Postcondition}: {error.Message}")));
        Assert.NotNull(output.TimestampAuthorityRotation);
        Assert.Equal(
            oldMaterial.LeafSha256,
            output.TimestampAuthorityRotation.OldLeafSha256);
        Assert.Equal(
            newLeaf,
            output.TimestampAuthorityRotation.NewLeafSha256);
        Assert.True(
            output.TimestampAuthorityRotation
                .HistoricalTimestampValidated);
        Assert.Equal(6, output.TimestampAuthorityRotation.Clients.Count);
        Assert.Equal(8, output.Resources.Count);
        Assert.False(runtime.WorkerStartedWhileLockHeld);
        Assert.Equal(
            1,
            runtime.ExecutedCommands.Count(
                call => call.Resource == "timestamp"
                    && call.Command
                        == KnownResourceCommands.RestartCommand));
        Assert.DoesNotContain(
            runtime.ExecutedCommands,
            call => call.Resource is "oidc"
                or "fulcio"
                or "tesseract"
                or "rekor"
                or "rekor-server"
                or "tuf"
                or "shady-blob-store");
        var timestampRestart = runtime.ExecutedCommands.FindIndex(
            call => call.Resource == "timestamp");
        Assert.Equal(
            6,
            runtime.ExecutedCommands
                .Take(timestampRestart)
                .Count(
                    call => call.Resource.EndsWith(
                        "-client",
                        StringComparison.Ordinal)));
        Assert.All(
            output.Postconditions,
            check => Assert.True(check.Passed, check.Name));
        Assert.Null(model.Parent.Resource.GetPresentation().Recovery);

        var journalPath = System.IO.Path.Combine(
            statePath,
            "tsa-rotation",
            output.TimestampAuthorityRotation.OperationId,
            "command.json");
        var completedJournal = JsonSerializer.Deserialize<
            TimestampAuthorityRotationCommandJournal>(
                File.ReadAllText(journalPath),
                JsonOptions)!;
        File.WriteAllText(
            journalPath,
            JsonSerializer.Serialize(
                completedJournal with
                {
                    Status = "timestamp-restarted",
                    CompletedAtUtc = null
                },
                JsonOptions));

        var replayEvents = new ConcurrentQueue<string>();
        var replayInspector = new FakeStateInspector(replayEvents);
        replayInspector.TufStates.Enqueue(after);
        replayInspector.TrustFingerprints.Enqueue(Hash('2'));
        replayInspector.MaterialFingerprints.Enqueue(Hash('4'));
        var replayRuntime = NewRuntime(
            model,
            replayEvents,
            replayInspector);
        replayRuntime.ServedStates.Enqueue(NewServed(after));
        replayRuntime.Statuses.Enqueue(NewAggregate(model, after));
        replayRuntime.SetSnapshotSequence(
            model.Parent.Resource.Components.TufBootstrap.Resource,
            Exited("tuf-bootstrap", "worker-after", 0));
        replayRuntime.SetSnapshotSequence(
            model.Parent.Resource.Components.Timestamp.Resource,
            Running("timestamp", "timestamp-after", offsetSeconds: 30),
            Running("timestamp", "timestamp-after", offsetSeconds: 30),
            Running("timestamp", "timestamp-after", offsetSeconds: 30));
        foreach (var protectedResource in model.Parent.Resource
            .GetRegistrations()
            .RequiredResources
            .Where(
                item =>
                    item.Name != "timestamp"
                    && !item.Name.EndsWith(
                        "-client",
                        StringComparison.Ordinal)))
        {
            var snapshot = Running(
                protectedResource.Name,
                $"{protectedResource.Name}-stable");
            replayRuntime.SetSnapshotSequence(
                protectedResource,
                snapshot,
                snapshot);
        }
        replayRuntime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-stable"),
            Running("tuf", "tuf-stable"),
            Running("tuf", "tuf-stable"));
        foreach (var client in clients)
        {
            replayRuntime.SetSnapshotSequence(
                client.Resource,
                Running(
                    client.Resource.Name,
                    $"{client.Resource.Name}-after",
                    offsetSeconds: 20));
            replayRuntime.ClientStatuses[client.Resource.Name] =
                NewClientStatus(client, after.Trust);
        }
        var replayProof = NewTimestampProof(newRoot, newLeaf, 'b');
        replayRuntime.TimestampProbes.Enqueue(
            new SigstoreTimestampAuthorityProbe([13], [14], replayProof));
        replayRuntime.TimestampProbes.Enqueue(
            new SigstoreTimestampAuthorityProbe([15], [16], replayProof));
        replayRuntime.TimestampProbes.Enqueue(
            new SigstoreTimestampAuthorityProbe([17], [18], replayProof));
        replayRuntime.StoredTimestampProofs.Enqueue(oldProof);

        var replayResult =
            await NewExecutor(model, replayRuntime, replayInspector)
                .ExecuteRotateTimestampAuthorityAsync(
                    CancellationToken.None);
        var replayOutput = ReadResult(replayResult);

        Assert.True(replayResult.Success, replayOutput.Message);
        Assert.True(replayOutput.TimestampAuthorityRotation!.Recovered);
        Assert.DoesNotContain(
            replayRuntime.ExecutedCommands,
            call => call.Resource == "timestamp"
                || call.Resource.EndsWith(
                    "-client",
                    StringComparison.Ordinal));
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
    public async Task TimestampRotationContentionIsRejectedByGate()
    {
        using var model = new OperationModelFixture();
        Assert.True(
            model.Parent.Resource.TryBeginOperation(
                SigstoreOperationCommand.RotateTimestampAuthorityCommand,
                "Rotating Timestamp Authority",
                out var lease,
                out _));
        try
        {
            var executor = NewExecutor(
                model,
                NewRuntime(
                    model,
                    new ConcurrentQueue<string>(),
                    new FakeStateInspector(
                        new ConcurrentQueue<string>())),
                new FakeStateInspector(
                    new ConcurrentQueue<string>()));

            var result =
                await executor.ExecuteRotateTimestampAuthorityAsync(
                    CancellationToken.None);
            var output = ReadResult(result);

            Assert.False(result.Success);
            Assert.Equal("contention", output.Phase);
            Assert.Contains(
                "rotate-timestamp-authority is already active",
                output.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            lease!.Dispose();
        }
    }

    [Fact]
    public async Task FulcioRotationOrdersTrustClientsTesseractAndIssuer()
    {
        using var model = new OperationModelFixture();
        var statePath = model.Parent.Resource.StatePath;
        var bootstrap = SigstoreStateBootstrapper.EnsureInitialized(
            statePath);
        var oldRoot = bootstrap.Generation.FulcioRootSha256;
        var newRoot = Hash('f');
        var acceptedHash = Hash('d');
        var ctKey = bootstrap.Generation.CtLogPublicKeySha256;
        var before = NewTufState();
        var after = NewFulcioRotationTufState(before);
        var checkpointBefore = new SigstoreCtCheckpoint(
            SigstoreFulcio.CtOrigin,
            10,
            1_000,
            Hash('1'),
            Hash('2'),
            ctKey);
        var checkpointAfter = checkpointBefore with
        {
            TreeSize = 12,
            Timestamp = 4_000,
            RootHash = Hash('3'),
            SignatureSha256 = Hash('4')
        };
        var oldArtifact = NewArtifact(
            100,
            oldRoot,
            ctKey,
            'a');
        var newArtifact = NewArtifact(
            120,
            newRoot,
            ctKey,
            'b');
        var oldStatus = NewFulcioStatus(
            oldRoot,
            oldRoot,
            [oldRoot],
            Hash('0'),
            ctKey,
            checkpointBefore,
            runtimeMatches: true);
        var overlapStatus = NewFulcioStatus(
            newRoot,
            oldRoot,
            [oldRoot, newRoot],
            acceptedHash,
            ctKey,
            checkpointBefore,
            runtimeMatches: false);
        var activatedStatus = overlapStatus with
        {
            RuntimeFulcioMatchesActive = true,
            RuntimePromotionPending = false,
            StagedRootSha256 = null
        };
        var finalStatus = activatedStatus with
        {
            LiveRootSha256 = newRoot,
            LiveRootMatchesActive = true,
            Checkpoint = checkpointAfter
        };

        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events)
        {
            FulcioCandidate = new FulcioCaMaterialInfo(
                newRoot,
                Hash('e'),
                "CN=Fulcio Root, O=Sigstore Aspire Demo",
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddYears(10)),
            FulcioProjection = new FulcioRuntimeProjectionInfo(
                newRoot,
                Hash('e'),
                "CN=Fulcio Root, O=Sigstore Aspire Demo",
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddYears(10),
                ctKey,
                null,
                false,
                acceptedHash,
                [oldRoot, newRoot])
        };
        inspector.TufStates.Enqueue(before);
        inspector.TufStates.Enqueue(after);
        inspector.TrustFingerprints.Enqueue(Hash('5'));
        inspector.TrustFingerprints.Enqueue(Hash('6'));
        inspector.MaterialFingerprints.Enqueue(Hash('7'));
        inspector.MaterialFingerprints.Enqueue(Hash('8'));

        var runtime = NewRuntime(model, events, inspector);
        runtime.ServedStates.Enqueue(NewServed(before));
        runtime.ServedStates.Enqueue(NewServed(after));
        runtime.FulcioStatuses.Enqueue(oldStatus);
        runtime.FulcioStatuses.Enqueue(overlapStatus);
        runtime.FulcioStatuses.Enqueue(overlapStatus);
        runtime.FulcioStatuses.Enqueue(activatedStatus);
        runtime.FulcioStatuses.Enqueue(finalStatus);
        runtime.Artifacts.Enqueue(oldArtifact);
        runtime.Artifacts.Enqueue(newArtifact);
        runtime.OidcTokens.Enqueue((CreateOidcJwt(new string('a', 43)), null));
        runtime.OidcTokens.Enqueue((CreateOidcJwt(new string('a', 43)), null));
        runtime.FulcioProofs.Enqueue(
            NewFulcioProof(oldRoot, ctKey, 2_000, 'c'));
        runtime.FulcioProofs.Enqueue(
            NewFulcioProof(newRoot, ctKey, 3_000, 'd'));
        runtime.CtCheckpoints.Enqueue(checkpointAfter);
        runtime.Statuses.Enqueue(NewAggregate(model, before));
        runtime.Statuses.Enqueue(
            NewAggregate(model, after) with
            {
                Fulcio = finalStatus
            });

        var workerBefore = Exited(
            "tuf-bootstrap",
            "worker-before",
            0);
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.TufBootstrap.Resource,
            workerBefore);
        runtime.WaitResults["tuf-bootstrap"] = Exited(
            "tuf-bootstrap",
            "worker-after",
            0,
            offsetSeconds: 10);

        var fulcioBefore = Running(
            "fulcio",
            "fulcio-before");
        var fulcioAfter = Running(
            "fulcio",
            "fulcio-after",
            offsetSeconds: 40);
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Fulcio.Resource,
            fulcioBefore,
            fulcioBefore);
        runtime.WaitResults["fulcio"] = fulcioAfter;
        var tesseractBefore = Running(
            "tesseract",
            "tesseract-before");
        var tesseractAfter = Running(
            "tesseract",
            "tesseract-after",
            offsetSeconds: 30);
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tesseract.Resource,
            tesseractBefore,
            tesseractBefore);
        runtime.WaitResults["tesseract"] = tesseractAfter;

        var clientRegistrations = model.Parent.Resource
            .GetRegistrations()
            .Clients
            .OrderBy(
                client => client.Resource.Name,
                StringComparer.Ordinal)
            .ToArray();
        foreach (var client in clientRegistrations)
        {
            var clientBefore = Running(
                client.Resource.Name,
                $"{client.Resource.Name}-before");
            var clientAfter = Running(
                client.Resource.Name,
                $"{client.Resource.Name}-after",
                offsetSeconds: 20);
            runtime.SetSnapshotSequence(
                client.Resource,
                clientBefore);
            runtime.WaitResults[client.Resource.Name] = clientAfter;
            runtime.ClientStatusSequences[client.Resource.Name] =
                new Queue<SigstoreClientTrustStatus>(
                    [
                        NewClientStatus(client, before.Trust),
                        NewClientStatus(client, after.Trust)
                    ]);
            runtime.ArtifactVerifications[client.Resource.Name] =
                new Queue<SigstoreClientArtifactVerification>(
                    [
                        NewArtifactVerification(
                            client,
                            oldArtifact,
                            after.Trust),
                        NewArtifactVerification(
                            client,
                            newArtifact,
                            after.Trust)
                    ]);
        }

        var excluded = clientRegistrations
            .Select(client => client.Resource.Name)
            .Append("fulcio")
            .Append("tesseract")
            .ToHashSet(StringComparer.Ordinal);
        foreach (var protectedResource in model.Parent.Resource
            .GetRegistrations()
            .RequiredResources
            .Where(resource => !excluded.Contains(resource.Name)))
        {
            var snapshot = Running(
                protectedResource.Name,
                $"{protectedResource.Name}-stable");
            runtime.SetSnapshotSequence(
                protectedResource,
                snapshot,
                snapshot,
                snapshot,
                snapshot,
                snapshot,
                snapshot);
        }

        runtime.OnExecuteCommand = (target, command) =>
        {
            if (target.Name != "tuf-bootstrap"
                || command != KnownResourceCommands.StartCommand)
            {
                return;
            }
            using var request = JsonDocument.Parse(
                File.ReadAllBytes(
                    System.IO.Path.Combine(
                        statePath,
                        "rotate-fulcio-ca.request")));
            var operationId = request.RootElement
                .GetProperty("operationId")
                .GetString()!;
            var oldGenerationPath = System.IO.Path.Combine(
                statePath,
                "generations",
                bootstrap.Generation.GenerationId);
            const string newGenerationId = "generation-00000002";
            var newGenerationPath = System.IO.Path.Combine(
                statePath,
                "generations",
                newGenerationId);
            CopyDirectory(
                oldGenerationPath,
                newGenerationPath);
            File.Delete(
                System.IO.Path.Combine(
                    newGenerationPath,
                    "manifest.json"));
            File.WriteAllText(
                System.IO.Path.Combine(
                    newGenerationPath,
                    "manifest.json"),
                JsonSerializer.Serialize(
                    new
                    {
                        generation = 2,
                        generationId = newGenerationId,
                        fulcioRootSha256 = newRoot,
                        fulcioRotationOperationId = operationId
                    }));
            Directory.Delete(
                System.IO.Path.Combine(
                    statePath,
                    "active-generation"));
            Directory.CreateSymbolicLink(
                System.IO.Path.Combine(
                    statePath,
                    "active-generation"),
                System.IO.Path.Combine(
                    "generations",
                    newGenerationId));
            File.WriteAllText(
                System.IO.Path.Combine(
                    statePath,
                    "rotate-fulcio-ca.completed"),
                JsonSerializer.Serialize(
                    new
                    {
                        schemaVersion = 1,
                        operationId,
                        trustDomainId = before.Trust.TrustDomainId,
                        completedAtUtc = DateTimeOffset.UtcNow,
                        priorGeneration = 1,
                        priorGenerationId =
                            bootstrap.Generation.GenerationId,
                        priorFulcioRootSha256 = oldRoot,
                        newGeneration = 2,
                        newGenerationId,
                        newFulcioRootSha256 = newRoot,
                        manifestSha256 =
                            after.Trust.GenerationManifestSha256,
                        publicationId = after.Trust.PublicationId,
                        publicationManifestSha256 =
                            after.Trust.PublicationManifestSha256,
                        trustedRootSha256 =
                            after.Trust.TrustedRootSha256,
                        signingConfigSha256 =
                            after.Trust.SigningConfigSha256,
                        fulcioTrustEntryCount = 2,
                        acceptedRootsSha256 = acceptedHash,
                        acceptedRootFingerprints =
                            new[] { oldRoot, newRoot },
                        activeFulcioRuntimeRootSha256 = oldRoot,
                        stagedFulcioRuntimeRootSha256 = newRoot
                    }));
            File.Delete(
                System.IO.Path.Combine(
                    statePath,
                    "rotate-fulcio-ca.request"));
        };

        var result = await NewExecutor(model, runtime, inspector)
            .ExecuteRotateFulcioCaAsync(CancellationToken.None);
        var output = ReadResult(result);

        Assert.True(
            result.Success,
            output.Message + ": " + string.Join(
                "; ",
                output.Errors.Select(error => error.Message)));
        Assert.NotNull(output.FulcioRotation);
        Assert.Equal(oldRoot, output.FulcioRotation.OldRootSha256);
        Assert.Equal(newRoot, output.FulcioRotation.NewRootSha256);
        Assert.Equal(6, output.FulcioRotation.Clients.Count);
        Assert.Equal(
            6,
            output.FulcioRotation.OldArtifactValidations.Count);
        Assert.Equal(
            6,
            output.FulcioRotation.NewArtifactValidations.Count);
        Assert.Equal(
            1,
            runtime.ExecutedCommands.Count(
                item => item.Resource == "tesseract"));
        Assert.Equal(
            1,
            runtime.ExecutedCommands.Count(
                item => item.Resource == "fulcio"));
        Assert.DoesNotContain(
            runtime.ExecutedCommands,
            item => item.Resource is
                "oidc" or "timestamp" or "rekor-server" or "rekor"
                or "tuf" or "shady-blob-store");

        var orderedEvents = events.ToArray();
        var lastClientRestart = Array.FindLastIndex(
            orderedEvents,
            item => item.StartsWith(
                "execute:",
                StringComparison.Ordinal)
                && item.Contains(
                    "-client:restart",
                    StringComparison.Ordinal));
        var tesseractRestart = Array.IndexOf(
            orderedEvents,
            "execute:tesseract:restart");
        var oldProof = Array.IndexOf(
            orderedEvents,
            $"fulcio-proof:{oldRoot}");
        var runtimeActivation = Array.IndexOf(
            orderedEvents,
            "fulcio-runtime-activate");
        var fulcioRestart = Array.IndexOf(
            orderedEvents,
            "execute:fulcio:restart");
        var newProof = Array.IndexOf(
            orderedEvents,
            $"fulcio-proof:{newRoot}");
        Assert.True(lastClientRestart < tesseractRestart);
        Assert.True(tesseractRestart < oldProof);
        Assert.True(oldProof < runtimeActivation);
        Assert.True(runtimeActivation < fulcioRestart);
        Assert.True(fulcioRestart < newProof);
    }

    [Fact]
    public async Task FulcioRotationContentionIsRejectedByGate()
    {
        using var model = new OperationModelFixture();
        Assert.True(
            model.Parent.Resource.TryBeginOperation(
                SigstoreOperationCommand.RotateFulcioCaCommand,
                "Rotating Fulcio CA",
                out var lease,
                out _));
        try
        {
            var events = new ConcurrentQueue<string>();
            var inspector = new FakeStateInspector(events);
            var result = await NewExecutor(
                    model,
                    NewRuntime(model, events, inspector),
                    inspector)
                .ExecuteRotateFulcioCaAsync(
                    CancellationToken.None);
            var output = ReadResult(result);

            Assert.False(result.Success);
            Assert.Equal("contention", output.Phase);
            Assert.Contains(
                "rotate-fulcio-ca is already active",
                output.Message,
                StringComparison.Ordinal);
        }
        finally
        {
            lease!.Dispose();
        }
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

    [Fact]
    public async Task RotateTufRootAdvancesRootVersionAndPreservesBootstrap()
    {
        using var model = new OperationModelFixture();
        var before = NewTufState();
        var after = NewTufState(before, rotation: true);
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

        var executor = NewExecutor(model, runtime, inspector);
        var result = await executor.ExecuteRotateTufRootAsync(
            CancellationToken.None);
        var output = ReadResult(result);

        Assert.True(result.Success);
        Assert.True(output.Success);
        Assert.Equal(
            SigstoreOperationCommand.RotateTufRootCommand,
            output.Command);
        Assert.Equal(1, output.Before!.Tuf.Metadata.Root.Version);
        Assert.Equal(2, output.After!.Tuf.Metadata.Root.Version);
        Assert.Equal(2, output.After.Tuf.Metadata.Targets.Version);
        Assert.Equal(2, output.After.Tuf.Metadata.Snapshot.Version);
        Assert.Equal(2, output.After.Tuf.Metadata.Timestamp.Version);
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
                "write-signal",
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
            IndexOf(events, "lock:release:dashboard-rotate-tuf-root-preflight")
            < IndexOf(events, "wait:tuf-bootstrap"));
        Assert.Null(model.Parent.Resource.GetPresentation().Operation);

        // Signal file should have been written during the operation.
        // (In production it would be consumed by the worker.)
        var signalPath = System.IO.Path.Combine(
            model.Parent.Resource.StatePath,
            "rotate-root.request");
        Assert.True(File.Exists(signalPath));
    }

    [Fact]
    public async Task RotateTufRootContentionIsRejectedByGate()
    {
        using var model = new OperationModelFixture();
        Assert.True(
            model.Parent.Resource.TryBeginOperation(
                SigstoreOperationCommand.RotateTufRootCommand,
                "Rotating TUF Root",
                out var lease,
                out _));

        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        var runtime = NewRuntime(model, events, inspector);
        var executor = NewExecutor(model, runtime, inspector);
        var result = await executor.ExecuteRotateTufRootAsync(
            CancellationToken.None);
        var output = ReadResult(result);

        Assert.False(result.Success);
        Assert.Equal("contention", output.Phase);
        Assert.Contains(
            "rotate-tuf-root is already active",
            output.Message,
            StringComparison.Ordinal);
        lease!.Dispose();
    }

    [Fact]
    public async Task RotateTufRootWorkerFailurePreservesState()
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
            Running("tuf", "tuf-id"),
            Running("tuf", "tuf-id"));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.TufBootstrap.Resource,
            Exited("tuf-bootstrap", "worker-before", 0));
        runtime.WaitResults["tuf-bootstrap"] =
            Exited("tuf-bootstrap", "worker-failed", 1, offsetSeconds: 10);

        var executor = NewExecutor(model, runtime, inspector);
        var result = await executor.ExecuteRotateTufRootAsync(
            CancellationToken.None);
        var output = ReadResult(result);

        Assert.False(result.Success);
        Assert.Contains("rotation worker failed", output.Message,
            StringComparison.Ordinal);
        Assert.True(output.CommittedStatePreserved);
    }

    [Fact]
    public async Task RestartClientsAcceptsStaleRootVersionAfterRotation()
    {
        using var model = new OperationModelFixture();
        // Disk is at root v2 (post-rotation), clients report root v1.
        var initial = NewTufState();
        var diskState = NewTufState(initial, rotation: true);
        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        // Two reads: preflight + postconditions
        inspector.TufStates.Enqueue(diskState);
        inspector.TufStates.Enqueue(diskState);
        inspector.TrustFingerprints.Enqueue(Hash('2'));
        inspector.TrustFingerprints.Enqueue(Hash('2'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));

        var runtime = NewRuntime(model, events, inspector);
        // Preflight status: stale clients (root v1 vs disk v2)
        runtime.Statuses.Enqueue(
            NewStaleRootAggregate(model, diskState, initial));
        // Postcondition aggregate: converged
        runtime.Statuses.Enqueue(NewAggregate(model, diskState));
        runtime.ServedStates.Enqueue(NewServed(diskState));
        runtime.ServedStates.Enqueue(NewServed(diskState));
        runtime.SetSnapshotSequence(
            model.Parent.Resource.Components.Tuf.Resource,
            Running("tuf", "tuf-id"),
            Running("tuf", "tuf-id"));

        var clients = model.Parent.Resource
            .GetRegistrations()
            .Clients
            .OrderBy(c => c.Resource.Name, StringComparer.Ordinal)
            .ToArray();
        foreach (var client in clients)
        {
            runtime.SetSnapshotSequence(
                client.Resource,
                Running(client.Resource.Name, $"{client.Resource.Name}-before"),
                Running(client.Resource.Name, $"{client.Resource.Name}-after",
                    offsetSeconds: 10));
            runtime.WaitResults[client.Resource.Name] =
                Running(client.Resource.Name, $"{client.Resource.Name}-after",
                    offsetSeconds: 10);
            runtime.ClientStatuses[client.Resource.Name] =
                NewClientStatus(client, diskState.Trust);
        }

        var executor = NewExecutor(model, runtime, inspector);
        var result = await executor.ExecuteRestartClientsAsync(
            CancellationToken.None);
        var output = ReadResult(result);

        Assert.True(result.Success);
        Assert.Equal(
            SigstoreOperationCommand.RestartClientsCommand,
            output.Command);
        Assert.Contains(
            output.Postconditions,
            check => check.Name == "trust-status-stale-root-acceptable"
                && check.Passed);
        Assert.Equal(6, output.Resources.Count);
    }

    [Fact]
    public async Task RestartClientsRejectsUnsafeTrustDomainMismatch()
    {
        using var model = new OperationModelFixture();
        var diskState = NewTufState();
        var events = new ConcurrentQueue<string>();
        var inspector = new FakeStateInspector(events);
        inspector.TufStates.Enqueue(diskState);
        inspector.TrustFingerprints.Enqueue(Hash('1'));
        inspector.MaterialFingerprints.Enqueue(Hash('3'));

        var runtime = NewRuntime(model, events, inspector);
        // Aggregate with an unsafe error (trust domain mismatch)
        var badAggregate = new SigstoreAggregateTrustStatus(
            1,
            "sigstore",
            false,
            "Degraded",
            "dotnet-client: trustDomainId is 'wrong', expected 'right'.",
            DateTimeOffset.UtcNow,
            diskState.Trust,
            NewServed(diskState).Trust,
            [],
            [],
            [new("dotnet-client",
                "trustDomainId is 'wrong', expected 'right'.")]);
        runtime.Statuses.Enqueue(badAggregate);
        runtime.ServedStates.Enqueue(NewServed(diskState));

        var executor = NewExecutor(model, runtime, inspector);
        var result = await executor.ExecuteRestartClientsAsync(
            CancellationToken.None);
        var output = ReadResult(result);

        Assert.False(result.Success);
        Assert.Contains(
            output.Errors,
            error => error.Message.Contains(
                "trustDomainId",
                StringComparison.Ordinal));
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
        bool refresh = false,
        bool rotation = false)
    {
        var future = DateTimeOffset.UtcNow.AddDays(30);
        var root = rotation
            ? new SigstoreTufMetadataRoleStatus(
                prior!.Metadata.Root.Version + 1,
                Hash('r'),
                prior.Metadata.Root.ExpiresAtUtc.AddDays(1))
            : prior?.Metadata.Root
                ?? new SigstoreTufMetadataRoleStatus(
                    1,
                    Hash('a'),
                    future.AddDays(300));
        var targets = rotation
            ? new SigstoreTufMetadataRoleStatus(
                prior!.Metadata.Targets.Version + 1,
                Hash('t'),
                prior.Metadata.Targets.ExpiresAtUtc.AddDays(1))
            : prior?.Metadata.Targets
                ?? new SigstoreTufMetadataRoleStatus(
                    1,
                    Hash('b'),
                    future.AddDays(300));
        var snapshot = refresh || rotation
            ? new SigstoreTufMetadataRoleStatus(
                prior!.Metadata.Snapshot.Version + 1,
                Hash('e'),
                prior.Metadata.Snapshot.ExpiresAtUtc.AddMinutes(1))
            : new SigstoreTufMetadataRoleStatus(
                1,
                Hash('c'),
                future);
        var timestamp = refresh || rotation
            ? new SigstoreTufMetadataRoleStatus(
                prior!.Metadata.Timestamp.Version + 1,
                Hash('f'),
                prior.Metadata.Timestamp.ExpiresAtUtc.AddMinutes(1))
            : new SigstoreTufMetadataRoleStatus(
                1,
                Hash('d'),
                future);
        var manifest = (refresh || rotation) ? Hash('9') : Hash('8');
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
            (refresh || rotation) ? prior!.Trust.PublicationId : null,
            (refresh || rotation)
                ? prior!.Trust.PublicationManifestSha256
                : null);
    }

    private static SigstoreTufStateSnapshot NewOidcRotationTufState(
        SigstoreTufStateSnapshot prior)
    {
        var trust = prior.Trust with
        {
            Generation = prior.Trust.Generation + 1,
            GenerationId = "generation-00000002",
            GenerationManifestSha256 = Hash('5'),
            TufTargetsVersion = prior.Trust.TufTargetsVersion + 1,
            PublicationId = "sha256-" + Hash('9'),
            PublicationManifestSha256 = Hash('9')
        };
        var metadata = prior.Metadata with
        {
            Targets = prior.Metadata.Targets with
            {
                Version = prior.Metadata.Targets.Version + 1,
                Sha256 = Hash('e')
            },
            Snapshot = prior.Metadata.Snapshot with
            {
                Version = prior.Metadata.Snapshot.Version + 1,
                Sha256 = Hash('f')
            },
            Timestamp = prior.Metadata.Timestamp with
            {
                Version = prior.Metadata.Timestamp.Version + 1,
                Sha256 = Hash('a')
            }
        };
        return prior with
        {
            Trust = trust,
            Metadata = metadata,
            PreviousPublicationId = prior.Trust.PublicationId,
            PreviousPublicationManifestSha256 =
                prior.Trust.PublicationManifestSha256
        };
    }

    private static SigstoreTufStateSnapshot NewTsaRotationTufState(
        SigstoreTufStateSnapshot prior)
    {
        var trust = prior.Trust with
        {
            Generation = prior.Trust.Generation + 1,
            GenerationId = "generation-00000002",
            GenerationManifestSha256 = Hash('5'),
            TufTargetsVersion = prior.Trust.TufTargetsVersion + 1,
            TrustedRootSha256 = Hash('8'),
            PublicationId = "sha256-" + Hash('9'),
            PublicationManifestSha256 = Hash('9')
        };
        var metadata = prior.Metadata with
        {
            Targets = new SigstoreTufMetadataRoleStatus(
                prior.Metadata.Targets.Version + 1,
                Hash('e'),
                prior.Metadata.Targets.ExpiresAtUtc.AddDays(1)),
            Snapshot = new SigstoreTufMetadataRoleStatus(
                prior.Metadata.Snapshot.Version + 1,
                Hash('f'),
                prior.Metadata.Snapshot.ExpiresAtUtc.AddMinutes(1)),
            Timestamp = new SigstoreTufMetadataRoleStatus(
                prior.Metadata.Timestamp.Version + 1,
                Hash('a'),
                prior.Metadata.Timestamp.ExpiresAtUtc.AddMinutes(1)),
            TrustedRootSha256 = trust.TrustedRootSha256
        };
        return prior with
        {
            Trust = trust,
            Metadata = metadata,
            PreviousPublicationId = prior.Trust.PublicationId,
            PreviousPublicationManifestSha256 =
                prior.Trust.PublicationManifestSha256
        };
    }

    private static SigstoreTufStateSnapshot NewFulcioRotationTufState(
        SigstoreTufStateSnapshot prior) =>
        NewTsaRotationTufState(prior);

    private static SigstoreFulcioStatus NewFulcioStatus(
        string activeRoot,
        string liveRoot,
        IReadOnlyList<string> roots,
        string acceptedRootsSha256,
        string ctKey,
        SigstoreCtCheckpoint checkpoint,
        bool runtimeMatches)
    {
        var trusted = roots
            .Select(
                (root, index) => new SigstoreFulcioTrustEntry(
                    index,
                    SigstoreFulcio.CanonicalUri,
                    root,
                    "CN=Fulcio Root, O=Sigstore Aspire Demo",
                    DateTime.UtcNow.AddMinutes(-5),
                    DateTime.UtcNow.AddYears(10)))
            .ToArray();
        return new SigstoreFulcioStatus(
            activeRoot,
            liveRoot,
            true,
            runtimeMatches,
            !runtimeMatches,
            runtimeMatches ? null : activeRoot,
            activeRoot == liveRoot,
            trusted,
            roots,
            acceptedRootsSha256,
            true,
            ctKey,
            ctKey,
            "ct-state",
            checkpoint);
    }

    private static SigstoreArtifactEvidence NewArtifact(
        long id,
        string root,
        string ctLogId,
        char marker) =>
        new(
            id,
            Hash(marker),
            Hash((char)(marker + 1)),
            Hash((char)(marker + 2)),
            root,
            ctLogId,
            1_500,
            1,
            1);

    private static SigstoreFulcioIssuanceProof NewFulcioProof(
        string root,
        string ctLogId,
        ulong timestamp,
        char marker) =>
        new(
            Hash(marker),
            root,
            "CN=leaf",
            "CN=Fulcio Root",
            SigstoreDefaults.ExpectedIdentity,
            DateTimeOffset.UtcNow.AddMinutes(-1),
            DateTimeOffset.UtcNow.AddMinutes(9),
            ctLogId,
            timestamp,
            Hash((char)(marker + 1)),
            true);

    private static SigstoreClientArtifactVerification
        NewArtifactVerification(
            SigstoreClientRegistration client,
            SigstoreArtifactEvidence artifact,
            SigstoreDiskTrustStatus trust) =>
        new(
            1,
            client.Resource.Name,
            client.Language,
            true,
            artifact.ArtifactId,
            artifact.ArtifactSha256,
            artifact.BundleSha256,
            trust.Generation,
            trust.GenerationId,
            trust.TrustedRootSha256);

    private static SigstoreTimestampAuthorityProbeEvidence
        NewTimestampProof(
            string rootSha256,
            string leafSha256,
            char marker) =>
        new(
            rootSha256,
            leafSha256,
            "CN=Timestamp Authority",
            "CN=Timestamp Authority Root",
            Hash(marker),
            Hash(marker),
            Hash(marker),
            DateTimeOffset.UtcNow);

    private static TsaCertificatePair ReadTsaCertificates(
        string generationPath)
    {
        using var leaf = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                System.IO.Path.Combine(
                    generationPath,
                    "public",
                    "tsa",
                    "leaf.pem")));
        using var root = X509Certificate2.CreateFromPem(
            File.ReadAllText(
                System.IO.Path.Combine(
                generationPath,
                "public",
                "tsa",
                "root.pem")));
        return new TsaCertificatePair(
            leaf.RawData,
            root.RawData);
    }

    private static void WriteTrustedRoot(
        string statePath,
        IReadOnlyList<TsaCertificatePair> authorities)
    {
        var targetPath = System.IO.Path.Combine(
            statePath,
            "tuf",
            "active",
            "targets");
        Directory.CreateDirectory(targetPath);
        File.WriteAllText(
            System.IO.Path.Combine(
                targetPath,
                "trusted_root.json"),
            JsonSerializer.Serialize(
                new
                {
                    mediaType =
                        "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
                    timestampAuthorities = authorities.Select(
                        certificates => new
                        {
                            uri = SigstoreDefaults.TimestampAuthorityUrl,
                            certChain = new
                            {
                                certificates = new[]
                                {
                                    new
                                    {
                                        rawBytes = certificates.Leaf
                                    },
                                    new
                                    {
                                        rawBytes = certificates.Root
                                    }
                                }
                            }
                        })
                }));
    }

    private static void CopyDirectory(
        string source,
        string destination)
    {
        Directory.CreateDirectory(destination);
        foreach (var directory in Directory.EnumerateDirectories(
            source,
            "*",
            SearchOption.AllDirectories))
        {
            Directory.CreateDirectory(
                System.IO.Path.Combine(
                    destination,
                    System.IO.Path.GetRelativePath(source, directory)));
        }
        foreach (var file in Directory.EnumerateFiles(
            source,
            "*",
            SearchOption.AllDirectories))
        {
            var target = System.IO.Path.Combine(
                destination,
                System.IO.Path.GetRelativePath(source, file));
            Directory.CreateDirectory(
                System.IO.Path.GetDirectoryName(target)!);
            File.Copy(file, target, overwrite: true);
        }
    }

    private static string CreateOidcJwt(string kid)
    {
        static string Encode(object value) =>
            Convert.ToBase64String(JsonSerializer.SerializeToUtf8Bytes(value))
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        return $"{Encode(new { alg = "RS256", kid })}." +
            $"{Encode(new
            {
                iss = SigstoreDefaults.ExpectedIssuer,
                sub = SigstoreDefaults.ExpectedIdentity,
                aud = "sigstore",
                iat = now,
                nbf = now - 1,
                exp = now + 600
            })}.c2ln";
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

    /// <summary>
    /// Creates an aggregate where disk is at current state (root v2)
    /// but clients report stale root from the prior state (root v1).
    /// </summary>
    private static SigstoreAggregateTrustStatus NewStaleRootAggregate(
        OperationModelFixture model,
        SigstoreTufStateSnapshot diskState,
        SigstoreTufStateSnapshot clientState)
    {
        var clients = model.Parent.Resource
            .GetRegistrations()
            .Clients
            .Select(client => NewClientStatus(client, clientState.Trust))
            .ToArray();
        var errors = clients
            .Select(client => new SigstoreStatusError(
                client.Resource,
                $"tufRootVersion is '{clientState.Trust.TufRootVersion}', " +
                    $"expected '{diskState.Trust.TufRootVersion}'."))
            .ToList();
        if (clientState.Trust.TufTargetsVersion
            != diskState.Trust.TufTargetsVersion)
        {
            errors.AddRange(clients.Select(client => new SigstoreStatusError(
                client.Resource,
                $"tufTargetsVersion is '{clientState.Trust.TufTargetsVersion}', " +
                    $"expected '{diskState.Trust.TufTargetsVersion}'.")));
        }
        return new SigstoreAggregateTrustStatus(
            1,
            "sigstore",
            false,
            "Degraded",
            $"{errors[0].Source}: {errors[0].Message}",
            DateTimeOffset.UtcNow,
            diskState.Trust,
            NewServed(diskState).Trust,
            clients,
            [],
            errors);
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

    private static string HashBytes(ReadOnlySpan<byte> value) =>
        Convert.ToHexString(SHA256.HashData(value))
            .ToLowerInvariant();

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
            Parent.WithArtifactStore(
                builder
                    .AddContainer(
                        "shady-blob-store",
                        "alpine")
                    .WithHttpEndpoint(
                        targetPort: 8080,
                        name: "http"));
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
                    15,
                    15));
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

        public FulcioCaMaterialInfo FulcioCandidate { get; set; } =
            new(
                Hash('f'),
                Hash('e'),
                "CN=Fulcio Root, O=Sigstore Aspire Demo",
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddYears(10));

        public FulcioRuntimeProjectionInfo FulcioProjection { get; set; } =
            new(
                Hash('f'),
                Hash('e'),
                "CN=Fulcio Root, O=Sigstore Aspire Demo",
                DateTimeOffset.UtcNow.AddMinutes(-5),
                DateTimeOffset.UtcNow.AddYears(10),
                Hash('c'),
                null,
                false,
                Hash('d'),
                [Hash('a'), Hash('f')]);

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

        public FulcioCaMaterialInfo EnsureFulcioCaRotationCandidate(
            string candidatePath)
        {
            events.Enqueue("fulcio-candidate");
            Directory.CreateDirectory(candidatePath);
            return FulcioCandidate;
        }

        public FulcioRuntimeProjectionInfo ActivateFulcioRuntimeProjection(
            string statePath,
            string operationId,
            string priorFulcioRootSha256,
            string newFulcioRootSha256)
        {
            events.Enqueue("fulcio-runtime-activate");
            return FulcioProjection;
        }
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

        public Queue<(string? jwt, string? kid)> OidcTokens { get; } = [];

        public Queue<FulcioIssuanceEvidence?> FulcioCertificates { get; } = [];

        public Queue<SigstoreTimestampAuthorityProbe> TimestampProbes
        {
            get;
        } = [];

        public Queue<SigstoreTimestampAuthorityProbeEvidence>
            StoredTimestampProofs { get; } = [];

        public Queue<SigstoreFulcioStatus> FulcioStatuses { get; } = [];

        public Queue<SigstoreFulcioIssuanceProof> FulcioProofs { get; } = [];

        public Queue<SigstoreCtCheckpoint> CtCheckpoints { get; } = [];

        public Queue<SigstoreArtifactEvidence> Artifacts { get; } = [];

        public Dictionary<
            string,
            Queue<SigstoreClientArtifactVerification>>
            ArtifactVerifications { get; } =
                new(StringComparer.Ordinal);

        public Dictionary<string, SigstoreResourceInstanceSnapshot>
            WaitResults { get; } = new(StringComparer.Ordinal);

        public Dictionary<string, Exception> WaitFailures { get; } =
            new(StringComparer.Ordinal);

        public Dictionary<string, SigstoreClientTrustStatus>
            ClientStatuses { get; } = new(StringComparer.Ordinal);

        public Dictionary<string, Queue<SigstoreClientTrustStatus>>
            ClientStatusSequences { get; } = new(StringComparer.Ordinal);

        public List<(string Resource, string Command)> ExecutedCommands
        {
            get;
        } = [];

        public List<string> WaitedResources { get; } = [];

        public ExecuteCommandResult CommandResult { get; set; } =
            CommandResults.Success();

        public Action<IResource, string>? OnExecuteCommand { get; set; }

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
            OnExecuteCommand?.Invoke(target, command);
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
            if (ClientStatusSequences.TryGetValue(
                    client.Resource.Name,
                    out var sequence))
            {
                return Task.FromResult(sequence.Dequeue());
            }
            return Task.FromResult(
                ClientStatuses[client.Resource.Name]);
        }

        public Task<(string? jwt, string? kid)> CaptureOidcTokenAsync(
            CancellationToken cancellationToken)
        {
            events.Enqueue("oidc-token");
            return Task.FromResult(OidcTokens.Dequeue());
        }

        public Task<FulcioIssuanceEvidence?> ProveFulcioCertIssuanceAsync(
            string oidcToken,
            string subject,
            CancellationToken cancellationToken)
        {
            events.Enqueue($"fulcio-certificate:{subject}");
            return Task.FromResult(FulcioCertificates.Dequeue());
        }

        public Task<SigstoreTimestampAuthorityProbe>
            ProbeTimestampAuthorityAsync(
                IReadOnlyList<SigstoreTimestampAuthorityTrustEntry>
                    trustedAuthorities,
                CancellationToken cancellationToken)
        {
            events.Enqueue("timestamp-probe");
            return Task.FromResult(TimestampProbes.Dequeue());
        }

        public Task<SigstoreTimestampAuthorityProbeEvidence>
            ValidateStoredTimestampAuthorityResponseAsync(
                ReadOnlyMemory<byte> request,
                ReadOnlyMemory<byte> response,
                IReadOnlyList<SigstoreTimestampAuthorityTrustEntry>
                    trustedAuthorities,
                CancellationToken cancellationToken)
        {
            events.Enqueue("timestamp-proof");
            return Task.FromResult(StoredTimestampProofs.Dequeue());
        }

        public Task<SigstoreFulcioStatus> ReadFulcioStatusAsync(
            CancellationToken cancellationToken)
        {
            events.Enqueue("fulcio-status");
            return Task.FromResult(FulcioStatuses.Dequeue());
        }

        public Task<SigstoreFulcioIssuanceProof>
            ProveFulcioIssuanceAsync(
                string oidcToken,
                string subject,
                string expectedRootSha256,
                CancellationToken cancellationToken)
        {
            events.Enqueue($"fulcio-proof:{expectedRootSha256}");
            return Task.FromResult(FulcioProofs.Dequeue());
        }

        public Task<SigstoreCtCheckpoint> ReadCtCheckpointAsync(
            CancellationToken cancellationToken)
        {
            events.Enqueue("ct-checkpoint");
            return Task.FromResult(CtCheckpoints.Dequeue());
        }

        public Task<long> ReadArtifactHeadAsync(
            CancellationToken cancellationToken)
        {
            events.Enqueue("artifact-head");
            return Task.FromResult(
                Artifacts.Count == 0
                    ? 0
                    : Artifacts.Peek().ArtifactId);
        }

        public Task<SigstoreArtifactEvidence> FindArtifactAsync(
            long minimumExclusiveId,
            string expectedRootSha256,
            CancellationToken cancellationToken)
        {
            events.Enqueue($"find-artifact:{expectedRootSha256}");
            return Task.FromResult(Artifacts.Dequeue());
        }

        public Task<SigstoreClientArtifactVerification>
            VerifyArtifactAsync(
                SigstoreClientRegistration client,
                SigstoreArtifactEvidence artifact,
                CancellationToken cancellationToken)
        {
            events.Enqueue(
                $"verify-artifact:{client.Resource.Name}:{artifact.ArtifactId}");
            return Task.FromResult(
                ArtifactVerifications[client.Resource.Name].Dequeue());
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

    private sealed record TsaCertificatePair(
        byte[] Leaf,
        byte[] Root);

    private sealed class EmptyServiceProvider : IServiceProvider
    {
        public object? GetService(Type serviceType) => null;
    }
}
