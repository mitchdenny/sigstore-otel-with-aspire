using Aspire.Hosting;
using Aspire.Hosting.ApplicationModel;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Xunit;

namespace Sigstore.Aspire.Hosting.Tests;

/// <summary>
/// Safe-order and replay coverage for the Rekor shard rotation's
/// post-commit activation step: <c>resource.ActivateConditionalResource</c>
/// on the secondary shard followed by <c>resource.MarkResourceHistorical</c>
/// on the primary. These tests exercise the real <see cref="SigstoreResource"/>
/// registration state machine (through the production <c>AddSigstore</c>
/// wiring) rather than the full rotation orchestration, since that is the
/// primitive the rotation operation depends on for correctness: it must
/// never mark the primary historical before the additive TUF commit is
/// proven, and replaying the transition after a resumed operation must be
/// safe.
/// </summary>
public sealed class SigstoreRekorShardActivationTests
{
    [Fact]
    public void BeforeActivationPrimaryIsRequiredAndSecondaryIsInactive()
    {
        using var model = new ActivationModelFixture();
        var resource = model.Parent.Resource;

        var registrations = resource.GetRegistrations();

        Assert.Contains(
            registrations.RequiredResources,
            item => ReferenceEquals(
                item,
                resource.Components.RekorServer.Resource));
        Assert.Contains(
            registrations.ConditionalResources,
            item => ReferenceEquals(
                item,
                resource.Components.RekorServerSecondary.Resource));
        Assert.False(
            resource.IsConditionalResourceActive(
                resource.Components.RekorServerSecondary.Resource.Name));
        Assert.Contains(
            resource.Components.RekorServer.Resource.Name,
            EffectiveRequiredNames(resource));
        Assert.DoesNotContain(
            resource.Components.RekorServerSecondary.Resource.Name,
            EffectiveRequiredNames(resource));
    }

    [Fact]
    public void
        ActivatingSecondaryThenMarkingPrimaryHistoricalMatchesTheSafeOrder()
    {
        using var model = new ActivationModelFixture();
        var resource = model.Parent.Resource;

        // This is the exact order the rotation operation uses, and only
        // after the additive TUF commit has already been proven.
        resource.ActivateConditionalResource(
            resource.Components.RekorServerSecondary.Resource);
        resource.MarkResourceHistorical(
            resource.Components.RekorServer.Resource);

        var registrations = resource.GetRegistrations();
        Assert.DoesNotContain(
            registrations.RequiredResources,
            item => ReferenceEquals(
                item,
                resource.Components.RekorServer.Resource));
        Assert.Contains(
            registrations.ConditionalResources,
            item => ReferenceEquals(
                item,
                resource.Components.RekorServer.Resource));
        Assert.False(
            resource.IsConditionalResourceActive(
                resource.Components.RekorServer.Resource.Name));
        Assert.True(
            resource.IsConditionalResourceActive(
                resource.Components.RekorServerSecondary.Resource.Name));

        // The gateway is a distinct, always-required resource: static
        // verification of the primary's tiles/checkpoint must remain
        // required even though the primary process itself is historical.
        Assert.Contains(
            registrations.RequiredResources,
            item => ReferenceEquals(
                item,
                resource.Components.Rekor.Resource));

        var effective = EffectiveRequiredNames(resource);
        Assert.DoesNotContain(
            resource.Components.RekorServer.Resource.Name,
            effective);
        Assert.Contains(
            resource.Components.RekorServerSecondary.Resource.Name,
            effective);
        Assert.Contains(resource.Components.Rekor.Resource.Name, effective);
    }

    [Fact]
    public void
        AggregateHealthMonitorIgnoresTheHistoricalPrimaryAfterActivation()
    {
        using var model = new ActivationModelFixture();
        var resource = model.Parent.Resource;
        resource.ActivateConditionalResource(
            resource.Components.RekorServerSecondary.Resource);
        resource.MarkResourceHistorical(
            resource.Components.RekorServer.Resource);
        var effective = EffectiveRequiredNames(resource);

        // A stopped/exited primary must not degrade the parent: it is no
        // longer part of the set the health monitor evaluates at all.
        var observed = new Dictionary<string, SigstoreObservedResource>(
            StringComparer.Ordinal)
        {
            [resource.Components.RekorServer.Resource.Name] =
                new(KnownResourceStates.Exited, HealthStatus.Unhealthy),
            [resource.Components.RekorServerSecondary.Resource.Name] =
                new(KnownResourceStates.Running, HealthStatus.Healthy),
            [resource.Components.Rekor.Resource.Name] =
                new(KnownResourceStates.Running, HealthStatus.Healthy)
        };
        foreach (var required in resource.GetRegistrations()
            .RequiredResources)
        {
            observed.TryAdd(
                required.Name,
                new SigstoreObservedResource(
                    KnownResourceStates.Running,
                    HealthStatus.Healthy));
        }

        var health = SigstoreParentHealthMonitor.Evaluate(
            effective,
            observed,
            wasHealthy: true);

        Assert.Equal("Healthy", health.State);
        Assert.DoesNotContain(
            health.Resources,
            status => status.Resource
                == resource.Components.RekorServer.Resource.Name);
    }

    [Fact]
    public void ReplayingActivationAfterResumeIsIdempotent()
    {
        using var model = new ActivationModelFixture();
        var resource = model.Parent.Resource;
        resource.ActivateConditionalResource(
            resource.Components.RekorServerSecondary.Resource);
        resource.MarkResourceHistorical(
            resource.Components.RekorServer.Resource);
        var before = model.Snapshot();

        // Simulate a resumed operation replaying the same transition.
        resource.ActivateConditionalResource(
            resource.Components.RekorServerSecondary.Resource);
        resource.MarkResourceHistorical(
            resource.Components.RekorServer.Resource);
        var after = model.Snapshot();

        Assert.Equal(before.Required, after.Required);
        Assert.Equal(before.ActiveConditional, after.ActiveConditional);
    }

    [Fact]
    public void MarkResourceHistoricalRejectsAnUnregisteredResource()
    {
        using var model = new ActivationModelFixture();
        var resource = model.Parent.Resource;
        var stray = model.Builder
            .AddContainer("stray-resource", "alpine")
            .Resource;

        Assert.Throws<InvalidOperationException>(
            () => resource.MarkResourceHistorical(stray));
    }

    private static HashSet<string> EffectiveRequiredNames(
        SigstoreResource resource)
    {
        var registrations = resource.GetRegistrations();
        return registrations.RequiredResources
            .Select(item => item.Name)
            .Concat(
                registrations.ConditionalResources
                    .Where(
                        item => resource.IsConditionalResourceActive(
                            item.Name))
                    .Select(item => item.Name))
            .ToHashSet(StringComparer.Ordinal);
    }

    private sealed class ActivationModelFixture : IDisposable
    {
        public ActivationModelFixture()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-rekor-activation-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
            Directory.CreateDirectory(
                System.IO.Path.Combine(Path, ".sigstore"));
            var sourcePath = System.IO.Path.Combine(
                FindRepositoryRoot(),
                "src");
            Builder = DistributedApplication.CreateBuilder(
                new DistributedApplicationOptions
                {
                    AssemblyName =
                        typeof(SigstoreRekorShardActivationTests)
                            .Assembly.FullName,
                    ProjectDirectory = Path,
                    DisableDashboard = true
                });
            Parent = Builder.AddSigstore(
                "sigstore",
                new SigstoreOptions
                {
                    SourcePath = sourcePath
                });
        }

        public string Path { get; }

        public IDistributedApplicationBuilder Builder { get; }

        public IResourceBuilder<SigstoreResource> Parent { get; }

        public (
            IReadOnlyList<string> Required,
            IReadOnlyList<string> ActiveConditional) Snapshot()
        {
            var registrations = Parent.Resource.GetRegistrations();
            return (
                registrations.RequiredResources
                    .Select(item => item.Name)
                    .Order(StringComparer.Ordinal)
                    .ToArray(),
                registrations.ConditionalResources
                    .Where(
                        item => Parent.Resource.IsConditionalResourceActive(
                            item.Name))
                    .Select(item => item.Name)
                    .Order(StringComparer.Ordinal)
                    .ToArray());
        }

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
}
