using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Sigstore.Bootstrap;
using Xunit;

namespace Aspire.Hosting.ApplicationModel;

public sealed class SigstoreFulcioTests
{
    [Fact]
    public void AcceptedRootBundleIsOrderedNormalizedAndDeduplicated()
    {
        using var firstState = new TemporaryDirectory();
        using var secondState = new TemporaryDirectory();
        _ = SigstoreStateBootstrapper.EnsureInitialized(
            firstState.Path);
        _ = SigstoreStateBootstrapper.EnsureInitialized(
            secondState.Path);
        using var first = ReadRoot(firstState.Path);
        using var second = ReadRoot(secondState.Path);

        var bundle = SigstoreFulcio.CreateAcceptedRootsBundle(
            [first, second, first]);
        var certificates = SigstoreFulcio.ReadCertificateBundle(
            bundle);
        try
        {
            Assert.Equal(2, certificates.Count);
            Assert.Equal(
                SigstoreFulcio.Fingerprint(first.RawData),
                SigstoreFulcio.Fingerprint(
                    certificates[0].RawData));
            Assert.Equal(
                SigstoreFulcio.Fingerprint(second.RawData),
                SigstoreFulcio.Fingerprint(
                    certificates[1].RawData));
            Assert.EndsWith(
                "\n",
                System.Text.Encoding.ASCII.GetString(bundle),
                StringComparison.Ordinal);
        }
        finally
        {
            foreach (var certificate in certificates)
            {
                certificate.Dispose();
            }
        }
    }

    [Fact]
    public void AcceptedRootBundleRejectsDuplicatePemEntries()
    {
        using var state = new TemporaryDirectory();
        _ = SigstoreStateBootstrapper.EnsureInitialized(state.Path);
        using var root = ReadRoot(state.Path);
        var pem = root.ExportCertificatePem();
        var duplicate = System.Text.Encoding.ASCII.GetBytes(
            $"{pem.TrimEnd()}\n{pem.TrimEnd()}\n");

        Assert.Throws<InvalidDataException>(
            () => SigstoreFulcio.ReadCertificateBundle(
                duplicate));
    }

    [Fact]
    public void CtCheckpointBindsOriginKeyTimestampSizeAndRoot()
    {
        using var state = new TemporaryDirectory();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        const ulong treeSize = 42;
        const ulong timestamp = 1_787_909_715_428;
        var rootHash = SHA256.HashData("root"u8);
        var signed = new byte[50];
        signed[0] = 0;
        signed[1] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(
            signed.AsSpan(2, 8),
            timestamp);
        BinaryPrimitives.WriteUInt64BigEndian(
            signed.AsSpan(10, 8),
            treeSize);
        rootHash.CopyTo(signed, 18);
        var signature = key.SignData(
            signed,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.Rfc3279DerSequence);
        var digitallySigned = new byte[4 + signature.Length];
        digitallySigned[0] = 4;
        digitallySigned[1] = 3;
        BinaryPrimitives.WriteUInt16BigEndian(
            digitallySigned.AsSpan(2, 2),
            checked((ushort)signature.Length));
        signature.CopyTo(digitallySigned, 4);

        var logId = SHA256.HashData(
            key.ExportSubjectPublicKeyInfo());
        var origin = Encoding.UTF8.GetBytes(
            SigstoreFulcio.CtOrigin);
        var noteKeyInput = new byte[
            origin.Length + 2 + logId.Length];
        origin.CopyTo(noteKeyInput, 0);
        noteKeyInput[origin.Length] = (byte)'\n';
        noteKeyInput[origin.Length + 1] = 0x05;
        logId.CopyTo(noteKeyInput, origin.Length + 2);
        var noteKeyHash = SHA256.HashData(noteKeyInput);
        var noteSignature = new byte[
            4 + 8 + digitallySigned.Length];
        noteKeyHash.AsSpan(0, 4).CopyTo(noteSignature);
        BinaryPrimitives.WriteUInt64BigEndian(
            noteSignature.AsSpan(4, 8),
            timestamp);
        digitallySigned.CopyTo(noteSignature, 12);

        var checkpointPath = System.IO.Path.Combine(
            state.Path,
            "data",
            "ctlog",
            "checkpoint");
        Directory.CreateDirectory(
            System.IO.Path.GetDirectoryName(checkpointPath)!);
        File.WriteAllText(
            checkpointPath,
            $"{SigstoreFulcio.CtOrigin}\n{treeSize}\n" +
            $"{Convert.ToBase64String(rootHash)}\n\n" +
            $"\u2014 {SigstoreFulcio.CtOrigin} " +
            $"{Convert.ToBase64String(noteSignature)}\n",
            new UTF8Encoding(false));

        var shard = new SigstoreFulcio.SelectedCtShard(
            System.IO.Path.Combine(state.Path, "active-generation"),
            SigstoreFulcio.CtOrigin,
            System.IO.Path.Combine(state.Path, "data", "ctlog"),
            "primary",
            System.IO.Path.Combine(state.Path, "runtime", "tesseract"));
        var checkpoint = SigstoreFulcio.ReadCheckpoint(shard, key);

        Assert.Equal(SigstoreFulcio.CtOrigin, checkpoint.Origin);
        Assert.Equal(treeSize, checkpoint.TreeSize);
        Assert.Equal(timestamp, checkpoint.Timestamp);
        Assert.Equal(
            Convert.ToHexString(rootHash).ToLowerInvariant(),
            checkpoint.RootHash);
        Assert.Equal(
            Convert.ToHexString(logId).ToLowerInvariant(),
            checkpoint.LogId);

        File.WriteAllText(
            checkpointPath,
            File.ReadAllText(checkpointPath).Replace(
                $"\n{treeSize}\n",
                $"\n{treeSize + 1}\n",
                StringComparison.Ordinal));
        Assert.Throws<InvalidDataException>(
            () => SigstoreFulcio.ReadCheckpoint(shard, key));
    }

    [Fact]
    public void AppHostSealsContainerWrittenGenerationManifest()
    {
        using var state = new TemporaryDirectory();
        var initialized = SigstoreStateBootstrapper.EnsureInitialized(
            state.Path);
        var manifestPath = System.IO.Path.Combine(
            state.Path,
            "generations",
            initialized.Generation.GenerationId,
            "manifest.json");
        if (OperatingSystem.IsWindows())
        {
            File.SetAttributes(
                manifestPath,
                File.GetAttributes(manifestPath)
                    & ~FileAttributes.ReadOnly);
        }
        else
        {
            File.SetUnixFileMode(
                manifestPath,
                UnixFileMode.UserRead
                | UnixFileMode.UserWrite
                | UnixFileMode.GroupRead
                | UnixFileMode.OtherRead);
        }

        new SigstoreFileStateInspector()
            .EnsureActiveGenerationManifestReadOnly(state.Path);

        if (OperatingSystem.IsWindows())
        {
            Assert.True(
                File.GetAttributes(manifestPath)
                    .HasFlag(FileAttributes.ReadOnly));
        }
        else
        {
            Assert.Equal(
                UnixFileMode.None,
                File.GetUnixFileMode(manifestPath)
                & (UnixFileMode.UserWrite
                    | UnixFileMode.GroupWrite
                    | UnixFileMode.OtherWrite));
        }
    }

    private static X509Certificate2 ReadRoot(string statePath) =>
        X509Certificate2.CreateFromPem(
            File.ReadAllText(
                System.IO.Path.Combine(
                    statePath,
                    "active-generation",
                    "public",
                    "fulcio",
                    "root.pem")));

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
            if (Directory.Exists(Path))
            {
                Directory.Delete(Path, recursive: true);
            }
        }
    }
}
