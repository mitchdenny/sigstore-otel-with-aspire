using System.Security.Cryptography;
using System.Text.Json;
using Sigstore.Bootstrap;
using Xunit;

namespace Sigstore.Bootstrap.Tests;

public sealed class OidcKeyRotationTests
{
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    private sealed class TemporaryDirectory : IDisposable
    {
        public TemporaryDirectory()
        {
            Path = System.IO.Path.Combine(
                System.IO.Path.GetTempPath(),
                $"sigstore-oidc-rotation-tests-{Guid.NewGuid():N}");
            Directory.CreateDirectory(Path);
        }

        public string Path { get; }

        public void Dispose()
        {
            try { Directory.Delete(Path, recursive: true); }
            catch { /* best effort */ }
        }
    }

    [Fact]
    public void GenerateCandidateProducesUniqueValidKey()
    {
        var candidate1 = OidcKeyRotation.GenerateCandidate();
        var candidate2 = OidcKeyRotation.GenerateCandidate();

        Assert.NotNull(candidate1.KeyId);
        Assert.NotNull(candidate1.PrivateKeyPem);
        Assert.NotNull(candidate1.Jwk);
        Assert.Equal("RSA", candidate1.Jwk.Kty);
        Assert.Equal("sig", candidate1.Jwk.Use);
        Assert.Equal("RS256", candidate1.Jwk.Alg);
        Assert.Equal(candidate1.KeyId, candidate1.Jwk.Kid);
        Assert.NotEqual(candidate1.KeyId, candidate2.KeyId);
    }

    [Fact]
    public void GenerateCandidateKeyIdMatchesDerivedSha256()
    {
        var candidate = OidcKeyRotation.GenerateCandidate();

        using var rsa = RSA.Create();
        rsa.ImportFromPem(candidate.PrivateKeyPem);
        var computedKid = OidcKeyRotation.ComputeKeyId(rsa);

        Assert.Equal(candidate.KeyId, computedKid);
    }

    [Fact]
    public void WriteOverlappingJwksAddsNewKey()
    {
        using var dir = new TemporaryDirectory();
        SetupInitialOidcState(dir.Path);
        var genPath = ResolveActiveGeneration(dir.Path);

        var initialKids = OidcKeyRotation.ReadJwksKeyIds(genPath);
        Assert.Single(initialKids);

        var candidate = OidcKeyRotation.GenerateCandidate();
        OidcKeyRotation.WriteOverlappingJwks(genPath, candidate.Jwk);

        var afterKids = OidcKeyRotation.ReadJwksKeyIds(genPath);
        Assert.Equal(2, afterKids.Length);
        Assert.Contains(initialKids[0], afterKids);
        Assert.Contains(candidate.KeyId, afterKids);
    }

    [Fact]
    public void WriteOverlappingJwksPreservesOriginalKeyBytes()
    {
        using var dir = new TemporaryDirectory();
        SetupInitialOidcState(dir.Path);
        var genPath = ResolveActiveGeneration(dir.Path);

        var jwksPath = Path.Combine(genPath, "public", "oidc", "jwks.json");
        var originalJwks = File.ReadAllText(jwksPath);
        using var originalDoc = JsonDocument.Parse(originalJwks);
        var originalKey = originalDoc.RootElement.GetProperty("keys")[0];
        var originalN = originalKey.GetProperty("n").GetString();
        var originalE = originalKey.GetProperty("e").GetString();

        var candidate = OidcKeyRotation.GenerateCandidate();
        OidcKeyRotation.WriteOverlappingJwks(genPath, candidate.Jwk);

        var newJwks = File.ReadAllText(jwksPath);
        using var newDoc = JsonDocument.Parse(newJwks);
        var keys = newDoc.RootElement.GetProperty("keys").EnumerateArray().ToArray();

        // Find the original key in the new JWKS.
        var found = keys.FirstOrDefault(k =>
            k.GetProperty("n").GetString() == originalN);
        Assert.Equal(originalN, found.GetProperty("n").GetString());
        Assert.Equal(originalE, found.GetProperty("e").GetString());
    }

    [Fact]
    public void RetainCurrentKeyCreatesRetainedFile()
    {
        using var dir = new TemporaryDirectory();
        SetupInitialOidcState(dir.Path);
        var genPath = ResolveActiveGeneration(dir.Path);

        var keyId = OidcKeyRotation.ReadActiveKeyId(genPath);
        OidcKeyRotation.RetainCurrentKey(genPath, keyId);

        var retainedPath = Path.Combine(
            genPath, "private", "oidc", "retained", $"key-{keyId}.pem");
        Assert.True(File.Exists(retainedPath));

        // Verify the retained key matches.
        using var original = RSA.Create();
        original.ImportFromPem(File.ReadAllText(
            Path.Combine(genPath, "private", "oidc", "signer.key")));
        using var retained = RSA.Create();
        retained.ImportFromPem(File.ReadAllText(retainedPath));
        Assert.Equal(
            OidcKeyRotation.ComputeKeyId(original),
            OidcKeyRotation.ComputeKeyId(retained));
    }

    [Fact]
    public void ActivateNewKeyReplacesSignerFile()
    {
        using var dir = new TemporaryDirectory();
        SetupInitialOidcState(dir.Path);
        var genPath = ResolveActiveGeneration(dir.Path);

        var oldKeyId = OidcKeyRotation.ReadActiveKeyId(genPath);
        var candidate = OidcKeyRotation.GenerateCandidate();

        OidcKeyRotation.ActivateNewKey(genPath, candidate.PrivateKeyPem);

        var newKeyId = OidcKeyRotation.ReadActiveKeyId(genPath);
        Assert.Equal(candidate.KeyId, newKeyId);
        Assert.NotEqual(oldKeyId, newKeyId);
    }

    [Fact]
    public void ReadAndWriteStateRoundTrips()
    {
        using var dir = new TemporaryDirectory();
        Directory.CreateDirectory(dir.Path);

        Assert.Null(OidcKeyRotation.ReadState(dir.Path));

        var state = new OidcRotationState(
            SchemaVersion: 1,
            ActiveKeyId: "test-kid-123",
            RetainedKeyIds: ["old-kid-456"],
            JwksSha256: "abc123",
            RotatedAtUtc: DateTimeOffset.UtcNow,
            OperationId: "op-789");

        OidcKeyRotation.WriteState(dir.Path, state);

        var read = OidcKeyRotation.ReadState(dir.Path);
        Assert.NotNull(read);
        Assert.Equal(state.ActiveKeyId, read.ActiveKeyId);
        Assert.Equal(state.RetainedKeyIds, read.RetainedKeyIds);
        Assert.Equal(state.JwksSha256, read.JwksSha256);
        Assert.Equal(state.OperationId, read.OperationId);
    }

    [Fact]
    public void OidcIssuerAcceptsOverlappingJwks()
    {
        // Verifies the modified OidcTokenIssuer works with multi-key JWKS.
        using var dir = new TemporaryDirectory();
        SetupInitialOidcState(dir.Path);
        var genPath = ResolveActiveGeneration(dir.Path);

        var candidate = OidcKeyRotation.GenerateCandidate();
        OidcKeyRotation.WriteOverlappingJwks(genPath, candidate.Jwk);

        // Load issuer with old key + overlapping JWKS - should succeed.
        var issuer = Sigstore.Oidc.OidcTokenIssuer.Load(
            "https://oidc.test.local",
            Path.Combine(genPath, "private", "oidc", "signer.key"),
            Path.Combine(genPath, "public", "oidc", "jwks.json"),
            "test@test.local");

        var token = issuer.CreateToken("test@test.local");
        Assert.NotNull(token);
        Assert.Contains(".", token);
        issuer.Dispose();
    }

    [Fact]
    public void OidcIssuerAcceptsActivatedNewKey()
    {
        using var dir = new TemporaryDirectory();
        SetupInitialOidcState(dir.Path);
        var genPath = ResolveActiveGeneration(dir.Path);

        var oldKeyId = OidcKeyRotation.ReadActiveKeyId(genPath);
        var candidate = OidcKeyRotation.GenerateCandidate();
        OidcKeyRotation.WriteOverlappingJwks(genPath, candidate.Jwk);
        OidcKeyRotation.ActivateNewKey(genPath, candidate.PrivateKeyPem);

        // Load issuer with new key + overlapping JWKS.
        var issuer = Sigstore.Oidc.OidcTokenIssuer.Load(
            "https://oidc.test.local",
            Path.Combine(genPath, "private", "oidc", "signer.key"),
            Path.Combine(genPath, "public", "oidc", "jwks.json"),
            "test@test.local");

        var token = issuer.CreateToken("test@test.local");
        Assert.NotNull(token);

        // Verify the token uses the new kid.
        var header = token.Split('.')[0]
            .Replace('-', '+').Replace('_', '/');
        header += (header.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        var headerJson = System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(header));
        using var doc = JsonDocument.Parse(headerJson);
        var kid = doc.RootElement.GetProperty("kid").GetString();
        Assert.Equal(candidate.KeyId, kid);

        issuer.Dispose();
    }

    [Fact]
    public void OldTokenVerifiesAgainstOverlappingJwks()
    {
        using var dir = new TemporaryDirectory();
        SetupInitialOidcState(dir.Path);
        var genPath = ResolveActiveGeneration(dir.Path);

        // Create a token with the old key.
        var oldIssuer = Sigstore.Oidc.OidcTokenIssuer.Load(
            "https://oidc.test.local",
            Path.Combine(genPath, "private", "oidc", "signer.key"),
            Path.Combine(genPath, "public", "oidc", "jwks.json"),
            "test@test.local");
        var oldToken = oldIssuer.CreateToken("test@test.local");
        var oldKeyId = OidcKeyRotation.ReadActiveKeyId(genPath);
        oldIssuer.Dispose();

        // Rotate: write overlapping JWKS + new key.
        var candidate = OidcKeyRotation.GenerateCandidate();
        OidcKeyRotation.WriteOverlappingJwks(genPath, candidate.Jwk);
        OidcKeyRotation.ActivateNewKey(genPath, candidate.PrivateKeyPem);

        // Load overlapping JWKS and verify old token.
        var jwksJson = File.ReadAllText(
            Path.Combine(genPath, "public", "oidc", "jwks.json"));
        using var jwksDoc = JsonDocument.Parse(jwksJson);
        var keys = jwksDoc.RootElement.GetProperty("keys")
            .EnumerateArray().ToArray();

        // Extract token header to find kid.
        var tokenParts = oldToken.Split('.');
        var headerBase64 = tokenParts[0].Replace('-', '+').Replace('_', '/');
        headerBase64 += (headerBase64.Length % 4) switch
        { 2 => "==", 3 => "=", _ => "" };
        var headerJson = System.Text.Encoding.UTF8.GetString(
            Convert.FromBase64String(headerBase64));
        using var headerDoc = JsonDocument.Parse(headerJson);
        var tokenKid = headerDoc.RootElement.GetProperty("kid").GetString();
        Assert.Equal(oldKeyId, tokenKid);

        // Find the old key in JWKS and verify signature.
        var oldJwk = keys.First(k =>
            k.GetProperty("kid").GetString() == oldKeyId);
        using var verifier = RSA.Create();
        var n = Base64UrlDecode(oldJwk.GetProperty("n").GetString()!);
        var e = Base64UrlDecode(oldJwk.GetProperty("e").GetString()!);
        verifier.ImportParameters(new RSAParameters
        {
            Modulus = n, Exponent = e
        });

        var signingInput = $"{tokenParts[0]}.{tokenParts[1]}";
        var signature = Base64UrlDecode(tokenParts[2]);
        var valid = verifier.VerifyData(
            System.Text.Encoding.ASCII.GetBytes(signingInput),
            signature,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        Assert.True(valid);
    }

    private static void SetupInitialOidcState(string rootPath)
    {
        // Bootstrap generates the initial state with OIDC keys.
        SigstoreStateBootstrapper.EnsureInitialized(rootPath);
    }

    private static string ResolveActiveGeneration(string rootPath)
    {
        var linkPath = Path.Combine(rootPath, "active-generation");
        var target = Directory.ResolveLinkTarget(linkPath, returnFinalTarget: true);
        return target?.FullName ?? Path.GetFullPath(linkPath);
    }

    private static byte[] Base64UrlDecode(string value)
    {
        var padded = value.Replace('-', '+').Replace('_', '/');
        padded += (padded.Length % 4) switch
        { 0 => "", 2 => "==", 3 => "=",
            _ => throw new InvalidOperationException() };
        return Convert.FromBase64String(padded);
    }
}
