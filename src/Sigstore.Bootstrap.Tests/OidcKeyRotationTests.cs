using System.Security.Cryptography;
using System.Text.Json;
using Xunit;

namespace Sigstore.Bootstrap.Tests;

/// <summary>
/// Tests for OIDC key rotation support: multi-key JWKS overlap
/// validation and active key selection in the bootstrap validator.
/// </summary>
public sealed class OidcKeyRotationTests : IDisposable
{
    private readonly string _tempDir;

    public OidcKeyRotationTests()
    {
        _tempDir = Path.Combine(
            Path.GetTempPath(),
            $"sigstore-oidc-rotation-tests-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); }
        catch { /* best effort */ }
    }

    [Fact]
    public void SingleKeyJwks_ValidatesSuccessfully()
    {
        SetupOidcKeyPair(_tempDir, out _, out _);
        var kid = SigstoreStateBootstrapper.ValidateOidcKeyPair(_tempDir);
        Assert.NotNull(kid);
        Assert.NotEmpty(kid);
    }

    [Fact]
    public void OverlappingJwks_TwoKeys_ValidatesActiveKey()
    {
        SetupOidcKeyPair(_tempDir, out var activeKid, out _);

        // Add an extra old key to JWKS
        AddExtraKeyToJwks(_tempDir);

        var validatedKid = SigstoreStateBootstrapper.ValidateOidcKeyPair(_tempDir);
        Assert.Equal(activeKid, validatedKid);
    }

    [Fact]
    public void OverlappingJwks_ThreeKeys_ValidatesActiveKey()
    {
        SetupOidcKeyPair(_tempDir, out var activeKid, out _);

        // Add two extra old keys
        AddExtraKeyToJwks(_tempDir);
        AddExtraKeyToJwks(_tempDir);

        var validatedKid = SigstoreStateBootstrapper.ValidateOidcKeyPair(_tempDir);
        Assert.Equal(activeKid, validatedKid);

        // Verify JWKS has 3 keys
        var jwksPath = Path.Combine(_tempDir, "public", "oidc", "jwks.json");
        var doc = JsonDocument.Parse(File.ReadAllText(jwksPath));
        Assert.Equal(3, doc.RootElement.GetProperty("keys").GetArrayLength());
    }

    [Fact]
    public void Jwks_MissingActiveKey_Throws()
    {
        SetupOidcKeyPair(_tempDir, out _, out _);

        // Replace JWKS with a key that doesn't match the private key
        var jwksPath = Path.Combine(_tempDir, "public", "oidc", "jwks.json");
        using var wrongRsa = RSA.Create(2048);
        var wrongParams = wrongRsa.ExportParameters(false);
        var wrongKid = Base64UrlEncode(
            SHA256.HashData(wrongRsa.ExportSubjectPublicKeyInfo()));
        File.WriteAllText(jwksPath, JsonSerializer.Serialize(new
        {
            keys = new[] { new {
                kty = "RSA", use = "sig", kid = wrongKid, alg = "RS256",
                n = Base64UrlEncode(wrongParams.Modulus!),
                e = Base64UrlEncode(wrongParams.Exponent!)
            }}
        }));

        var ex = Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.ValidateOidcKeyPair(_tempDir));
        Assert.Contains("active key ID", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Jwks_EmptyKeys_Throws()
    {
        SetupOidcKeyPair(_tempDir, out _, out _);
        var jwksPath = Path.Combine(_tempDir, "public", "oidc", "jwks.json");
        File.WriteAllText(jwksPath,
            JsonSerializer.Serialize(new { keys = Array.Empty<object>() }));

        var ex = Assert.Throws<InvalidDataException>(
            () => SigstoreStateBootstrapper.ValidateOidcKeyPair(_tempDir));
        Assert.Contains("at least one key", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void GeneratedKeys_HaveUniqueKids()
    {
        var kids = new HashSet<string>();
        for (int i = 0; i < 5; i++)
        {
            using var rsa = RSA.Create(2048);
            var kid = Base64UrlEncode(
                SHA256.HashData(rsa.ExportSubjectPublicKeyInfo()));
            Assert.True(kids.Add(kid), $"Duplicate kid generated: {kid}");
        }
    }

    [Fact]
    public void Kid_IsSha256OfSpki()
    {
        SetupOidcKeyPair(_tempDir, out var kid, out var rsa);
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var expectedKid = Base64UrlEncode(SHA256.HashData(spki));
        Assert.Equal(expectedKid, kid);
        rsa.Dispose();
    }

    private static void SetupOidcKeyPair(string rootPath, out string kid, out RSA rsa)
    {
        var privatePath = Path.Combine(rootPath, "private", "oidc");
        var publicPath = Path.Combine(rootPath, "public", "oidc");
        Directory.CreateDirectory(privatePath);
        Directory.CreateDirectory(publicPath);

        rsa = RSA.Create(2048);
        File.WriteAllText(
            Path.Combine(privatePath, "signer.key"),
            rsa.ExportPkcs8PrivateKeyPem());
        File.WriteAllText(
            Path.Combine(publicPath, "signer.pub"),
            rsa.ExportSubjectPublicKeyInfoPem());

        var spki = rsa.ExportSubjectPublicKeyInfo();
        kid = Base64UrlEncode(SHA256.HashData(spki));
        var parameters = rsa.ExportParameters(false);

        var jwks = JsonSerializer.Serialize(new
        {
            keys = new[] { new {
                kty = "RSA", use = "sig", kid, alg = "RS256",
                n = Base64UrlEncode(parameters.Modulus!),
                e = Base64UrlEncode(parameters.Exponent!)
            }}
        });
        File.WriteAllText(Path.Combine(publicPath, "jwks.json"), jwks);
    }

    private static void AddExtraKeyToJwks(string rootPath)
    {
        var jwksPath = Path.Combine(rootPath, "public", "oidc", "jwks.json");
        var doc = JsonDocument.Parse(File.ReadAllText(jwksPath));
        var existingKeys = doc.RootElement.GetProperty("keys")
            .EnumerateArray().ToList();

        using var extraRsa = RSA.Create(2048);
        var extraParams = extraRsa.ExportParameters(false);
        var extraKid = Base64UrlEncode(
            SHA256.HashData(extraRsa.ExportSubjectPublicKeyInfo()));

        var allKeys = new List<object>();
        foreach (var k in existingKeys)
            allKeys.Add(JsonSerializer.Deserialize<object>(k.GetRawText())!);
        allKeys.Add(new {
            kty = "RSA", use = "sig", kid = extraKid, alg = "RS256",
            n = Base64UrlEncode(extraParams.Modulus!),
            e = Base64UrlEncode(extraParams.Exponent!)
        });

        File.WriteAllText(jwksPath,
            JsonSerializer.Serialize(new { keys = allKeys }));
    }

    private static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
