using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sigstore.Oidc;

internal sealed class OidcTokenIssuer : IDisposable
{
    private const string Audience = "sigstore";
    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web);

    private readonly Lock signingLock = new();
    private readonly RSA signingKey;
    private readonly string keyId;

    private OidcTokenIssuer(
        string issuer,
        string defaultIdentity,
        string jwksJson,
        string keyId,
        RSA signingKey)
    {
        Issuer = issuer;
        DefaultIdentity = defaultIdentity;
        JwksJson = jwksJson;
        this.keyId = keyId;
        this.signingKey = signingKey;
    }

    public string Issuer { get; }

    public string DefaultIdentity { get; }

    public string JwksJson { get; }

    public static OidcTokenIssuer Load(
        string issuer,
        string privateKeyPath,
        string jwksPath,
        string defaultIdentity)
    {
        var normalizedIssuer = NormalizeIssuer(issuer);
        if (!IsValidIdentity(defaultIdentity))
        {
            throw new InvalidDataException(
                "The default OIDC identity must be an email address.");
        }

        var signingKey = RSA.Create();
        try
        {
            signingKey.ImportFromPem(
                File.ReadAllText(privateKeyPath));
            var jwksJson = File.ReadAllText(jwksPath);
            var keyId = ValidateJwks(signingKey, jwksJson);

            return new OidcTokenIssuer(
                normalizedIssuer,
                defaultIdentity,
                jwksJson,
                keyId,
                signingKey);
        }
        catch
        {
            signingKey.Dispose();
            throw;
        }
    }

    public object CreateDiscoveryDocument() => new
    {
        issuer = Issuer,
        jwks_uri = $"{Issuer}/jwks",
        token_endpoint = $"{Issuer}/token",
        response_types_supported = new[]
        {
            "id_token"
        },
        subject_types_supported = new[]
        {
            "public"
        },
        id_token_signing_alg_values_supported = new[]
        {
            "RS256"
        },
        scopes_supported = new[]
        {
            "openid",
            "email"
        },
        claims_supported = new[]
        {
            "iss",
            "sub",
            "aud",
            "iat",
            "nbf",
            "exp",
            "email",
            "email_verified"
        }
    };

    public string CreateToken(string identity)
    {
        if (!IsValidIdentity(identity))
        {
            throw new ArgumentException(
                "The identity must be an email address.",
                nameof(identity));
        }

        var now = DateTimeOffset.UtcNow;
        var header = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                alg = "RS256",
                kid = keyId,
                typ = "JWT"
            },
            JsonOptions);
        var payload = JsonSerializer.SerializeToUtf8Bytes(
            new
            {
                iss = Issuer,
                sub = identity,
                aud = Audience,
                iat = now.ToUnixTimeSeconds(),
                nbf = now.AddSeconds(-5).ToUnixTimeSeconds(),
                exp = now.AddMinutes(5).ToUnixTimeSeconds(),
                email = identity,
                email_verified = true
            },
            JsonOptions);
        var signingInput =
            $"{Base64UrlEncode(header)}.{Base64UrlEncode(payload)}";
        byte[] signature;

        lock (signingLock)
        {
            signature = signingKey.SignData(
                Encoding.ASCII.GetBytes(signingInput),
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1);
        }

        return $"{signingInput}.{Base64UrlEncode(signature)}";
    }

    public static bool IsValidIdentity(string identity)
    {
        if (string.IsNullOrWhiteSpace(identity)
            || identity.Length > 254
            || identity.Any(char.IsWhiteSpace))
        {
            return false;
        }

        var atIndex = identity.IndexOf('@');
        return atIndex > 0
            && atIndex == identity.LastIndexOf('@')
            && atIndex < identity.Length - 1;
    }

    public void Dispose() => signingKey.Dispose();

    private static string NormalizeIssuer(string issuer)
    {
        if (!Uri.TryCreate(
            issuer,
            UriKind.Absolute,
            out var uri)
            || !string.Equals(
                uri.Scheme,
                Uri.UriSchemeHttps,
                StringComparison.OrdinalIgnoreCase)
            || !string.IsNullOrEmpty(uri.Query)
            || !string.IsNullOrEmpty(uri.Fragment))
        {
            throw new InvalidDataException(
                "The OIDC issuer must be an absolute HTTPS URL.");
        }

        return uri.AbsoluteUri.TrimEnd('/');
    }

    private static string ValidateJwks(
        RSA signingKey,
        string jwksJson)
    {
        using var document = JsonDocument.Parse(jwksJson);
        var keys = document.RootElement
            .GetProperty("keys")
            .EnumerateArray()
            .ToArray();

        if (keys.Length != 1)
        {
            throw new InvalidDataException(
                "The OIDC JWKS must contain exactly one key.");
        }

        var key = keys[0];
        EnsureEqual("key type", "RSA", key.GetProperty("kty").GetString());
        EnsureEqual("key use", "sig", key.GetProperty("use").GetString());
        EnsureEqual("algorithm", "RS256", key.GetProperty("alg").GetString());

        var parameters = signingKey.ExportParameters(
            includePrivateParameters: false);
        EnsureKeyBytesEqual(
            "modulus",
            parameters.Modulus!,
            Base64UrlDecode(key.GetProperty("n").GetString()));
        EnsureKeyBytesEqual(
            "exponent",
            parameters.Exponent!,
            Base64UrlDecode(key.GetProperty("e").GetString()));

        var expectedKeyId = Base64UrlEncode(
            SHA256.HashData(
                signingKey.ExportSubjectPublicKeyInfo()));
        EnsureEqual(
            "key ID",
            expectedKeyId,
            key.GetProperty("kid").GetString());

        return expectedKeyId;
    }

    private static void EnsureKeyBytesEqual(
        string description,
        byte[] expected,
        byte[] actual)
    {
        if (!CryptographicOperations.FixedTimeEquals(
            expected,
            actual))
        {
            throw new InvalidDataException(
                $"The OIDC JWKS {description} does not match " +
                "the private key.");
        }
    }

    private static void EnsureEqual(
        string description,
        string expected,
        string? actual)
    {
        if (!string.Equals(
            expected,
            actual,
            StringComparison.Ordinal))
        {
            throw new InvalidDataException(
                $"The OIDC JWKS {description} is invalid.");
        }
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static byte[] Base64UrlDecode(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidDataException(
                "The OIDC JWKS contains an empty key value.");
        }

        var padded = value
            .Replace('-', '+')
            .Replace('_', '/');
        padded += (padded.Length % 4) switch
        {
            0 => string.Empty,
            2 => "==",
            3 => "=",
            _ => throw new InvalidDataException(
                "The OIDC JWKS contains invalid base64url data.")
        };

        return Convert.FromBase64String(padded);
    }
}
