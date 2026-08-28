using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Sigstore.Bootstrap;

/// <summary>
/// Manages OIDC signing key rotation within the active generation.
/// The generation manifest's OidcKeyId is a historical bootstrap record;
/// the active signer is tracked independently via oidc-rotation.json.
/// </summary>
internal static class OidcKeyRotation
{
    private const string RotationStateFileName = "oidc-rotation.json";
    private const string RetainedKeysDirectory = "private/oidc/retained";
    private const string ActiveSignerKeyPath = "private/oidc/signer.key";
    private const string JwksPath = "public/oidc/jwks.json";

    private static readonly JsonSerializerOptions JsonOptions =
        new(JsonSerializerDefaults.Web)
        {
            WriteIndented = true
        };

    /// <summary>
    /// Reads the current OIDC rotation state, or returns null if no
    /// rotation has been performed (initial bootstrap state).
    /// </summary>
    public static OidcRotationState? ReadState(string statePath)
    {
        var stateFile = Path.Combine(statePath, RotationStateFileName);
        if (!File.Exists(stateFile))
        {
            return null;
        }

        var json = File.ReadAllText(stateFile);
        return JsonSerializer.Deserialize<OidcRotationState>(json, JsonOptions)
            ?? throw new InvalidDataException(
                "The OIDC rotation state file is invalid.");
    }

    /// <summary>
    /// Reads the current active key ID from the active generation's
    /// signer.key file.
    /// </summary>
    public static string ReadActiveKeyId(string activeGenerationPath)
    {
        var signerPath = Path.Combine(activeGenerationPath, ActiveSignerKeyPath);
        if (!File.Exists(signerPath))
        {
            throw new InvalidDataException(
                "The active OIDC signer key file does not exist.");
        }

        using var rsa = RSA.Create();
        rsa.ImportFromPem(File.ReadAllText(signerPath));
        return ComputeKeyId(rsa);
    }

    /// <summary>
    /// Reads all key IDs from the JWKS file.
    /// </summary>
    public static string[] ReadJwksKeyIds(string activeGenerationPath)
    {
        var jwksPath = Path.Combine(activeGenerationPath, JwksPath);
        if (!File.Exists(jwksPath))
        {
            throw new InvalidDataException(
                "The OIDC JWKS file does not exist.");
        }

        var json = File.ReadAllText(jwksPath);
        using var document = JsonDocument.Parse(json);
        return document.RootElement
            .GetProperty("keys")
            .EnumerateArray()
            .Select(k => k.GetProperty("kid").GetString()!)
            .ToArray();
    }

    /// <summary>
    /// Generates a new RSA 2048 key pair and returns the key ID, PEM-encoded
    /// private key, PEM-encoded public key, and a JWK object for the JWKS.
    /// </summary>
    public static OidcKeyCandidate GenerateCandidate()
    {
        using var privateKey = RSA.Create(2048);
        var publicKeyBytes = privateKey.ExportSubjectPublicKeyInfo();
        var parameters = privateKey.ExportParameters(
            includePrivateParameters: false);
        var keyId = Base64UrlEncode(SHA256.HashData(publicKeyBytes));

        var jwk = new OidcJwk(
            Kty: "RSA",
            Use: "sig",
            Kid: keyId,
            Alg: "RS256",
            N: Base64UrlEncode(parameters.Modulus!),
            E: Base64UrlEncode(parameters.Exponent!));

        return new OidcKeyCandidate(
            KeyId: keyId,
            PrivateKeyPem: privateKey.ExportPkcs8PrivateKeyPem(),
            PublicKeyPem: privateKey.ExportSubjectPublicKeyInfoPem(),
            Jwk: jwk);
    }

    /// <summary>
    /// Writes the overlapping JWKS (old + new public keys) atomically.
    /// The old JWKS content is preserved and the new key is appended.
    /// </summary>
    public static string WriteOverlappingJwks(
        string activeGenerationPath,
        OidcJwk newJwk)
    {
        var jwksPath = Path.Combine(activeGenerationPath, JwksPath);
        var existingJson = File.ReadAllText(jwksPath);
        using var document = JsonDocument.Parse(existingJson);
        var existingKeys = document.RootElement
            .GetProperty("keys")
            .EnumerateArray()
            .ToArray();

        // Build the new JWKS with all existing keys plus the new one.
        var allJwks = new List<object>();
        foreach (var key in existingKeys)
        {
            allJwks.Add(new
            {
                kty = key.GetProperty("kty").GetString(),
                use = key.GetProperty("use").GetString(),
                kid = key.GetProperty("kid").GetString(),
                alg = key.GetProperty("alg").GetString(),
                n = key.GetProperty("n").GetString(),
                e = key.GetProperty("e").GetString()
            });
        }

        allJwks.Add(new
        {
            kty = newJwk.Kty,
            use = newJwk.Use,
            kid = newJwk.Kid,
            alg = newJwk.Alg,
            n = newJwk.N,
            e = newJwk.E
        });

        var newJwksJson = JsonSerializer.Serialize(
            new { keys = allJwks },
            JsonOptions) + "\n";

        AtomicWrite(jwksPath, newJwksJson);
        return ComputeSha256(newJwksJson);
    }

    /// <summary>
    /// Retains the current active private key in the retained directory
    /// before replacing it with the new key.
    /// </summary>
    public static void RetainCurrentKey(
        string activeGenerationPath,
        string currentKeyId)
    {
        var retainedDir = Path.Combine(activeGenerationPath, RetainedKeysDirectory);
        Directory.CreateDirectory(retainedDir);

        var currentKeyPath = Path.Combine(activeGenerationPath, ActiveSignerKeyPath);
        var retainedPath = Path.Combine(retainedDir, $"key-{currentKeyId}.pem");

        if (!File.Exists(retainedPath))
        {
            File.Copy(currentKeyPath, retainedPath);
            // Restrict permissions on retained private key.
            if (!OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    retainedPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }
        }
    }

    /// <summary>
    /// Atomically replaces the active signer key with the new private key.
    /// </summary>
    public static void ActivateNewKey(
        string activeGenerationPath,
        string privateKeyPem)
    {
        var signerPath = Path.Combine(activeGenerationPath, ActiveSignerKeyPath);
        AtomicWrite(signerPath, privateKeyPem, isPrivate: true);
    }

    /// <summary>
    /// Writes or updates the OIDC rotation state file.
    /// </summary>
    public static void WriteState(
        string statePath,
        OidcRotationState state)
    {
        var stateFile = Path.Combine(statePath, RotationStateFileName);
        var json = JsonSerializer.Serialize(state, JsonOptions) + "\n";
        AtomicWrite(stateFile, json);
    }

    /// <summary>
    /// Computes the key ID (base64url-encoded SHA-256 of SPKI) from an RSA key.
    /// </summary>
    public static string ComputeKeyId(RSA key) =>
        Base64UrlEncode(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));

    private static void AtomicWrite(
        string path,
        string content,
        bool isPrivate = false)
    {
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);

        var tempPath = Path.Combine(
            directory,
            $".{Path.GetFileName(path)}.{Environment.ProcessId}.tmp");
        try
        {
            File.WriteAllText(tempPath, content, Encoding.UTF8);
            if (isPrivate && !OperatingSystem.IsWindows())
            {
                File.SetUnixFileMode(
                    tempPath,
                    UnixFileMode.UserRead | UnixFileMode.UserWrite);
            }

            File.Move(tempPath, path, overwrite: true);
        }
        catch
        {
            try { File.Delete(tempPath); }
            catch { /* best effort */ }
            throw;
        }
    }

    private static string ComputeSha256(string content)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexStringLower(hash);
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}

internal sealed record OidcRotationState(
    int SchemaVersion,
    string ActiveKeyId,
    string[] RetainedKeyIds,
    string JwksSha256,
    DateTimeOffset RotatedAtUtc,
    string OperationId);

internal sealed record OidcKeyCandidate(
    string KeyId,
    string PrivateKeyPem,
    string PublicKeyPem,
    OidcJwk Jwk);

internal sealed record OidcJwk(
    string Kty,
    string Use,
    string Kid,
    string Alg,
    string N,
    string E);
