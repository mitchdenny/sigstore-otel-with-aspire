package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewClientTrustStatusUsesVerifiedTargetBytes(t *testing.T) {
	trustedRoot := []byte("{\"trusted\":true}\n")
	signingConfig := []byte("{\"signing\":true}\n")
	published := publishedTrustStatus{
		SchemaVersion:            trustStatusSchema,
		TrustDomainID:            "sha256-" + strings.Repeat("a", 64),
		Generation:               1,
		GenerationID:             "generation-00000001",
		GenerationManifestSHA256: strings.Repeat("b", 64),
		TUFRootVersion:           2,
		TUFTargetsVersion:        3,
		TrustedRootSHA256:        sha256Hex(trustedRoot),
		SigningConfigSHA256:      sha256Hex(signingConfig),
	}
	publishedBytes, err := json.Marshal(published)
	if err != nil {
		t.Fatal(err)
	}
	initializedAt := time.Date(
		2026,
		time.August,
		27,
		0,
		0,
		0,
		0,
		time.UTC,
	)

	status, err := newClientTrustStatus(
		"go-client",
		"go",
		publishedBytes,
		trustedRoot,
		signingConfig,
		2,
		3,
		initializedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !status.Ready ||
		status.TrustedRootSHA256 != published.TrustedRootSHA256 ||
		status.SigningConfigSHA256 != published.SigningConfigSHA256 ||
		!status.InitializedAtUTC.Equal(initializedAt) {
		t.Fatalf("unexpected client trust status: %+v", status)
	}

	trustedRoot[0] ^= 0xff
	if _, err := newClientTrustStatus(
		"go-client",
		"go",
		publishedBytes,
		trustedRoot,
		signingConfig,
		2,
		3,
		initializedAt,
	); err == nil {
		t.Fatal("changed trusted-root bytes were accepted")
	}
}

func TestReadTUFMetadataVersionRejectsInvalidVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "root.json")
	if err := os.WriteFile(
		path,
		[]byte(`{"signed":{"version":4}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	version, err := readTUFMetadataVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if version != 4 {
		t.Fatalf("version = %d, want 4", version)
	}

	if err := os.WriteFile(
		path,
		[]byte(`{"signed":{"version":0}}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := readTUFMetadataVersion(path); err == nil {
		t.Fatal("zero metadata version was accepted")
	}
}
