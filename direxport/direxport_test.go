package direxport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cpuguy83/ocijoin"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// makeRealisticLayout creates an OCI layout directory with a proper manifest
// structure: index -> manifest -> config + layers. This is needed because
// images.Walk traverses into manifest blobs to discover children.
func makeRealisticLayout(t *testing.T, platform *ocispec.Platform) (*ocijoin.LocalLayout, digest.Digest) {
	t.Helper()

	dir := t.TempDir()

	// Create blobs directory.
	blobDir := filepath.Join(dir, "blobs", "sha256")
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Config blob.
	config := []byte(`{"architecture":"` + platform.Architecture + `","os":"` + platform.OS + `"}`)
	configDigest := digest.FromBytes(config)
	writeBlobFile(t, blobDir, configDigest, config)

	// Layer blob.
	layer := []byte("layer data for " + platform.Architecture)
	layerDigest := digest.FromBytes(layer)
	writeBlobFile(t, blobDir, layerDigest, layer)

	// Manifest referencing config + layer.
	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    configDigest,
			Size:      int64(len(config)),
		},
		Layers: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageLayerGzip,
				Digest:    layerDigest,
				Size:      int64(len(layer)),
			},
		},
	}
	manifest.SchemaVersion = 2
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest.FromBytes(manifestData)
	writeBlobFile(t, blobDir, manifestDigest, manifestData)

	// index.json pointing to the manifest.
	idx := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    manifestDigest,
				Size:      int64(len(manifestData)),
				Platform:  platform,
			},
		},
	}
	idx.SchemaVersion = 2
	idxData, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idxData, 0o644); err != nil {
		t.Fatal(err)
	}

	ociLayout := ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion}
	layoutData, err := json.Marshal(ociLayout)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ocispec.ImageLayoutFile), layoutData, 0o644); err != nil {
		t.Fatal(err)
	}

	layout, err := ocijoin.NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	return layout, manifestDigest
}

func writeBlobFile(t *testing.T, blobDir string, dgst digest.Digest, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(blobDir, dgst.Encoded()), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestExport(t *testing.T) {
	ctx := context.Background()

	platform := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	layout, _ := makeRealisticLayout(t, platform)

	out := filepath.Join(t.TempDir(), "exported")
	if err := Export(ctx, layout, out); err != nil {
		t.Fatal(err)
	}

	// Should have oci-layout.
	ociLayoutData, err := os.ReadFile(filepath.Join(out, ocispec.ImageLayoutFile))
	if err != nil {
		t.Fatalf("missing oci-layout: %v", err)
	}
	var ociLayout ocispec.ImageLayout
	if err := json.Unmarshal(ociLayoutData, &ociLayout); err != nil {
		t.Fatal(err)
	}
	if ociLayout.Version != ocispec.ImageLayoutVersion {
		t.Fatalf("expected layout version %s, got %s", ocispec.ImageLayoutVersion, ociLayout.Version)
	}

	// Should have index.json that matches the layout's Index exactly.
	idxData, err := os.ReadFile(filepath.Join(out, "index.json"))
	if err != nil {
		t.Fatalf("missing index.json: %v", err)
	}
	expectedIdx, _ := layout.Index(ctx)
	expectedIdxData, _ := json.Marshal(expectedIdx)
	if !bytes.Equal(idxData, expectedIdxData) {
		t.Fatal("index.json does not match layout's Index")
	}

	// Verify each blob in the index is present and correct.
	for _, desc := range expectedIdx.Manifests {
		blobPath := filepath.Join(out, "blobs", desc.Digest.Algorithm().String(), desc.Digest.Encoded())
		data, err := os.ReadFile(blobPath)
		if err != nil {
			t.Fatalf("missing blob %s: %v", desc.Digest, err)
		}
		if int64(len(data)) != desc.Size {
			t.Fatalf("blob %s: expected size %d, got %d", desc.Digest, desc.Size, len(data))
		}
	}
}

func TestExportJoinedAndFiltered(t *testing.T) {
	ctx := context.Background()

	layout1, _ := makeRealisticLayout(t, &ocispec.Platform{OS: "linux", Architecture: "amd64"})
	layout2, _ := makeRealisticLayout(t, &ocispec.Platform{OS: "linux", Architecture: "arm64"})

	merged := ocijoin.Join(layout1, layout2)

	out := filepath.Join(t.TempDir(), "exported")
	if err := Export(ctx, merged, out); err != nil {
		t.Fatal(err)
	}

	// Verify index.json has both platforms.
	idxData, err := os.ReadFile(filepath.Join(out, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(idxData, &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 2 {
		t.Fatalf("expected 2 manifests in merged index, got %d", len(idx.Manifests))
	}

	// All manifest blobs should be present and readable.
	for _, desc := range idx.Manifests {
		blobPath := filepath.Join(out, "blobs", desc.Digest.Algorithm().String(), desc.Digest.Encoded())
		data, err := os.ReadFile(blobPath)
		if err != nil {
			t.Fatalf("missing blob %s: %v", desc.Digest, err)
		}

		// Parse manifest and verify its children are also present.
		var manifest ocispec.Manifest
		if err := json.Unmarshal(data, &manifest); err != nil {
			t.Fatalf("parsing manifest %s: %v", desc.Digest, err)
		}

		// Config should exist.
		configPath := filepath.Join(out, "blobs", manifest.Config.Digest.Algorithm().String(), manifest.Config.Digest.Encoded())
		if _, err := os.Stat(configPath); err != nil {
			t.Fatalf("missing config blob %s: %v", manifest.Config.Digest, err)
		}

		// Layers should exist.
		for _, layer := range manifest.Layers {
			layerPath := filepath.Join(out, "blobs", layer.Digest.Algorithm().String(), layer.Digest.Encoded())
			if _, err := os.Stat(layerPath); err != nil {
				t.Fatalf("missing layer blob %s: %v", layer.Digest, err)
			}
		}
	}
}

func TestExportPreservesIndex(t *testing.T) {
	ctx := context.Background()

	layout, _ := makeRealisticLayout(t, &ocispec.Platform{OS: "linux", Architecture: "amd64"})

	originalIdx, err := layout.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}

	out := filepath.Join(t.TempDir(), "exported")
	if err := Export(ctx, layout, out); err != nil {
		t.Fatal(err)
	}

	// The index.json should be byte-for-byte identical
	// to what the layout's Index() returns when marshaled.
	expectedData, _ := json.Marshal(originalIdx)
	actualData, err := os.ReadFile(filepath.Join(out, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actualData, expectedData) {
		t.Fatal("exported index.json does not match layout's Index()")
	}
}

func TestExportCanBeReadBack(t *testing.T) {
	ctx := context.Background()

	layout1, _ := makeRealisticLayout(t, &ocispec.Platform{OS: "linux", Architecture: "amd64"})
	layout2, _ := makeRealisticLayout(t, &ocispec.Platform{OS: "linux", Architecture: "arm64"})

	merged := ocijoin.Join(layout1, layout2)

	out := filepath.Join(t.TempDir(), "exported")
	if err := Export(ctx, merged, out); err != nil {
		t.Fatal(err)
	}

	// The exported directory should be a valid OCI layout that NewLocalLayout can read.
	reloaded, err := ocijoin.NewLocalLayout(out)
	if err != nil {
		t.Fatalf("exported layout is not valid: %v", err)
	}

	reloadedIdx, err := reloaded.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloadedIdx.Manifests) != 2 {
		t.Fatalf("expected 2 manifests in reloaded index, got %d", len(reloadedIdx.Manifests))
	}

	// Verify all blobs are readable through the reloaded layout.
	for _, desc := range reloadedIdx.Manifests {
		ra, err := reloaded.ReaderAt(ctx, desc)
		if err != nil {
			t.Fatalf("reading blob %s from reloaded layout: %v", desc.Digest, err)
		}
		data := make([]byte, ra.Size())
		if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		ra.Close()
		if int64(len(data)) != desc.Size {
			t.Fatalf("blob %s: expected size %d, got %d", desc.Digest, desc.Size, len(data))
		}
	}
}
