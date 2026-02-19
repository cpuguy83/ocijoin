package tarexport

import (
	"archive/tar"
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
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
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

// readTar extracts all entries from a tar archive into a map of name -> data.
func readTar(t *testing.T, data []byte) map[string][]byte {
	t.Helper()
	entries := make(map[string][]byte)
	tr := tar.NewReader(bytes.NewReader(data))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		entries[hdr.Name] = content
	}
	return entries
}

func TestExport(t *testing.T) {
	ctx := context.Background()

	platform := &ocispec.Platform{OS: "linux", Architecture: "amd64"}
	layout, _ := makeRealisticLayout(t, platform)

	var buf bytes.Buffer
	if err := Export(ctx, layout, &buf); err != nil {
		t.Fatal(err)
	}

	entries := readTar(t, buf.Bytes())

	// Should have oci-layout.
	ociLayoutData, ok := entries[ocispec.ImageLayoutFile]
	if !ok {
		t.Fatal("missing oci-layout in tar")
	}
	var ociLayout ocispec.ImageLayout
	if err := json.Unmarshal(ociLayoutData, &ociLayout); err != nil {
		t.Fatal(err)
	}
	if ociLayout.Version != ocispec.ImageLayoutVersion {
		t.Fatalf("expected layout version %s, got %s", ocispec.ImageLayoutVersion, ociLayout.Version)
	}

	// Should have index.json that matches the layout's Index exactly.
	idxData, ok := entries["index.json"]
	if !ok {
		t.Fatal("missing index.json in tar")
	}
	expectedIdx, _ := layout.Index(ctx)
	expectedIdxData, _ := json.Marshal(expectedIdx)
	if !bytes.Equal(idxData, expectedIdxData) {
		t.Fatal("index.json in tar does not match layout's Index")
	}

	// Should have blobs: manifest, config, and layer (3 blobs minimum).
	blobCount := 0
	for name := range entries {
		if len(name) > 6 && name[:6] == "blobs/" {
			blobCount++
		}
	}
	if blobCount < 3 {
		t.Fatalf("expected at least 3 blobs (manifest, config, layer), got %d", blobCount)
	}

	// Verify each blob in the index is present.
	for _, desc := range expectedIdx.Manifests {
		blobPath := "blobs/" + desc.Digest.Algorithm().String() + "/" + desc.Digest.Encoded()
		if _, ok := entries[blobPath]; !ok {
			t.Fatalf("missing blob %s in tar", blobPath)
		}
	}
}

func TestExportJoinedAndFiltered(t *testing.T) {
	ctx := context.Background()

	layout1, _ := makeRealisticLayout(t, &ocispec.Platform{OS: "linux", Architecture: "amd64"})
	layout2, _ := makeRealisticLayout(t, &ocispec.Platform{OS: "linux", Architecture: "arm64"})

	merged := ocijoin.Join(layout1, layout2)

	var buf bytes.Buffer
	if err := Export(ctx, merged, &buf); err != nil {
		t.Fatal(err)
	}

	entries := readTar(t, buf.Bytes())

	// Verify index.json has both platforms.
	var idx ocispec.Index
	if err := json.Unmarshal(entries["index.json"], &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 2 {
		t.Fatalf("expected 2 manifests in merged index, got %d", len(idx.Manifests))
	}

	// All blobs for both platforms should be present.
	blobCount := 0
	for name := range entries {
		if len(name) > 6 && name[:6] == "blobs/" {
			blobCount++
		}
	}
	// 2 manifests + 2 configs + 2 layers = 6, but configs are identical so 5 unique.
	if blobCount < 5 {
		t.Fatalf("expected at least 5 unique blobs, got %d", blobCount)
	}
}

func TestExportPreservesIndex(t *testing.T) {
	ctx := context.Background()

	layout, _ := makeRealisticLayout(t, &ocispec.Platform{OS: "linux", Architecture: "amd64"})

	// Get the original index.
	originalIdx, err := layout.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Export(ctx, layout, &buf); err != nil {
		t.Fatal(err)
	}

	entries := readTar(t, buf.Bytes())

	// The index.json in the tar should be byte-for-byte identical
	// to what the layout's Index() returns when marshaled.
	expectedData, _ := json.Marshal(originalIdx)
	if !bytes.Equal(entries["index.json"], expectedData) {
		t.Fatal("exported index.json does not match layout's Index()")
	}
}
