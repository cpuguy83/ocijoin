package ocijoin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// makeTestLayout creates a minimal OCI layout directory in a temp dir
// with the given blobs and index entries.
func makeTestLayout(t *testing.T, blobs map[digest.Digest][]byte) string {
	t.Helper()

	dir := t.TempDir()

	var descs []ocispec.Descriptor
	for dgst, data := range blobs {
		algoDir := filepath.Join(dir, "blobs", dgst.Algorithm().String())
		if err := os.MkdirAll(algoDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(algoDir, dgst.Encoded()), data, 0o644); err != nil {
			t.Fatal(err)
		}
		descs = append(descs, ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    dgst,
			Size:      int64(len(data)),
		})
	}

	idx := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: descs,
	}
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

	return dir
}

func blobDigest(data []byte) digest.Digest {
	return digest.FromBytes(data)
}

func TestLocalLayout(t *testing.T) {
	blob1 := []byte("hello world")
	dgst1 := blobDigest(blob1)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})

	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Test Index
	idx, err := layout.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(idx.Manifests))
	}
	if idx.Manifests[0].Digest != dgst1 {
		t.Fatalf("expected digest %s, got %s", dgst1, idx.Manifests[0].Digest)
	}

	// Test ReaderAt
	desc := ocispec.Descriptor{Digest: dgst1, Size: int64(len(blob1))}
	ra, err := layout.ReaderAt(ctx, desc)
	if err != nil {
		t.Fatal(err)
	}
	defer ra.Close()

	data := make([]byte, ra.Size())
	if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	if !bytes.Equal(data, blob1) {
		t.Fatalf("expected %q, got %q", blob1, data)
	}

	// Test missing blob
	missingDesc := ocispec.Descriptor{Digest: digest.FromBytes([]byte("nonexistent"))}
	_, err = layout.ReaderAt(ctx, missingDesc)
	if err == nil {
		t.Fatal("expected error for missing blob")
	}
	if !errdefs.IsNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestJoin(t *testing.T) {
	blob1 := []byte("blob one")
	blob2 := []byte("blob two")
	blob3 := []byte("blob three")
	dgst1 := blobDigest(blob1)
	dgst2 := blobDigest(blob2)
	dgst3 := blobDigest(blob3)

	dir1 := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2})
	dir2 := makeTestLayout(t, map[digest.Digest][]byte{dgst2: blob2, dgst3: blob3})

	layout1, err := NewLocalLayout(dir1)
	if err != nil {
		t.Fatal(err)
	}
	layout2, err := NewLocalLayout(dir2)
	if err != nil {
		t.Fatal(err)
	}

	joined := Join(layout1, layout2)
	ctx := context.Background()

	// Test merged index
	idx, err := joined.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Should have 3 unique descriptors (dgst2 appears in both but same descriptor)
	if len(idx.Manifests) != 3 {
		t.Fatalf("expected 3 manifests, got %d", len(idx.Manifests))
	}

	// Test blob access — all three should be accessible
	for dgst, expected := range map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2, dgst3: blob3} {
		desc := ocispec.Descriptor{Digest: dgst, Size: int64(len(expected))}
		ra, err := joined.ReaderAt(ctx, desc)
		if err != nil {
			t.Fatalf("blob %s: %v", dgst, err)
		}

		data := make([]byte, ra.Size())
		if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
			t.Fatalf("blob %s read: %v", dgst, err)
		}
		ra.Close()

		if !bytes.Equal(data, expected) {
			t.Fatalf("blob %s: expected %q, got %q", dgst, expected, data)
		}
	}

	// Test missing blob
	missingDesc := ocispec.Descriptor{Digest: digest.FromBytes([]byte("missing"))}
	_, err = joined.ReaderAt(ctx, missingDesc)
	if err == nil {
		t.Fatal("expected error for missing blob")
	}
	if !errdefs.IsNotFound(err) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestFilter(t *testing.T) {
	blob1 := []byte("manifest one")
	blob2 := []byte("manifest two")
	blob3 := []byte("attestation")
	dgst1 := blobDigest(blob1)
	dgst2 := blobDigest(blob2)
	dgst3 := blobDigest(blob3)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2, dgst3: blob3})

	// Patch the index to give descriptors distinguishing annotations.
	idx := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{MediaType: ocispec.MediaTypeImageManifest, Digest: dgst1, Size: int64(len(blob1))},
			{MediaType: ocispec.MediaTypeImageManifest, Digest: dgst2, Size: int64(len(blob2))},
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    dgst3,
				Size:      int64(len(blob3)),
				Annotations: map[string]string{
					"vnd.docker.reference.type": "attestation-manifest",
				},
			},
		},
	}
	idxData, err := json.Marshal(idx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idxData, 0o644); err != nil {
		t.Fatal(err)
	}

	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Filter out attestation manifests.
	noAttestations := Filter(layout, func(desc ocispec.Descriptor) bool {
		return desc.Annotations["vnd.docker.reference.type"] != "attestation-manifest"
	})

	filteredIdx, err := noAttestations.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(filteredIdx.Manifests) != 2 {
		t.Fatalf("expected 2 manifests after filter, got %d", len(filteredIdx.Manifests))
	}
	for _, desc := range filteredIdx.Manifests {
		if desc.Digest == dgst3 {
			t.Fatal("attestation descriptor should have been filtered out")
		}
	}

	// Blobs for filtered-out descriptors should still be accessible.
	ra, err := noAttestations.ReaderAt(ctx, ocispec.Descriptor{Digest: dgst3, Size: int64(len(blob3))})
	if err != nil {
		t.Fatalf("expected filtered-out blob to still be accessible: %v", err)
	}
	data := make([]byte, ra.Size())
	if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	ra.Close()
	if !bytes.Equal(data, blob3) {
		t.Fatalf("expected %q, got %q", blob3, data)
	}
}

func TestFilterExcludesAll(t *testing.T) {
	blob1 := []byte("only blob")
	dgst1 := blobDigest(blob1)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})
	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Filter that rejects everything.
	empty := Filter(layout, func(ocispec.Descriptor) bool { return false })

	idx, err := empty.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 0 {
		t.Fatalf("expected 0 manifests, got %d", len(idx.Manifests))
	}
}

func TestFilterWithJoin(t *testing.T) {
	blob1 := []byte("platform manifest")
	blob2 := []byte("attestation manifest")
	blob3 := []byte("other platform manifest")
	dgst1 := blobDigest(blob1)
	dgst2 := blobDigest(blob2)
	dgst3 := blobDigest(blob3)

	// Layout 1: has a platform manifest and an attestation.
	dir1 := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2})
	idx1 := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{MediaType: ocispec.MediaTypeImageManifest, Digest: dgst1, Size: int64(len(blob1))},
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    dgst2,
				Size:      int64(len(blob2)),
				Annotations: map[string]string{
					"vnd.docker.reference.type": "attestation-manifest",
				},
			},
		},
	}
	idxData1, _ := json.Marshal(idx1)
	os.WriteFile(filepath.Join(dir1, "index.json"), idxData1, 0o644)

	// Layout 2: has a plain platform manifest.
	dir2 := makeTestLayout(t, map[digest.Digest][]byte{dgst3: blob3})

	layout1, err := NewLocalLayout(dir1)
	if err != nil {
		t.Fatal(err)
	}
	layout2, err := NewLocalLayout(dir2)
	if err != nil {
		t.Fatal(err)
	}

	// Filter attestations from layout1, then join with layout2.
	filterFn := func(desc ocispec.Descriptor) bool {
		return desc.Annotations["vnd.docker.reference.type"] != "attestation-manifest"
	}
	merged := Join(Filter(layout1, filterFn), layout2)

	ctx := context.Background()
	idx, err := merged.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Should have dgst1 from filtered layout1 + dgst3 from layout2.
	if len(idx.Manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(idx.Manifests))
	}

	digests := make(map[digest.Digest]bool)
	for _, desc := range idx.Manifests {
		digests[desc.Digest] = true
	}
	if !digests[dgst1] {
		t.Fatal("expected dgst1 in merged index")
	}
	if digests[dgst2] {
		t.Fatal("attestation dgst2 should have been filtered out")
	}
	if !digests[dgst3] {
		t.Fatal("expected dgst3 in merged index")
	}
}

func TestIsIndex(t *testing.T) {
	tests := []struct {
		name string
		desc ocispec.Descriptor
		want bool
	}{
		{"OCI image index", ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex}, true},
		{"Docker manifest list", ocispec.Descriptor{MediaType: "application/vnd.docker.distribution.manifest.list.v2+json"}, true},
		{"image manifest", ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest}, false},
		{"empty", ocispec.Descriptor{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsIndex(tt.desc); got != tt.want {
				t.Fatalf("IsIndex() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsAttestation(t *testing.T) {
	tests := []struct {
		name string
		desc ocispec.Descriptor
		want bool
	}{
		{
			"attestation",
			ocispec.Descriptor{Annotations: map[string]string{"vnd.docker.reference.type": "attestation-manifest"}},
			true,
		},
		{
			"not attestation",
			ocispec.Descriptor{Annotations: map[string]string{"vnd.docker.reference.type": "other"}},
			false,
		},
		{"no annotations", ocispec.Descriptor{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsAttestation(tt.desc); got != tt.want {
				t.Fatalf("IsAttestation() = %v, want %v", got, tt.want)
			}
		})
	}
}

// makeNestedLayout creates an OCI layout with a nested index structure:
// index.json (outer) -> inner index blob -> platform manifest blobs.
// The inner index contains the given descriptors. Additional blobs are
// written to the layout's blob store so they can be resolved.
func makeNestedLayout(t *testing.T, innerDescs []ocispec.Descriptor, blobs map[digest.Digest][]byte) string {
	t.Helper()

	dir := t.TempDir()

	// Write all provided blobs.
	for dgst, data := range blobs {
		algoDir := filepath.Join(dir, "blobs", dgst.Algorithm().String())
		if err := os.MkdirAll(algoDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(algoDir, dgst.Encoded()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Build and write the inner index as a blob.
	innerIdx := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: innerDescs,
	}
	innerData, err := json.Marshal(innerIdx)
	if err != nil {
		t.Fatal(err)
	}
	innerDigest := blobDigest(innerData)

	algoDir := filepath.Join(dir, "blobs", innerDigest.Algorithm().String())
	if err := os.MkdirAll(algoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(algoDir, innerDigest.Encoded()), innerData, 0o644); err != nil {
		t.Fatal(err)
	}

	// Write the outer index.json pointing to the inner index.
	outerIdx := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageIndex,
				Digest:    innerDigest,
				Size:      int64(len(innerData)),
				Annotations: map[string]string{
					"org.opencontainers.image.ref.name": "latest",
				},
			},
		},
	}
	outerData, err := json.Marshal(outerIdx)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), outerData, 0o644); err != nil {
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

	return dir
}

func TestUnwrap(t *testing.T) {
	// Create a nested layout: outer index -> inner index -> platform manifest.
	platformBlob := []byte("platform manifest data")
	platformDigest := blobDigest(platformBlob)

	innerDescs := []ocispec.Descriptor{
		{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    platformDigest,
			Size:      int64(len(platformBlob)),
			Platform:  &ocispec.Platform{OS: "linux", Architecture: "amd64"},
		},
	}
	dir := makeNestedLayout(t, innerDescs, map[digest.Digest][]byte{platformDigest: platformBlob})

	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Before unwrap: outer index has one ImageIndex descriptor.
	outerIdx, err := layout.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(outerIdx.Manifests) != 1 {
		t.Fatalf("expected 1 outer manifest, got %d", len(outerIdx.Manifests))
	}
	if outerIdx.Manifests[0].MediaType != ocispec.MediaTypeImageIndex {
		t.Fatalf("expected outer descriptor to be an index, got %s", outerIdx.Manifests[0].MediaType)
	}

	// After unwrap: should see the inner index's platform manifest.
	unwrapped := Unwrap(layout)
	innerIdx, err := unwrapped.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(innerIdx.Manifests) != 1 {
		t.Fatalf("expected 1 inner manifest, got %d", len(innerIdx.Manifests))
	}
	if innerIdx.Manifests[0].Digest != platformDigest {
		t.Fatalf("expected digest %s, got %s", platformDigest, innerIdx.Manifests[0].Digest)
	}
	if innerIdx.Manifests[0].Platform.Architecture != "amd64" {
		t.Fatalf("expected amd64 platform, got %s", innerIdx.Manifests[0].Platform.Architecture)
	}

	// Blobs should still be accessible.
	ra, err := unwrapped.ReaderAt(ctx, ocispec.Descriptor{Digest: platformDigest, Size: int64(len(platformBlob))})
	if err != nil {
		t.Fatal(err)
	}
	data := make([]byte, ra.Size())
	if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	ra.Close()
	if !bytes.Equal(data, platformBlob) {
		t.Fatalf("expected %q, got %q", platformBlob, data)
	}
}

func TestUnwrapNoMatch(t *testing.T) {
	// Layout with no nested index — just plain manifest descriptors.
	blob1 := []byte("plain manifest")
	dgst1 := blobDigest(blob1)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})
	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Unwrap should return the original layout unchanged.
	unwrapped := Unwrap(layout)
	idx, err := unwrapped.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("expected 1 manifest, got %d", len(idx.Manifests))
	}
	if idx.Manifests[0].Digest != dgst1 {
		t.Fatalf("expected digest %s, got %s", dgst1, idx.Manifests[0].Digest)
	}
}

func TestUnwrapWithFilter(t *testing.T) {
	// Create a layout whose outer index has two index descriptors:
	// one tagged "v1" and one tagged "v2". Each points to a different inner index.
	blob1 := []byte("v1 manifest data")
	blob2 := []byte("v2 manifest data")
	dgst1 := blobDigest(blob1)
	dgst2 := blobDigest(blob2)

	dir := t.TempDir()

	// Write blobs.
	for dgst, data := range map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2} {
		algoDir := filepath.Join(dir, "blobs", dgst.Algorithm().String())
		if err := os.MkdirAll(algoDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(algoDir, dgst.Encoded()), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Inner index 1 (v1): contains dgst1.
	inner1 := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{MediaType: ocispec.MediaTypeImageManifest, Digest: dgst1, Size: int64(len(blob1))},
		},
	}
	inner1Data, _ := json.Marshal(inner1)
	inner1Digest := blobDigest(inner1Data)

	// Inner index 2 (v2): contains dgst2.
	inner2 := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{MediaType: ocispec.MediaTypeImageManifest, Digest: dgst2, Size: int64(len(blob2))},
		},
	}
	inner2Data, _ := json.Marshal(inner2)
	inner2Digest := blobDigest(inner2Data)

	// Write inner index blobs.
	for dgst, data := range map[digest.Digest][]byte{inner1Digest: inner1Data, inner2Digest: inner2Data} {
		algoDir := filepath.Join(dir, "blobs", dgst.Algorithm().String())
		os.MkdirAll(algoDir, 0o755)
		os.WriteFile(filepath.Join(algoDir, dgst.Encoded()), data, 0o644)
	}

	// Outer index: two image index descriptors with different tags.
	outerIdx := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{
			{
				MediaType:   ocispec.MediaTypeImageIndex,
				Digest:      inner1Digest,
				Size:        int64(len(inner1Data)),
				Annotations: map[string]string{"org.opencontainers.image.ref.name": "v1"},
			},
			{
				MediaType:   ocispec.MediaTypeImageIndex,
				Digest:      inner2Digest,
				Size:        int64(len(inner2Data)),
				Annotations: map[string]string{"org.opencontainers.image.ref.name": "v2"},
			},
		},
	}
	outerData, _ := json.Marshal(outerIdx)
	os.WriteFile(filepath.Join(dir, "index.json"), outerData, 0o644)

	ociLayout := ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion}
	layoutData, _ := json.Marshal(ociLayout)
	os.WriteFile(filepath.Join(dir, ocispec.ImageLayoutFile), layoutData, 0o644)

	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Without filter: unwraps the first index (v1).
	unwrapped := Unwrap(layout)
	idx, err := unwrapped.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 1 || idx.Manifests[0].Digest != dgst1 {
		t.Fatalf("expected dgst1 from v1 index, got %v", idx.Manifests)
	}

	// With filter: unwrap the v2 index.
	unwrappedV2 := UnwrapWithFilter(layout, func(desc ocispec.Descriptor) bool {
		return desc.Annotations["org.opencontainers.image.ref.name"] == "v2"
	})
	idx2, err := unwrappedV2.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(idx2.Manifests) != 1 || idx2.Manifests[0].Digest != dgst2 {
		t.Fatalf("expected dgst2 from v2 index, got %v", idx2.Manifests)
	}
}

func TestUnwrapFilterAndJoin(t *testing.T) {
	// Simulate the dalec-build-defs pattern:
	// Two per-platform layouts, each with:
	//   outer index -> inner index -> [platform manifest, attestation manifest]
	// We want to unwrap + filter attestations + join.

	amdBlob := []byte("amd64 manifest")
	amdAttest := []byte("amd64 attestation")
	armBlob := []byte("arm64 manifest")
	armAttest := []byte("arm64 attestation")
	amdDigest := blobDigest(amdBlob)
	amdAttestDigest := blobDigest(amdAttest)
	armDigest := blobDigest(armBlob)
	armAttestDigest := blobDigest(armAttest)

	// Layout 1: linux/amd64 with attestation.
	dir1 := makeNestedLayout(t,
		[]ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    amdDigest,
				Size:      int64(len(amdBlob)),
				Platform:  &ocispec.Platform{OS: "linux", Architecture: "amd64"},
			},
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    amdAttestDigest,
				Size:      int64(len(amdAttest)),
				Annotations: map[string]string{
					"vnd.docker.reference.digest": amdDigest.String(),
					"vnd.docker.reference.type":   "attestation-manifest",
				},
				Platform: &ocispec.Platform{OS: "unknown", Architecture: "unknown"},
			},
		},
		map[digest.Digest][]byte{amdDigest: amdBlob, amdAttestDigest: amdAttest},
	)

	// Layout 2: linux/arm64 with attestation.
	dir2 := makeNestedLayout(t,
		[]ocispec.Descriptor{
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    armDigest,
				Size:      int64(len(armBlob)),
				Platform:  &ocispec.Platform{OS: "linux", Architecture: "arm64"},
			},
			{
				MediaType: ocispec.MediaTypeImageManifest,
				Digest:    armAttestDigest,
				Size:      int64(len(armAttest)),
				Annotations: map[string]string{
					"vnd.docker.reference.digest": armDigest.String(),
					"vnd.docker.reference.type":   "attestation-manifest",
				},
				Platform: &ocispec.Platform{OS: "unknown", Architecture: "unknown"},
			},
		},
		map[digest.Digest][]byte{armDigest: armBlob, armAttestDigest: armAttest},
	)

	layout1, err := NewLocalLayout(dir1)
	if err != nil {
		t.Fatal(err)
	}
	layout2, err := NewLocalLayout(dir2)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// The dalec-build-defs pattern: Unwrap -> Filter -> Join.
	noAttestations := func(desc ocispec.Descriptor) bool {
		return !IsAttestation(desc)
	}
	merged := Join(
		Filter(Unwrap(layout1), noAttestations),
		Filter(Unwrap(layout2), noAttestations),
	)

	idx, err := merged.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Should have exactly 2 platform manifests, no attestations.
	if len(idx.Manifests) != 2 {
		t.Fatalf("expected 2 manifests, got %d", len(idx.Manifests))
	}

	digests := make(map[digest.Digest]bool)
	for _, desc := range idx.Manifests {
		digests[desc.Digest] = true
		if IsAttestation(desc) {
			t.Fatalf("attestation should have been filtered: %s", desc.Digest)
		}
	}
	if !digests[amdDigest] {
		t.Fatal("expected amd64 manifest in merged index")
	}
	if !digests[armDigest] {
		t.Fatal("expected arm64 manifest in merged index")
	}

	// Attestation blobs should still be accessible through the merged layout.
	for dgst, expected := range map[digest.Digest][]byte{amdAttestDigest: amdAttest, armAttestDigest: armAttest} {
		ra, err := merged.ReaderAt(ctx, ocispec.Descriptor{Digest: dgst, Size: int64(len(expected))})
		if err != nil {
			t.Fatalf("expected attestation blob %s to be accessible: %v", dgst, err)
		}
		data := make([]byte, ra.Size())
		if _, err := ra.ReadAt(data, 0); err != nil && err != io.EOF {
			t.Fatal(err)
		}
		ra.Close()
		if !bytes.Equal(data, expected) {
			t.Fatalf("blob %s: expected %q, got %q", dgst, expected, data)
		}
	}
}

func TestJoinDeduplication(t *testing.T) {
	blob1 := []byte("shared blob")
	dgst1 := blobDigest(blob1)

	// Both layouts have the exact same descriptor
	dir1 := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})
	dir2 := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})

	layout1, err := NewLocalLayout(dir1)
	if err != nil {
		t.Fatal(err)
	}
	layout2, err := NewLocalLayout(dir2)
	if err != nil {
		t.Fatal(err)
	}

	joined := Join(layout1, layout2)
	ctx := context.Background()

	idx, err := joined.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Should be deduplicated to 1 entry
	if len(idx.Manifests) != 1 {
		t.Fatalf("expected 1 manifest after dedup, got %d", len(idx.Manifests))
	}
}
