package ocijoin_test

import (
	"bytes"
	"context"
	"fmt"

	"github.com/cpuguy83/ocijoin"
	"github.com/cpuguy83/ocijoin/direxport"
	"github.com/cpuguy83/ocijoin/tarexport"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func ExampleNewLocalLayout() {
	// NewLocalLayout reads an OCI layout directory from disk.
	// The index.json is parsed eagerly at construction time.
	layout, err := ocijoin.NewLocalLayout("/path/to/oci-layout")
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	idx, _ := layout.Index(context.Background())
	fmt.Println("manifests:", len(idx.Manifests))
}

func ExampleJoin() {
	// Join merges multiple layouts into a single view.
	// Duplicate descriptors (by JSON equality) are deduplicated.
	amd64, _ := ocijoin.NewLocalLayout("/path/to/linux-amd64")
	arm64, _ := ocijoin.NewLocalLayout("/path/to/linux-arm64")

	merged := ocijoin.Join(amd64, arm64)

	idx, _ := merged.Index(context.Background())
	for _, desc := range idx.Manifests {
		fmt.Println(desc.Digest)
	}
}

func ExampleFilter() {
	// Filter keeps only index descriptors matching a predicate.
	// Blob access is unaffected -- all blobs remain accessible.
	layout, _ := ocijoin.NewLocalLayout("/path/to/oci-layout")

	// Keep only non-attestation manifests.
	filtered := ocijoin.Filter(layout, func(desc ocispec.Descriptor) bool {
		return !ocijoin.IsAttestation(desc)
	})

	idx, _ := filtered.Index(context.Background())
	fmt.Println("manifests after filtering:", len(idx.Manifests))
}

func ExampleUnwrap() {
	// Unwrap resolves a nested index. Many build tools (e.g. docker buildx)
	// produce layouts where index.json contains a single descriptor pointing
	// to an inner ImageIndex blob. Unwrap reads that blob and returns a
	// layout whose Index is the inner index.
	//
	// If the layout is not nested, it is returned unchanged.
	layout, _ := ocijoin.NewLocalLayout("/path/to/oci-layout")

	unwrapped := ocijoin.Unwrap(layout)

	idx, _ := unwrapped.Index(context.Background())
	for _, desc := range idx.Manifests {
		fmt.Println(desc.Platform.Architecture, desc.Digest)
	}
}

func ExampleWrap() {
	// Wrap nests a layout's index inside a new outer index with annotations.
	// This is the inverse of Unwrap and is useful for producing layouts
	// compatible with tools like oras that expect a tagged outer index.
	layout, _ := ocijoin.NewLocalLayout("/path/to/oci-layout")

	wrapped := ocijoin.Wrap(layout, map[string]string{
		"org.opencontainers.image.ref.name": "v1.0.0",
		"io.containerd.image.name":          "registry.example.com/myimage:v1.0.0",
	})

	idx, _ := wrapped.Index(context.Background())
	fmt.Println("outer descriptors:", len(idx.Manifests))
	fmt.Println("tag:", idx.Manifests[0].Annotations["org.opencontainers.image.ref.name"])
}

// This example shows a complete multiplatform merge workflow:
// load per-platform layouts, unwrap nested indexes, merge, re-wrap
// with tag annotations, and export to a directory.
func Example_multiplatformMerge() {
	layoutPaths := []string{
		"/path/to/linux-amd64",
		"/path/to/linux-arm64",
	}

	layouts := make([]ocijoin.Layout, len(layoutPaths))
	for i, p := range layoutPaths {
		l, _ := ocijoin.NewLocalLayout(p)
		layouts[i] = ocijoin.Unwrap(l)
	}

	merged := ocijoin.Join(layouts...)
	wrapped := ocijoin.Wrap(merged, map[string]string{
		"org.opencontainers.image.ref.name": "v1.0.0",
	})

	// Export as a directory for use with oras or other tools.
	_ = direxport.Export(context.Background(), wrapped, "/path/to/output")

	// Or export as a tar archive.
	var buf bytes.Buffer
	_ = tarexport.Export(context.Background(), wrapped, &buf)
}
