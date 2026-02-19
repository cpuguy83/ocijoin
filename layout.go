// Package ocijoin provides composable primitives for reading, merging,
// filtering, wrapping, and exporting OCI image layouts.
//
// The central type is [Layout], an interface that combines an OCI index
// with containerd's [content.Provider] for blob access. Layouts are
// assumed to be immutable.
//
// Primitives can be composed freely:
//
//   - [NewLocalLayout] reads an OCI layout directory from disk.
//   - [Join] merges multiple layouts into a single deduplicated view.
//   - [Filter] keeps only index descriptors matching a predicate.
//   - [Unwrap] resolves a nested index (outer index pointing to inner index).
//   - [Wrap] nests a layout's index inside a new outer index with annotations.
//   - [IsIndex] and [IsAttestation] are predicate helpers for common filtering.
//
// Because [Layout] embeds [content.Provider], all layouts are directly usable
// with containerd's image push/pull infrastructure.
//
// Sub-packages [tarexport] and [direxport] write layouts to tar archives and
// filesystem directories respectively.
//
// A typical multiplatform merge workflow:
//
//	// Load per-platform layouts produced by docker build.
//	for _, path := range layoutPaths {
//	    l, _ := ocijoin.NewLocalLayout(path)
//	    layouts = append(layouts, ocijoin.Unwrap(l))
//	}
//
//	// Merge, re-wrap with tag annotations, and export.
//	merged := ocijoin.Join(layouts...)
//	wrapped := ocijoin.Wrap(merged, map[string]string{
//	    "org.opencontainers.image.ref.name": tag,
//	})
//	direxport.Export(ctx, wrapped, outputDir)
package ocijoin

import (
	"context"

	"github.com/containerd/containerd/v2/core/content"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Layout provides read-only access to an immutable OCI image layout.
// It embeds content.Provider, making it directly usable with
// containerd's push/pull infrastructure.
type Layout interface {
	content.Provider

	// Index returns the OCI index for this layout.
	Index(ctx context.Context) (*ocispec.Index, error)
}
