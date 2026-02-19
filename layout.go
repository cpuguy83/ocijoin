// Package ocijoin provides tools for joining multiple OCI image layouts
// into a single merged view.
//
// Layouts are assumed to be immutable.
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
