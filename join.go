package ocijoin

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	imgspecs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// joined implements Layout by merging multiple underlying Layouts.
type joined struct {
	layouts []Layout

	once  sync.Once
	index *ocispec.Index
	err   error
}

// Join returns a Layout that presents a merged view of the given layouts.
// The merged index contains deduplicated descriptors from all layouts.
// Blob lookups search the underlying layouts in order.
func Join(layouts ...Layout) Layout {
	return &joined{layouts: layouts}
}

// Index returns the merged OCI index, computed once and cached.
// Descriptors are deduplicated by comparing their JSON-marshaled form.
func (j *joined) Index(ctx context.Context) (*ocispec.Index, error) {
	j.once.Do(func() {
		j.index, j.err = j.buildIndex(ctx)
	})
	return j.index, j.err
}

func (j *joined) buildIndex(ctx context.Context) (*ocispec.Index, error) {
	seen := make(map[string]struct{})
	merged := &ocispec.Index{
		Versioned: imgspecs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageIndex,
	}

	for _, l := range j.layouts {
		idx, err := l.Index(ctx)
		if err != nil {
			return nil, fmt.Errorf("reading index: %w", err)
		}

		for _, desc := range idx.Manifests {
			key, err := json.Marshal(desc)
			if err != nil {
				return nil, fmt.Errorf("marshaling descriptor: %w", err)
			}

			if _, ok := seen[string(key)]; ok {
				continue
			}
			seen[string(key)] = struct{}{}
			merged.Manifests = append(merged.Manifests, desc)
		}
	}

	return merged, nil
}

// ReaderAt searches the underlying layouts in order and returns the first
// matching blob for the given descriptor.
func (j *joined) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	for _, l := range j.layouts {
		ra, err := l.ReaderAt(ctx, desc)
		if err != nil {
			if errdefs.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		return ra, nil
	}
	return nil, fmt.Errorf("blob %s: %w", desc.Digest, errdefs.ErrNotFound)
}
