package ocijoin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sync"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// IsIndex reports whether desc has an image index media type.
// This covers both OCI image indexes and Docker manifest lists.
func IsIndex(desc ocispec.Descriptor) bool {
	return images.IsIndexType(desc.MediaType)
}

// IsAttestation reports whether desc is an attestation manifest,
// identified by the "vnd.docker.reference.type" annotation.
func IsAttestation(desc ocispec.Descriptor) bool {
	return desc.Annotations["vnd.docker.reference.type"] == "attestation-manifest"
}

// filtered implements Layout by wrapping another Layout and filtering its
// index descriptors through a predicate function.
type filtered struct {
	layout Layout
	fn     func(ocispec.Descriptor) bool

	once  sync.Once
	index *ocispec.Index
	err   error
}

// Filter returns a Layout whose Index contains only the descriptors from l's
// Index for which fn returns true. Blob access via ReaderAt is unaffected;
// all blobs remain accessible regardless of filtering.
func Filter(l Layout, fn func(ocispec.Descriptor) bool) Layout {
	return &filtered{layout: l, fn: fn}
}

// Index returns the filtered OCI index, computed once and cached.
func (f *filtered) Index(ctx context.Context) (*ocispec.Index, error) {
	f.once.Do(func() {
		f.index, f.err = f.buildIndex(ctx)
	})
	return f.index, f.err
}

func (f *filtered) buildIndex(ctx context.Context) (*ocispec.Index, error) {
	idx, err := f.layout.Index(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading index: %w", err)
	}

	out := &ocispec.Index{
		Versioned:   idx.Versioned,
		MediaType:   idx.MediaType,
		Annotations: idx.Annotations,
	}

	for _, desc := range idx.Manifests {
		if f.fn(desc) {
			out.Manifests = append(out.Manifests, desc)
		}
	}

	return out, nil
}

// ReaderAt delegates directly to the underlying layout.
func (f *filtered) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	return f.layout.ReaderAt(ctx, desc)
}

// unwrapped implements Layout by resolving a nested index descriptor from the
// underlying layout's Index into a new top-level index.
type unwrapped struct {
	layout Layout
	fn     func(ocispec.Descriptor) bool

	once  sync.Once
	inner Layout
	err   error
}

// Unwrap returns a Layout whose Index is the first nested image index found
// in l's Index. If l's Index contains no image index descriptors, l is
// returned unchanged.
//
// This is equivalent to UnwrapWithFilter(l, nil).
func Unwrap(l Layout) Layout {
	return UnwrapWithFilter(l, nil)
}

// UnwrapWithFilter returns a Layout whose Index is the first nested image
// index found in l's Index for which fn returns true. The IsIndex check is
// always applied; fn provides additional filtering on top of that.
// If fn is nil, any image index descriptor matches.
//
// If no matching descriptor is found, l is returned unchanged.
// The returned Layout shares the same blob store as l.
func UnwrapWithFilter(l Layout, fn func(ocispec.Descriptor) bool) Layout {
	return &unwrapped{layout: l, fn: fn}
}

func (u *unwrapped) Index(ctx context.Context) (*ocispec.Index, error) {
	u.once.Do(func() {
		u.inner, u.err = u.resolve(ctx)
	})
	if u.err != nil {
		return nil, u.err
	}
	return u.inner.Index(ctx)
}

func (u *unwrapped) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	return u.layout.ReaderAt(ctx, desc)
}

func (u *unwrapped) resolve(ctx context.Context) (Layout, error) {
	idx, err := u.layout.Index(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading index: %w", err)
	}

	for _, desc := range idx.Manifests {
		if !IsIndex(desc) {
			continue
		}
		if u.fn != nil && !u.fn(desc) {
			continue
		}

		ra, err := u.layout.ReaderAt(ctx, desc)
		if err != nil {
			return nil, fmt.Errorf("reading nested index blob %s: %w", desc.Digest, err)
		}
		defer ra.Close()

		data, err := io.ReadAll(io.NewSectionReader(ra, 0, ra.Size()))
		if err != nil {
			return nil, fmt.Errorf("reading nested index blob %s: %w", desc.Digest, err)
		}

		var inner ocispec.Index
		if err := json.Unmarshal(data, &inner); err != nil {
			return nil, fmt.Errorf("parsing nested index blob %s: %w", desc.Digest, err)
		}

		return &staticLayout{index: &inner, provider: u.layout}, nil
	}

	// No matching nested index found; return the original layout unchanged.
	return u.layout, nil
}

// staticLayout is a Layout backed by a pre-built index and an existing
// content.Provider for blob access.
type staticLayout struct {
	index    *ocispec.Index
	provider content.Provider
}

func (s *staticLayout) Index(_ context.Context) (*ocispec.Index, error) {
	return s.index, nil
}

func (s *staticLayout) ReaderAt(ctx context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	return s.provider.ReaderAt(ctx, desc)
}
