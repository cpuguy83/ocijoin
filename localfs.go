package ocijoin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/errdefs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// LocalLayout is a Layout backed by an OCI image layout directory on the local filesystem.
// The index is eagerly loaded at construction time and cached.
type LocalLayout struct {
	root  string
	index *ocispec.Index
}

// NewLocalLayout creates a new Layout backed by the OCI layout directory
// at the given path. The index.json is parsed eagerly.
func NewLocalLayout(path string) (*LocalLayout, error) {
	data, err := os.ReadFile(filepath.Join(path, "index.json"))
	if err != nil {
		return nil, fmt.Errorf("reading index.json: %w", err)
	}

	var idx ocispec.Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("parsing index.json: %w", err)
	}

	return &LocalLayout{
		root:  path,
		index: &idx,
	}, nil
}

// Index returns the cached OCI index for this layout.
func (l *LocalLayout) Index(_ context.Context) (*ocispec.Index, error) {
	return l.index, nil
}

// ReaderAt returns a content.ReaderAt for the blob identified by the descriptor's digest.
func (l *LocalLayout) ReaderAt(_ context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	path := filepath.Join(l.root, "blobs", desc.Digest.Algorithm().String(), desc.Digest.Encoded())
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("blob %s: %w", desc.Digest, errdefs.ErrNotFound)
		}
		return nil, fmt.Errorf("opening blob %s: %w", desc.Digest, err)
	}
	return &fileReaderAt{File: f}, nil
}

// fileReaderAt wraps an *os.File to implement content.ReaderAt.
// *os.File already provides ReadAt and Close; this adds Size().
type fileReaderAt struct {
	*os.File
}

func (f *fileReaderAt) Size() int64 {
	fi, err := f.File.Stat()
	if err != nil {
		return -1
	}
	return fi.Size()
}
