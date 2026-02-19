// Package direxport writes OCI image layouts as directories on the local filesystem.
package direxport

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/cpuguy83/ocijoin"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Export writes the given Layout as an OCI image layout directory at path.
// The directory will contain oci-layout, index.json, and all blobs
// referenced by the index's manifest tree under blobs/<algorithm>/<encoded>.
//
// The directory is created if it does not exist.
func Export(ctx context.Context, l ocijoin.Layout, path string) error {
	idx, err := l.Index(ctx)
	if err != nil {
		return fmt.Errorf("reading index: %w", err)
	}

	if err := os.MkdirAll(path, 0o755); err != nil {
		return fmt.Errorf("creating output directory: %w", err)
	}

	// Write oci-layout file.
	ociLayout := ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion}
	layoutData, err := json.Marshal(ociLayout)
	if err != nil {
		return fmt.Errorf("marshaling oci-layout: %w", err)
	}
	if err := os.WriteFile(filepath.Join(path, ocispec.ImageLayoutFile), layoutData, 0o444); err != nil {
		return fmt.Errorf("writing oci-layout: %w", err)
	}

	// Walk the index tree to discover and write all blobs.
	written := make(map[digest.Digest]struct{})

	handler := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if _, ok := written[desc.Digest]; ok {
			return nil, images.ErrSkipDesc
		}
		written[desc.Digest] = struct{}{}

		if err := writeBlob(ctx, path, l, desc); err != nil {
			return nil, fmt.Errorf("writing blob %s: %w", desc.Digest, err)
		}

		return images.Children(ctx, l, desc)
	})

	if err := images.Walk(ctx, handler, idx.Manifests...); err != nil {
		return fmt.Errorf("walking index: %w", err)
	}

	// Write index.json last — all blobs are already written.
	idxData, err := json.Marshal(idx)
	if err != nil {
		return fmt.Errorf("marshaling index.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(path, "index.json"), idxData, 0o444); err != nil {
		return fmt.Errorf("writing index.json: %w", err)
	}

	return nil
}

// writeBlob reads a blob from the layout and writes it to the blobs directory.
func writeBlob(ctx context.Context, root string, l ocijoin.Layout, desc ocispec.Descriptor) error {
	ra, err := l.ReaderAt(ctx, desc)
	if err != nil {
		return err
	}
	defer ra.Close()

	dir := filepath.Join(root, "blobs", desc.Digest.Algorithm().String())
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	f, err := os.OpenFile(filepath.Join(dir, desc.Digest.Encoded()), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		if os.IsExist(err) {
			// Already written (e.g. shared blob across algorithms); skip.
			return nil
		}
		return err
	}
	defer f.Close()

	if _, err := io.Copy(f, io.NewSectionReader(ra, 0, ra.Size())); err != nil {
		return err
	}

	return f.Sync()
}
