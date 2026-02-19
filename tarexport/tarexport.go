// Package tarexport writes OCI image layouts as tar archives.
package tarexport

import (
	"archive/tar"
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/cpuguy83/oci-join"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// Export writes the given Layout as a tar archive in OCI image layout format.
// The tar contains oci-layout, index.json (preserved exactly from the layout),
// and all blobs referenced by the index's manifest tree.
func Export(ctx context.Context, l ocijoin.Layout, w io.Writer) error {
	idx, err := l.Index(ctx)
	if err != nil {
		return fmt.Errorf("reading index: %w", err)
	}

	tw := tar.NewWriter(w)
	defer tw.Close()

	// Write oci-layout file.
	ociLayout := ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion}
	layoutData, err := json.Marshal(ociLayout)
	if err != nil {
		return fmt.Errorf("marshaling oci-layout: %w", err)
	}
	if err := writeEntry(tw, ocispec.ImageLayoutFile, layoutData); err != nil {
		return fmt.Errorf("writing oci-layout: %w", err)
	}

	// Walk the index tree to discover and write all blobs.
	written := make(map[digest.Digest]struct{})

	handler := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		if _, ok := written[desc.Digest]; ok {
			return nil, images.ErrSkipDesc
		}
		written[desc.Digest] = struct{}{}

		if err := writeBlob(ctx, tw, l, desc); err != nil {
			return nil, fmt.Errorf("writing blob %s: %w", desc.Digest, err)
		}

		return images.Children(ctx, l, desc)
	})

	if err := images.Walk(ctx, handler, idx.Manifests...); err != nil {
		return fmt.Errorf("walking index: %w", err)
	}

	// Write index.json last — all blobs are already in the tar.
	idxData, err := json.Marshal(idx)
	if err != nil {
		return fmt.Errorf("marshaling index.json: %w", err)
	}
	if err := writeEntry(tw, "index.json", idxData); err != nil {
		return fmt.Errorf("writing index.json: %w", err)
	}

	return nil
}

// writeBlob reads a blob from the layout and writes it as a tar entry.
func writeBlob(ctx context.Context, tw *tar.Writer, l ocijoin.Layout, desc ocispec.Descriptor) error {
	ra, err := l.ReaderAt(ctx, desc)
	if err != nil {
		return err
	}
	defer ra.Close()

	hdr := &tar.Header{
		Name: fmt.Sprintf("blobs/%s/%s", desc.Digest.Algorithm(), desc.Digest.Encoded()),
		Mode: 0o444,
		Size: ra.Size(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}

	_, err = io.Copy(tw, io.NewSectionReader(ra, 0, ra.Size()))
	return err
}

// writeEntry writes a small data blob as a tar entry.
func writeEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name: name,
		Mode: 0o444,
		Size: int64(len(data)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}
