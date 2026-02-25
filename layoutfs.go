package ocijoin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// NewFS returns an [fs.FS] that presents the layout as an OCI image layout
// directory tree. The tree contains oci-layout, index.json, and all blobs
// referenced by the index's manifest tree under blobs/<algorithm>/<encoded>.
//
// The returned FS implements [fs.StatFS], [fs.ReadFileFS], and [fs.ReadDirFS].
// The context is used for index access and blob reads.
func NewFS(ctx context.Context, l Layout) fs.FS {
	return &layoutFS{ctx: ctx, layout: l}
}

// layoutFS implements fs.FS over a Layout.
type layoutFS struct {
	ctx    context.Context
	layout Layout

	// Lazy-computed index data.
	indexOnce  sync.Once
	indexBytes []byte
	indexErr   error

	// Lazy-computed blob enumeration: algorithm -> sorted list of blob entries.
	blobsOnce   sync.Once
	blobsByAlgo map[string][]blobEntry // e.g. "sha256" -> [{encoded, size}, ...]
	algos       []string               // sorted algorithm names
	blobsErr    error
}

// blobEntry stores the encoded digest and size of a blob for directory listings.
type blobEntry struct {
	encoded string
	size    int64
}

// Open implements [fs.FS].
func (f *layoutFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}

	switch name {
	case ".":
		return f.openRootDir()
	case "oci-layout":
		return f.openOCILayout()
	case "index.json":
		return f.openIndexJSON()
	case "blobs":
		return f.openBlobsDir()
	}

	// blobs/<algo> or blobs/<algo>/<encoded>
	if !strings.HasPrefix(name, "blobs/") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}

	rest := strings.TrimPrefix(name, "blobs/")
	algo, encoded, hasEncoded := strings.Cut(rest, "/")

	if !hasEncoded {
		// blobs/<algo> directory
		return f.openAlgoDir(name, algo)
	}

	// Reject paths with extra slashes (e.g. "blobs/sha256/abc/extra").
	if strings.Contains(encoded, "/") {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}

	return f.openBlob(name, algo, encoded)
}

// Stat implements [fs.StatFS].
func (f *layoutFS) Stat(name string) (fs.FileInfo, error) {
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return file.Stat()
}

// ReadFile implements [fs.ReadFileFS].
func (f *layoutFS) ReadFile(name string) ([]byte, error) {
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(file)
}

// ReadDir implements [fs.ReadDirFS].
func (f *layoutFS) ReadDir(name string) ([]fs.DirEntry, error) {
	file, err := f.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	dir, ok := file.(fs.ReadDirFile)
	if !ok {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: fmt.Errorf("not a directory")}
	}
	return dir.ReadDir(-1)
}

// --- index.json and oci-layout ---

func (f *layoutFS) marshalIndex() ([]byte, error) {
	f.indexOnce.Do(func() {
		idx, err := f.layout.Index(f.ctx)
		if err != nil {
			f.indexErr = fmt.Errorf("reading index: %w", err)
			return
		}
		f.indexBytes, f.indexErr = json.Marshal(idx)
	})
	return f.indexBytes, f.indexErr
}

var ociLayoutBytes = func() []byte {
	data, _ := json.Marshal(ocispec.ImageLayout{Version: ocispec.ImageLayoutVersion})
	return data
}()

func (f *layoutFS) openOCILayout() (fs.File, error) {
	return newBytesFile("oci-layout", ociLayoutBytes), nil
}

func (f *layoutFS) openIndexJSON() (fs.File, error) {
	data, err := f.marshalIndex()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: "index.json", Err: err}
	}
	return newBytesFile("index.json", data), nil
}

// --- blob enumeration ---

func (f *layoutFS) enumerateBlobs() (map[string][]blobEntry, []string, error) {
	f.blobsOnce.Do(func() {
		idx, err := f.layout.Index(f.ctx)
		if err != nil {
			f.blobsErr = fmt.Errorf("reading index: %w", err)
			return
		}

		byAlgo := make(map[string][]blobEntry)
		seen := make(map[digest.Digest]struct{})

		handler := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
			if _, ok := seen[desc.Digest]; ok {
				return nil, images.ErrSkipDesc
			}
			seen[desc.Digest] = struct{}{}

			algo := desc.Digest.Algorithm().String()
			byAlgo[algo] = append(byAlgo[algo], blobEntry{encoded: desc.Digest.Encoded(), size: desc.Size})

			children, err := images.Children(ctx, f.layout, desc)
			if err != nil {
				// Blob is a leaf (e.g. config, layer) that can't be parsed
				// for children. This is normal and expected.
				return nil, nil
			}
			return children, nil
		})

		if err := images.Walk(f.ctx, handler, idx.Manifests...); err != nil {
			f.blobsErr = fmt.Errorf("walking index: %w", err)
			return
		}

		// Sort for deterministic directory listings.
		algos := make([]string, 0, len(byAlgo))
		for algo, entries := range byAlgo {
			sort.Slice(entries, func(i, j int) bool {
				return entries[i].encoded < entries[j].encoded
			})
			byAlgo[algo] = entries
			algos = append(algos, algo)
		}
		sort.Strings(algos)

		f.blobsByAlgo = byAlgo
		f.algos = algos
	})
	return f.blobsByAlgo, f.algos, f.blobsErr
}

func (f *layoutFS) openBlob(name, algo, encoded string) (fs.File, error) {
	dgst := digest.NewDigestFromEncoded(digest.Algorithm(algo), encoded)
	if err := dgst.Validate(); err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}

	desc := ocispec.Descriptor{Digest: dgst}
	ra, err := f.layout.ReaderAt(f.ctx, desc)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
	}

	return &blobFile{
		name:   encoded,
		ra:     ra,
		reader: io.NewSectionReader(ra, 0, ra.Size()),
		size:   ra.Size(),
	}, nil
}

// blobFile implements fs.File over a content.ReaderAt.
type blobFile struct {
	name   string
	ra     io.Closer
	reader *io.SectionReader
	size   int64
}

func (b *blobFile) Read(p []byte) (int, error)              { return b.reader.Read(p) }
func (b *blobFile) ReadAt(p []byte, off int64) (int, error) { return b.reader.ReadAt(p, off) }
func (b *blobFile) Close() error                            { return b.ra.Close() }
func (b *blobFile) Stat() (fs.FileInfo, error)              { return fileInfo{b.name, b.size, false}, nil }
func (b *blobFile) Seek(offset int64, whence int) (int64, error) {
	return b.reader.Seek(offset, whence)
}

func (f *layoutFS) openRootDir() (fs.File, error) {
	entries := []fs.DirEntry{
		dirEntry{name: "blobs", dir: true},
		dirEntry{name: "index.json", size: int64(len(f.indexBytes))},
		dirEntry{name: "oci-layout", size: int64(len(ociLayoutBytes))},
	}

	// Ensure index is marshaled so we can report the correct size.
	data, err := f.marshalIndex()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: ".", Err: err}
	}
	entries[1] = dirEntry{name: "index.json", size: int64(len(data))}

	return &dir{name: ".", entries: entries}, nil
}

func (f *layoutFS) openBlobsDir() (fs.File, error) {
	_, algos, err := f.enumerateBlobs()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: "blobs", Err: err}
	}

	entries := make([]fs.DirEntry, len(algos))
	for i, algo := range algos {
		entries[i] = dirEntry{name: algo, dir: true}
	}

	return &dir{name: "blobs", entries: entries}, nil
}

func (f *layoutFS) openAlgoDir(fullPath, algo string) (fs.File, error) {
	byAlgo, _, err := f.enumerateBlobs()
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: fullPath, Err: err}
	}

	blobs, ok := byAlgo[algo]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: fullPath, Err: fs.ErrNotExist}
	}

	entries := make([]fs.DirEntry, len(blobs))
	for i, b := range blobs {
		entries[i] = dirEntry{name: b.encoded, size: b.size}
	}

	return &dir{name: algo, entries: entries}, nil
}

// dir implements fs.ReadDirFile for a directory with known entries.
type dir struct {
	name    string
	entries []fs.DirEntry
	offset  int
}

func (d *dir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: fmt.Errorf("is a directory")}
}

func (d *dir) Close() error { return nil }

func (d *dir) Stat() (fs.FileInfo, error) {
	return fileInfo{name: d.name, dir: true}, nil
}

func (d *dir) ReadDir(n int) ([]fs.DirEntry, error) {
	if n <= 0 {
		entries := d.entries[d.offset:]
		d.offset = len(d.entries)
		return entries, nil
	}

	if d.offset >= len(d.entries) {
		return nil, io.EOF
	}

	end := d.offset + n
	if end > len(d.entries) {
		end = len(d.entries)
	}
	entries := d.entries[d.offset:end]
	d.offset = end

	if d.offset >= len(d.entries) {
		return entries, io.EOF
	}
	return entries, nil
}

// --- shared fileInfo and dirEntry ---

// fileInfo implements fs.FileInfo for files and directories.
type fileInfo struct {
	name string
	size int64
	dir  bool
}

func (fi fileInfo) Name() string { return path.Base(fi.name) }
func (fi fileInfo) Size() int64  { return fi.size }
func (fi fileInfo) Mode() fs.FileMode {
	if fi.dir {
		return fs.ModeDir | 0o555
	}
	return 0o444
}
func (fi fileInfo) ModTime() time.Time { return time.Time{} }
func (fi fileInfo) IsDir() bool        { return fi.dir }
func (fi fileInfo) Sys() any           { return nil }

// dirEntry implements fs.DirEntry.
type dirEntry struct {
	name string
	size int64
	dir  bool
}

func (e dirEntry) Name() string { return e.name }
func (e dirEntry) IsDir() bool  { return e.dir }
func (e dirEntry) Type() fs.FileMode {
	if e.dir {
		return fs.ModeDir
	}
	return 0
}
func (e dirEntry) Info() (fs.FileInfo, error) {
	return fileInfo(e), nil
}

// --- bytesFile for oci-layout and index.json ---

// bytesFile implements fs.File over an in-memory byte slice.
type bytesFile struct {
	name   string
	reader *bytes.Reader
	size   int64
}

func newBytesFile(name string, data []byte) *bytesFile {
	return &bytesFile{
		name:   name,
		reader: bytes.NewReader(data),
		size:   int64(len(data)),
	}
}

func (b *bytesFile) Read(p []byte) (int, error)              { return b.reader.Read(p) }
func (b *bytesFile) ReadAt(p []byte, off int64) (int, error) { return b.reader.ReadAt(p, off) }
func (b *bytesFile) Close() error                            { return nil }
func (b *bytesFile) Stat() (fs.FileInfo, error)              { return fileInfo{b.name, b.size, false}, nil }
func (b *bytesFile) Seek(offset int64, whence int) (int64, error) {
	return b.reader.Seek(offset, whence)
}
