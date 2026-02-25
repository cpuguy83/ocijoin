package ocijoin

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"sort"
	"testing"
	"testing/fstest"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestFSTestFS(t *testing.T) {
	blob1 := []byte("manifest one")
	blob2 := []byte("manifest two")
	dgst1 := blobDigest(blob1)
	dgst2 := blobDigest(blob2)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2})
	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	fsys := NewFS(ctx, layout)

	// Build the list of expected files for fstest.TestFS.
	expected := []string{
		"oci-layout",
		"index.json",
		"blobs/" + dgst1.Algorithm().String() + "/" + dgst1.Encoded(),
		"blobs/" + dgst2.Algorithm().String() + "/" + dgst2.Encoded(),
	}

	if err := fstest.TestFS(fsys, expected...); err != nil {
		t.Fatal(err)
	}
}

func TestFSWalkDir(t *testing.T) {
	blob1 := []byte("blob alpha")
	blob2 := []byte("blob beta")
	dgst1 := blobDigest(blob1)
	dgst2 := blobDigest(blob2)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2})
	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	fsys := NewFS(ctx, layout)

	var paths []string
	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		paths = append(paths, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Build expected paths.
	algo := dgst1.Algorithm().String()
	encodedDigests := []string{dgst1.Encoded(), dgst2.Encoded()}
	sort.Strings(encodedDigests)

	expected := []string{
		".",
		"blobs",
		"blobs/" + algo,
	}
	for _, e := range encodedDigests {
		expected = append(expected, "blobs/"+algo+"/"+e)
	}
	expected = append(expected, "index.json", "oci-layout")

	sort.Strings(paths)
	sort.Strings(expected)

	if len(paths) != len(expected) {
		t.Fatalf("WalkDir: got %d paths, want %d\ngot:  %v\nwant: %v", len(paths), len(expected), paths, expected)
	}
	for i := range paths {
		if paths[i] != expected[i] {
			t.Fatalf("WalkDir: path[%d] = %q, want %q", i, paths[i], expected[i])
		}
	}
}

func TestFSReadFile(t *testing.T) {
	blob1 := []byte("content of blob one")
	dgst1 := blobDigest(blob1)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})
	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	fsys := NewFS(ctx, layout)

	// Read oci-layout.
	data, err := fs.ReadFile(fsys, "oci-layout")
	if err != nil {
		t.Fatal(err)
	}
	var ociLayout ocispec.ImageLayout
	if err := json.Unmarshal(data, &ociLayout); err != nil {
		t.Fatalf("parsing oci-layout: %v", err)
	}
	if ociLayout.Version != ocispec.ImageLayoutVersion {
		t.Fatalf("oci-layout version = %q, want %q", ociLayout.Version, ocispec.ImageLayoutVersion)
	}

	// Read index.json.
	data, err = fs.ReadFile(fsys, "index.json")
	if err != nil {
		t.Fatal(err)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(data, &idx); err != nil {
		t.Fatalf("parsing index.json: %v", err)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("index.json: got %d manifests, want 1", len(idx.Manifests))
	}
	if idx.Manifests[0].Digest != dgst1 {
		t.Fatalf("index.json: manifest digest = %s, want %s", idx.Manifests[0].Digest, dgst1)
	}

	// Read a blob.
	blobPath := "blobs/" + dgst1.Algorithm().String() + "/" + dgst1.Encoded()
	data, err = fs.ReadFile(fsys, blobPath)
	if err != nil {
		t.Fatalf("reading blob: %v", err)
	}
	if string(data) != string(blob1) {
		t.Fatalf("blob content = %q, want %q", data, blob1)
	}
}

func TestFSStat(t *testing.T) {
	blob1 := []byte("stat test blob")
	dgst1 := blobDigest(blob1)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})
	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	fsys := NewFS(ctx, layout)

	tests := []struct {
		name  string
		isDir bool
		size  int64 // -1 to skip size check
	}{
		{".", true, -1},
		{"blobs", true, -1},
		{"blobs/" + dgst1.Algorithm().String(), true, -1},
		{"oci-layout", false, -1},
		{"index.json", false, -1},
		{"blobs/" + dgst1.Algorithm().String() + "/" + dgst1.Encoded(), false, int64(len(blob1))},
	}

	for _, tt := range tests {
		fi, err := fs.Stat(fsys, tt.name)
		if err != nil {
			t.Fatalf("Stat(%q): %v", tt.name, err)
		}
		if fi.IsDir() != tt.isDir {
			t.Fatalf("Stat(%q).IsDir() = %v, want %v", tt.name, fi.IsDir(), tt.isDir)
		}
		if tt.size >= 0 && fi.Size() != tt.size {
			t.Fatalf("Stat(%q).Size() = %d, want %d", tt.name, fi.Size(), tt.size)
		}
		if !tt.isDir && fi.Mode() != 0o444 {
			t.Fatalf("Stat(%q).Mode() = %v, want 0444", tt.name, fi.Mode())
		}
		if tt.isDir && fi.Mode() != (fs.ModeDir|0o555) {
			t.Fatalf("Stat(%q).Mode() = %v, want d0555", tt.name, fi.Mode())
		}
	}
}

func TestFSNotExist(t *testing.T) {
	blob1 := []byte("exists")
	dgst1 := blobDigest(blob1)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})
	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	fsys := NewFS(ctx, layout)

	notExist := []string{
		"nonexistent",
		"blobs/sha256/0000000000000000000000000000000000000000000000000000000000000000",
		"blobs/sha512",
		"blobs/sha256/abc/extra",
	}

	for _, name := range notExist {
		_, err := fsys.Open(name)
		if err == nil {
			t.Fatalf("Open(%q): expected error, got nil", name)
		}
		if !isNotExist(err) {
			t.Fatalf("Open(%q): expected fs.ErrNotExist, got %v", name, err)
		}
	}
}

func isNotExist(err error) bool {
	var pathErr *fs.PathError
	if ok := errorAs(err, &pathErr); ok {
		return pathErr.Err == fs.ErrNotExist || pathErr.Err == fs.ErrInvalid
	}
	return false
}

func errorAs[T any](err error, target *T) bool {
	return err != nil && asError(err, target)
}

// asError wraps errors.As to avoid import cycle concerns in test helpers.
func asError[T any](err error, target *T) bool {
	for {
		if t, ok := any(err).(*fs.PathError); ok {
			if tt, ok := any(t).(T); ok {
				*target = tt
				return true
			}
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
}

func TestFSRoundTrip(t *testing.T) {
	// Create a layout, wrap it in FS, read everything back, and verify consistency.
	blob1 := []byte("round trip one")
	blob2 := []byte("round trip two")
	dgst1 := blobDigest(blob1)
	dgst2 := blobDigest(blob2)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2})
	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// Get index from layout directly.
	origIdx, err := layout.Index(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Read index.json from FS and compare.
	fsys := NewFS(ctx, layout)
	data, err := fs.ReadFile(fsys, "index.json")
	if err != nil {
		t.Fatal(err)
	}

	var fsIdx ocispec.Index
	if err := json.Unmarshal(data, &fsIdx); err != nil {
		t.Fatal(err)
	}

	if len(fsIdx.Manifests) != len(origIdx.Manifests) {
		t.Fatalf("round trip: got %d manifests, want %d", len(fsIdx.Manifests), len(origIdx.Manifests))
	}

	origDigests := make(map[digest.Digest]struct{})
	for _, d := range origIdx.Manifests {
		origDigests[d.Digest] = struct{}{}
	}
	for _, d := range fsIdx.Manifests {
		if _, ok := origDigests[d.Digest]; !ok {
			t.Fatalf("round trip: unexpected digest %s", d.Digest)
		}
	}

	// Read each blob from FS and verify contents match.
	for dgst, expected := range map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2} {
		path := "blobs/" + dgst.Algorithm().String() + "/" + dgst.Encoded()
		got, err := fs.ReadFile(fsys, path)
		if err != nil {
			t.Fatalf("reading blob %s: %v", dgst, err)
		}
		if string(got) != string(expected) {
			t.Fatalf("blob %s: got %q, want %q", dgst, got, expected)
		}
	}
}

func TestFSReadAt(t *testing.T) {
	blob1 := []byte("hello, this is a test blob for ReadAt")
	dgst1 := blobDigest(blob1)

	dir := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})
	layout, err := NewLocalLayout(dir)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	fsys := NewFS(ctx, layout)

	t.Run("blob", func(t *testing.T) {
		blobPath := "blobs/" + dgst1.Algorithm().String() + "/" + dgst1.Encoded()
		file, err := fsys.Open(blobPath)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		ra, ok := file.(io.ReaderAt)
		if !ok {
			t.Fatal("blob file does not implement io.ReaderAt")
		}

		// Read at offset 0.
		buf := make([]byte, 5)
		n, err := ra.ReadAt(buf, 0)
		if err != nil {
			t.Fatalf("ReadAt(0): %v", err)
		}
		if got := string(buf[:n]); got != "hello" {
			t.Fatalf("ReadAt(0) = %q, want %q", got, "hello")
		}

		// Read at mid-blob offset.
		n, err = ra.ReadAt(buf, 7)
		if err != nil {
			t.Fatalf("ReadAt(7): %v", err)
		}
		if got := string(buf[:n]); got != "this " {
			t.Fatalf("ReadAt(7) = %q, want %q", got, "this ")
		}

		// Read at end — should get short read + EOF.
		buf = make([]byte, 10)
		n, err = ra.ReadAt(buf, int64(len(blob1))-3)
		if err != io.EOF {
			t.Fatalf("ReadAt(end): err = %v, want io.EOF", err)
		}
		if got, want := string(buf[:n]), string(blob1[len(blob1)-3:]); got != want {
			t.Fatalf("ReadAt(end) = %q, want %q", got, want)
		}

		// ReadAt should not affect sequential Read position.
		// Reopen to get a fresh file.
		file2, err := fsys.Open(blobPath)
		if err != nil {
			t.Fatal(err)
		}
		defer file2.Close()

		ra2 := file2.(io.ReaderAt)
		buf = make([]byte, 5)

		// Read sequentially first.
		n, err = file2.Read(buf)
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
		if got := string(buf[:n]); got != "hello" {
			t.Fatalf("Read = %q, want %q", got, "hello")
		}

		// ReadAt at offset 0 should not change sequential position.
		_, err = ra2.ReadAt(buf, 0)
		if err != nil {
			t.Fatalf("ReadAt(0) after Read: %v", err)
		}

		// Sequential Read should continue from where it left off.
		n, err = file2.Read(buf)
		if err != nil {
			t.Fatalf("Read after ReadAt: %v", err)
		}
		if got := string(buf[:n]); got != ", thi" {
			t.Fatalf("Read after ReadAt = %q, want %q", got, ", thi")
		}
	})

	t.Run("bytesFile", func(t *testing.T) {
		file, err := fsys.Open("oci-layout")
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()

		ra, ok := file.(io.ReaderAt)
		if !ok {
			t.Fatal("oci-layout file does not implement io.ReaderAt")
		}

		// Read the whole thing via ReadAt.
		fi, err := file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, fi.Size())
		n, err := ra.ReadAt(buf, 0)
		if err != nil && err != io.EOF {
			t.Fatalf("ReadAt: %v", err)
		}
		if int64(n) != fi.Size() {
			t.Fatalf("ReadAt: got %d bytes, want %d", n, fi.Size())
		}
	})
}

func TestFSWithJoinedLayout(t *testing.T) {
	blob1 := []byte("layout1 manifest")
	blob2 := []byte("layout2 manifest")
	dgst1 := blobDigest(blob1)
	dgst2 := blobDigest(blob2)

	dir1 := makeTestLayout(t, map[digest.Digest][]byte{dgst1: blob1})
	dir2 := makeTestLayout(t, map[digest.Digest][]byte{dgst2: blob2})

	l1, err := NewLocalLayout(dir1)
	if err != nil {
		t.Fatal(err)
	}
	l2, err := NewLocalLayout(dir2)
	if err != nil {
		t.Fatal(err)
	}

	merged := Join(l1, l2)
	ctx := context.Background()
	fsys := NewFS(ctx, merged)

	// Should have both blobs accessible.
	for dgst, expected := range map[digest.Digest][]byte{dgst1: blob1, dgst2: blob2} {
		path := "blobs/" + dgst.Algorithm().String() + "/" + dgst.Encoded()
		got, err := fs.ReadFile(fsys, path)
		if err != nil {
			t.Fatalf("reading blob %s: %v", dgst, err)
		}
		if string(got) != string(expected) {
			t.Fatalf("blob %s: got %q, want %q", dgst, got, expected)
		}
	}

	// index.json should have both manifests.
	data, err := fs.ReadFile(fsys, "index.json")
	if err != nil {
		t.Fatal(err)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(data, &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) != 2 {
		t.Fatalf("joined FS: got %d manifests, want 2", len(idx.Manifests))
	}
}
