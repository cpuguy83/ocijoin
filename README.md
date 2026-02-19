# oci-join

Composable primitives for reading, merging, filtering, and exporting OCI image layouts in Go.

## Overview

`ocijoin` operates on a simple `Layout` interface that pairs an OCI index with containerd's `content.Provider` for blob access:

```go
type Layout interface {
    content.Provider
    Index(ctx context.Context) (*ocispec.Index, error)
}
```

Because `Layout` embeds `content.Provider`, every layout is directly usable with containerd's push/pull infrastructure.

## Primitives

| Function | Description |
|----------|-------------|
| `NewLocalLayout(path)` | Read an OCI layout directory from disk |
| `Join(layouts...)` | Merge multiple layouts into a single deduplicated view |
| `Filter(layout, fn)` | Keep only index descriptors matching a predicate |
| `Unwrap(layout)` | Resolve a nested index (outer index → inner index) |
| `Wrap(layout, annotations)` | Nest a layout's index inside a new outer index |
| `IsIndex(desc)` | Predicate: is this an image index / manifest list? |
| `IsAttestation(desc)` | Predicate: is this a Docker attestation manifest? |

### Export sub-packages

| Package | Description |
|---------|-------------|
| `direxport` | Write a layout as an OCI image layout directory |
| `tarexport` | Write a layout as an OCI image layout tar archive |

## Usage

A typical multiplatform merge — combining per-platform layouts produced by
`docker buildx` into a single layout suitable for `oras cp`:

```go
layouts := make([]ocijoin.Layout, len(paths))
for i, p := range paths {
    l, _ := ocijoin.NewLocalLayout(p)
    layouts[i] = ocijoin.Unwrap(l) // resolve nested outer→inner index
}

merged := ocijoin.Join(layouts...)
wrapped := ocijoin.Wrap(merged, map[string]string{
    "org.opencontainers.image.ref.name": tag,
})

// Write to disk for oras or other tools.
direxport.Export(ctx, wrapped, outputDir)

// Or write as a tar archive.
tarexport.Export(ctx, wrapped, w)
```

### Why Unwrap/Wrap?

Many build tools (Docker buildx, BuildKit) produce OCI layouts with a nested
index structure: the top-level `index.json` contains a single descriptor
pointing to an inner `ImageIndex` blob, which in turn lists the actual platform
manifests and attestation manifests.

`Unwrap` resolves this nesting so you can work with the platform manifests
directly. After merging, `Wrap` re-creates the nested structure with the
annotations that tools like `oras` expect (e.g. `org.opencontainers.image.ref.name`
for tag resolution).

If a layout is not nested, `Unwrap` returns it unchanged.

### Filtering

```go
// Remove attestation manifests.
clean := ocijoin.Filter(layout, func(desc ocispec.Descriptor) bool {
    return !ocijoin.IsAttestation(desc)
})
```

Filtering only affects the index — all blobs remain accessible through the
filtered layout's `ReaderAt`.
