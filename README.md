# mirror-sync

`mirrorsync` is a Go command-line tool for transparent mirroring of APT and
Alpine APK repositories. It preserves upstream metadata and signatures, verifies
package payloads against upstream checksums, and publishes package files before
signed metadata so clients do not observe metadata that references missing
packages.

## Usage

```bash
mirrorsync plan   -config config.yaml
mirrorsync sync   -config config.yaml
mirrorsync verify -config config.yaml
mirrorsync prune  -config config.yaml
mirrorsync run    -config config.yaml
```

See `spec.md` and `config.test.yaml` for the supported configuration format.

## Build

```bash
make build
make test
```

The project uses Go 1.26.4. The release binary is built statically with
`CGO_ENABLED=0`.

## Docker

```bash
docker run --rm \
  -v "$PWD/config.yaml:/config.yaml:ro" \
  -v "$PWD/mirrors:/srv/mirrors" \
  ghcr.io/torob/mirror-sync:latest \
  sync -config /config.yaml
```

Published images are available at `ghcr.io/torob/mirror-sync`.

## Release

Releases are created from `v*` tags. The release workflow builds Linux
`amd64` and `arm64` archives, publishes checksums, and pushes a multi-arch
image to GitHub Container Registry.
