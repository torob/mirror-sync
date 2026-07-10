# Transparent APT/APK Mirror Sync Tool Specification

## Overview

`mirrorsync` is a Go command-line tool for transparent mirroring of APT and
Alpine APK repositories.

`mirrorsync` is distributed as a standalone executable. Runtime behavior must
be implemented inside the Go binary and must not depend on third-party command
line tools such as `apt`, `apk`, `gpg`, `gpgv`, `curl`, `wget`, `rsync`,
`tar`, `sha256sum`, or similar helpers.
Third-party Go packages may be used as implementation dependencies, but the
final `mirrorsync` executable must be statically linked.

The mirrored repository must remain compatible with the original upstream
trust model. Clients change only repository URLs and continue to use the
original vendor keyrings. `mirrorsync` therefore preserves upstream metadata and
signatures and never rewrites or re-signs repository metadata.

## Goals

- Mirror APT and Alpine APK repositories into a local served directory.
- Treat `primary_source` as authoritative for signed metadata.
- Download package payloads from ordered `mirror_sources` when configured.
- Verify every package payload against checksums and sizes from upstream
  metadata before publishing it.
- Fall back to `primary_source` when configured mirrors are missing packages,
  return errors, or provide invalid payloads.
- Publish package files before signed metadata so clients never observe
  metadata that references unavailable package files.
- Support pruning files that are not referenced by current published metadata.
- Support HTTP and HTTPS proxies for outbound source requests.
- Reuse outbound HTTP connections when the remote endpoint permits it.
- Prefer HTTP/2 over HTTP/1.1 when the remote endpoint supports it.
- Support built-in periodic sync execution without relying on external
  schedulers.

## Non-Goals

- `mirrorsync` does not create custom repositories.
- `mirrorsync` does not filter packages, components, architectures, or APK
  repositories beyond the configured upstream metadata selection.
- `mirrorsync` does not generate, edit, or re-sign APT `Release` metadata.
- `mirrorsync` does not generate, edit, or re-sign APK `APKINDEX.tar.gz`
  metadata.
- `mirrorsync` does not provide snapshot retention in version 1.
- `mirrorsync` does not throttle bandwidth and does not provide requests-per-
  second limiting in version 1.

## Limitations

- `mirrorsync` does not provide whole-repository multi-file atomic snapshots in
  version 1. Publishing safety relies on package payloads being present before
  metadata, metadata files being replaced with atomic same-filesystem renames,
  and authoritative signed metadata being published last.
- A crash or power loss while publishing metadata may leave a temporary mix of
  old and new metadata files. Clients must continue to rely on upstream
  signature and checksum verification; a mixed metadata set may cause client
  update failures, but must not be accepted as trusted inconsistent metadata.
  A later startup sync repairs the repository by fetching and publishing fresh
  authoritative metadata.

## Implementation Organization

The Go implementation must be organized into small packages and files by
responsibility. The implementation must not place all runtime code in one large
source file.

Recommended package boundaries include:

- Command-line entrypoint and command dispatch.
- Configuration loading, normalization, and validation.
- Outbound HTTP source clients, proxy resolution, retries, in-flight request
  limits, and connection limit handling.
- APT metadata fetching, OpenPGP verification, index parsing, and package
  verification.
- APK index signature verification, APK metadata parsing, and package
  verification.
- Repository planning, sync execution, publishing, pruning, and verification.
- Built-in scheduling and graceful shutdown.

## Build and Test Workflow

The repository must provide a `Makefile` for common development and validation
tasks. Developers and CI should not need to remember long `go` command lines
for normal workflows.

Required targets:

- `make build` builds the `mirrorsync` executable.
- `make test` runs the normal automated test suite.
- `make e2e` runs the real end-to-end test workflow using `config.test.yaml`.

The built release binary should be minimized in size while preserving required
runtime behavior. At minimum, release builds should strip unnecessary symbol
and debug information and avoid embedding avoidable local path or build
metadata.

## Command Line Interface

The executable name is `mirrorsync`.

```text
mirrorsync plan   -config config.yaml
mirrorsync sync   -config config.yaml
mirrorsync verify -config config.yaml
mirrorsync prune  -config config.yaml
mirrorsync run    -config config.yaml
```

Commands:

- `plan` reports the repositories, metadata, packages, source order, expected
  downloads, and prune candidates without modifying the publish tree.
- `sync` downloads and verifies metadata, reuses existing package payloads by
  size, downloads missing or wrong-size payloads, verifies newly downloaded
  payloads, then publishes a complete mirror update.
- `verify` validates the current published mirror against local published
  metadata and repairs missing or corrupted package payloads.
- `prune` removes files that are not referenced by current metadata after
  confirming they are outside the active metadata set.
- `run` starts a long-running built-in scheduler that repeatedly performs
  complete mirror sync cycles according to `sync.schedule`.

All commands require `-config`. For one-shot commands, invalid configuration,
failed signature verification, checksum mismatch, unavailable required files,
or publish errors must return a non-zero exit status. For `run`, invalid
startup configuration and fatal scheduler errors must return a non-zero exit
status; individual sync cycle failures are reported and do not stop the
scheduler.

## Configuration

Configuration is YAML with a required `version` field and optional top-level
`logging`, `apt`, and `apk` sections.

```yaml
version: 1

logging:
  level: info

storage:
  published: /srv/mirrors
  staging: /srv/mirrors/.staging

sync:
  prune: true
  repository_retries: 2
  schedule:
    cron: "0 3 * * *"
    timezone: Asia/Tehran
  download:
    retries: 3
    max_in_flight_requests: 16
    max_connections_per_source: 4
    max_in_flight_requests_per_source: 4
    proxy:
      url: https://proxy.example.com:8443
      enabled_by_default: false

apt:
  repositories:
    - name: ubuntu
      publish_path: ubuntu
      keyring: keyrings/ubuntu-archive-keyring.gpg
      primary_source:
        url: https://archive.ubuntu.com/ubuntu
        max_connections: 2
        max_in_flight_requests: 2
        proxy:
          url: https://metadata-proxy.example.com:8443
      mirror_sources:
        - url: http://local-ubuntu-mirror.example.com/ubuntu
          max_connections: 8
          max_in_flight_requests: 8
          proxy:
            enabled: true
        - url: https://archive.ubuntu.com/ubuntu
          max_in_flight_requests: 2
          proxy:
            url: http://fallback-proxy.example.com:8080
      architectures: [amd64]
      suites:
        - name: noble
          components: [main, restricted, universe, multiverse]

apk:
  repositories:
    - name: alpine
      publish_path: alpine
      keys_dir: /etc/apk/keys
      primary_source:
        url: https://dl-cdn.alpinelinux.org/alpine
      mirror_sources:
        - url: http://local-alpine.example.com/alpine
          proxy:
            enabled: true
        - url: https://dl-cdn.alpinelinux.org/alpine
      architectures: [x86_64]
      versions:
        - name: v3.24
          repositories: [main, community]
```

### Configuration Rules

- `version` must be `1`.
- `logging.level` may be `debug`, `info`, `warn`, `error`, or `off` and
  defaults to `info` when omitted. `off` suppresses lifecycle records but not
  the final stderr diagnostic for a failed command.
- Operational logs are human-readable key/value text on standard error;
  command result output remains on standard output.
- Lifecycle logs report commands, sync cycles, repository attempts, retries,
  durations, outcomes, and aggregate payload operation counters. They identify
  network sources and proxies by host only.
- `storage.published` is the served mirror root.
- `storage.staging` is used for temporary downloads and must not be inside a
  client-visible repository path unless it is hidden from clients.
- `storage.staging` is the default location for internal sync state such as
  per-repository lock files.
- `storage.staging` and `storage.published` must be on the same filesystem so
  verified package payloads can be moved into the published tree with atomic,
  metadata-only rename operations.
- `publish_path` is relative to `storage.published`.
- `publish_path` must not be absolute and must not escape `storage.published`.
- Each configured `publish_path` is resolved against `storage.published`, cleaned,
  and converted to an absolute path during configuration validation.
- Resolved publish paths must be unique across all APT and APK repositories.
  Configuration with duplicate resolved publish paths is invalid.
- Repository `name` values must be unique within their package ecosystem.
- `primary_source.url` is the authoritative metadata source.
- APT `keyring` is required and must be a local filesystem path.
- Relative local APT keyring paths are resolved relative to the directory that
  contains the configuration file, then cleaned and converted to absolute
  paths during configuration validation.
- Local APT keyring paths must exist and be readable before APT metadata is
  fetched.
- `mirror_sources` is optional and may be omitted or configured as an empty
  list.
- Package payloads are downloaded from `mirror_sources` first, in declaration
  order, when configured.
- `primary_source` is always the final fallback source for package payloads.
  When `mirror_sources` is omitted or empty, package payloads are downloaded
  directly from `primary_source`.
- If the same URL appears in both `mirror_sources` and `primary_source`, it
  must not be tried twice for the same package payload.
- `sync.download.max_in_flight_requests`, when set, must be a positive integer
  and bounds total in-flight outbound source requests across all configured
  repositories, sources, and packages in each sync cycle started by `sync` or
  `run`.
- `sync.schedule` configures built-in periodic execution for the `run`
  command.
- `run` requires `sync.schedule` to specify exactly one schedule trigger:
  `interval` or `cron`.
- `sync.schedule.interval`, when set, must be a positive duration string with
  an explicit unit, such as `15m`, `1h`, or `24h`.
- `sync.schedule.cron`, when set, starts sync cycles at times matched by a
  crontab-style expression.
- `sync.schedule.cron` must use quoted five-field crontab syntax:
  `minute hour day-of-month month day-of-week`, such as `"0 3 * * *"`.
- `sync.schedule.cron` must support `*`, comma-separated values, ranges, and
  step values such as `*/15`, `1,15`, and `1-5`.
- In `sync.schedule.cron`, day-of-week values `0` and `7` both mean Sunday.
- When both day-of-month and day-of-week are restricted, a time matches when
  either field matches, following traditional crontab behavior.
- `sync.schedule.cron` does not include a command field and must not be
  executed by the system crontab.
- `sync.schedule.timezone` is required when `sync.schedule.cron` is set and
  must be an IANA timezone name, such as `UTC`, `Asia/Tehran`, or
  `Europe/Berlin`.
- The `sync` command runs exactly one sync cycle and does not repeat when
  `sync.schedule` is configured.
- `sync.repository_retries`, when set, must be a non-negative integer. It
  configures additional whole-repository sync attempts after a repository
  fails, so `2` permits up to three total attempts for that repository.
- `sync.download` configures outbound source downloads for one-shot and
  scheduled sync cycles.
- `sync.download.retries`, when set, must be a non-negative integer.
- `sync.download.max_connections_per_source`, when set, is the default maximum
  number of established outbound connections used for each configured source.
- Source-level `max_connections`, when set on `primary_source` or a
  `mirror_sources` entry, overrides
  `sync.download.max_connections_per_source` for that source.
- There is no global established-connection limit. Total established
  connections are constrained only by each source's effective connection
  limit, the number of configured sources, operating-system limits, and remote
  endpoint behavior.
- `sync.download.max_in_flight_requests_per_source`, when set, is the default
  maximum number of concurrent in-flight outbound requests for each configured
  source.
- Source-level `max_in_flight_requests`, when set on `primary_source` or a
  `mirror_sources` entry, overrides
  `sync.download.max_in_flight_requests_per_source` for that source.
- `sync.download.max_in_flight_requests` is the global maximum number of
  concurrent in-flight outbound source requests across all sources.
- Connection and in-flight request limit values must be positive integers.
- Package payload downloads for a single repository must be eligible to run
  concurrently when more than one package is missing or invalid. They must not
  be processed by an intentionally serial repository-local package loop when
  global and per-source in-flight request limits and source connection limits
  allow parallel work.
- A proxy may be configured globally with `sync.download.proxy`, per source
  with `primary_source.proxy` or `mirror_sources[].proxy`, or globally from
  the `MIRRORSYNC_PROXY` environment variable.
- Proxy `url` values and `MIRRORSYNC_PROXY`, when set, must use the `http` or
  `https` scheme.
- `sync.download.proxy.enabled_by_default`, when omitted, defaults to `true`.
- When `sync.download.proxy.enabled_by_default` is `true`, sources with no
  source-level proxy configuration inherit `sync.download.proxy` or
  `MIRRORSYNC_PROXY`.
- When `sync.download.proxy.enabled_by_default` is `false`, sources with no
  source-level proxy configuration use direct connections.
- Source-level `proxy.enabled: true` explicitly enables inherited proxy use
  for that source.
- Source-level `proxy.enabled: false` explicitly disables inherited proxy use
  for that source.
- A source-level proxy object must specify only one of `url` or `enabled`.
- Source-level proxy configuration takes precedence over `sync.download.proxy`.
- `sync.download.proxy` takes precedence over `MIRRORSYNC_PROXY`.
- An empty `MIRRORSYNC_PROXY` value is treated as unset.
- Sources with no source-level proxy inherit `sync.download.proxy` or
  `MIRRORSYNC_PROXY` only when proxy inheritance is enabled by default.
- Sources with no source-level proxy, no `sync.download.proxy`, and no
  `MIRRORSYNC_PROXY` use direct connections.

## Periodic Sync Semantics

`mirrorsync run` provides built-in periodic synchronization. It must not rely
on external shell loops, cron jobs, systemd timers, or other third-party
schedulers to repeat sync cycles.

Requirements:

- `run` validates configuration at startup before network access or filesystem
  mutation.
- `run` uses the configured `sync.schedule` trigger to determine when to start
  sync cycles.
- `run` starts a sync cycle immediately after successful startup validation,
  before waiting for the configured schedule. This startup sync is required to
  verify and reconcile repository state after crashes, interrupted syncs,
  stale staging files, or manual filesystem changes.
- After the startup sync cycle finishes, `run` uses the configured schedule for
  later cycles.
- For cron schedules, `mirrorsync` evaluates the configured expression in
  `sync.schedule.timezone`.
- For cron schedules, daylight-saving transitions must not create duplicate
  sync cycles for the same matched local time.
- If a cron-matched wall-clock time does not exist on a calendar date because
  of a daylight-saving transition, `mirrorsync` starts that sync cycle at the
  next valid local time after the matched time.
- Each scheduled cycle uses the same download, verification, publishing,
  pruning, proxy, in-flight request limit, and connection-reuse semantics as
  `sync`.
- Scheduled sync cycles must not overlap.
- If a scheduled start time occurs while a sync cycle is still running,
  `mirrorsync` starts the next cycle only after the current cycle completes.
- A failed scheduled cycle leaves the last successfully published mirror active
  whenever the underlying filesystem permits it.
- A failed scheduled cycle is reported with the same repository, file, source,
  and verification context required for `sync` failures.
- A failed scheduled cycle does not stop `run`; the next cycle is still
  attempted at the next scheduled time.
- On graceful shutdown, `run` stops starting new cycles and preserves the same
  publish-safety guarantees as an interrupted one-shot `sync`.

## Proxy Semantics

For each source request, `mirrorsync` resolves an effective proxy from the
source configuration, `sync.download.proxy`, and environment. When the
effective proxy is a URL, `mirrorsync` must send the request through that
proxy. When the effective proxy is direct, `mirrorsync` must connect directly
to the source. The proxy URL scheme controls whether traffic between
`mirrorsync` and the proxy is encrypted.

Requirements:

- `MIRRORSYNC_PROXY` uses the same URL format and validation rules as
  proxy `url` fields.
- Environment proxy configuration is read from the process environment at
  startup and is not written back to the configuration file.
- `plan` output identifies the effective proxy mode for each configured
  source.
- For an `https` proxy URL, the connection from `mirrorsync` to the proxy is
  established with TLS.
- For an `https` proxy URL, proxy TLS certificates are verified with the host
  trust store.
- For an `http` proxy URL, the connection from `mirrorsync` to the proxy is
  plaintext and must not be wrapped in TLS.
- For HTTPS source URLs, `mirrorsync` uses HTTP `CONNECT` through the proxy
  connection, then performs the source TLS handshake through that tunnel.
- When the proxy connection uses HTTP/2, `mirrorsync` still uses `CONNECT` for
  HTTPS source URLs before establishing the source TLS connection inside the
  tunnel.
- For HTTP source URLs, `mirrorsync` sends absolute-form HTTP requests over
  the proxy connection.
- `mirrorsync` assumes the configured proxy supports both HTTPS upstreams via
  `CONNECT` and plain HTTP upstream requests.
- Proxy configuration does not change source ordering, signature verification,
  checksum verification, or publishing semantics.
- Proxy connection, authentication, proxy TLS, or `CONNECT` failures are
  treated as source request failures and must include proxy context in error
  output.

## Network Connection Semantics

`mirrorsync` must use persistent HTTP connections for outbound source requests
when the source server or proxy permits reuse. It must prefer HTTP/2 over
HTTP/1.1 when the remote endpoint supports HTTP/2.

Requirements:

- For TLS connections that carry HTTP requests, `mirrorsync` offers HTTP/2
  before HTTP/1.1 with ALPN.
- When ALPN negotiates HTTP/2, `mirrorsync` uses HTTP/2 for requests on that
  connection.
- When HTTP/2 is unavailable, rejected by ALPN, or fails before a request can
  be sent, `mirrorsync` falls back to HTTP/1.1.
- HTTPS source requests through a proxy prefer HTTP/2 for the source
  connection inside the `CONNECT` tunnel when the source supports it.
- HTTPS proxy connections prefer HTTP/2 for the proxy connection when the
  proxy supports it.
- Multiple established source TLS connections may each negotiate HTTP/2 and
  carry concurrent download streams.
- Plain HTTP connections use HTTP/1.1 unless a peer-supported HTTP/2 cleartext
  mode is explicitly implemented.
- Each configured source has an effective connection limit from source-level
  `max_connections`, `sync.download.max_connections_per_source`, or the
  implementation default when neither is set.
- Direct source requests must not exceed the source's effective connection
  limit for established connections to the source scheme, host, and port.
- HTTPS source requests through a proxy must not exceed the source's effective
  connection limit for established `CONNECT` tunnels with source TLS
  connections to the source scheme, host, and port through the same proxy
  endpoint.
- A `CONNECT` tunnel that carries a source TLS connection counts as one
  established source connection, regardless of whether the proxy connection
  uses HTTP/1.1 or HTTP/2.
- HTTP source requests through a proxy must not exceed the source's effective
  connection limit for established proxy connections carrying requests for
  that source, because `mirrorsync` does not establish a separate connection to
  the source.
- HTTP/2 request streams on an established source connection are used for
  concurrent downloads and do not count as separate established source
  connections.
- When the source supports HTTP/2, `mirrorsync` may establish multiple source
  connections up to the effective source connection limit and use HTTP/2
  streams on each connection for downloads.
- If the effective connection limit is reached, additional requests for that
  source wait for an existing connection to become available or reusable
  instead of opening another connection.
- Direct source requests reuse idle connections for subsequent requests to the
  same scheme, host, and port.
- HTTP source requests through a proxy reuse idle connections to the same proxy
  endpoint when the proxy permits reuse.
- HTTPS source requests through a proxy reuse idle `CONNECT` tunnels for
  subsequent requests to the same source scheme, host, and port through the
  same proxy endpoint when the proxy and source permit reuse.
- `mirrorsync` must not intentionally force `Connection: close` on normal
  successful requests.
- Response bodies are closed in a way that allows connection reuse after
  successful and rejected downloads.
- Connection reuse must respect server or proxy `Connection: close` behavior,
  transport errors, TLS errors, and protocol limits.
- Connection reuse is scoped to a single command execution; `mirrorsync` does
  not persist connections across processes.

## Download Semantics

Package payload downloads must be streamed to staging storage while checksums
and sizes are computed incrementally. `mirrorsync` must not read a complete
package payload into memory before writing it to disk or before checksum
verification.

Requirements:

- During sync, before downloading a package payload, `mirrorsync` must first
  check whether the package already exists at its final published path as a
  regular file with the expected size. A matching published payload is reused
  without checksum verification and must not be downloaded again.
- If the package is missing or wrong-size at the published path, `mirrorsync`
  downloads and verifies a fresh payload before publishing it.
- During repair verification, a previously staged payload may be reused only
  after it is verified against the current local metadata.
- A verified staged payload is moved into the final published path with the
  same atomic rename semantics as a newly downloaded payload.
- A staged payload that is partial, checksum-invalid, size-invalid, or not
  referenced by the current metadata must be deleted or ignored and must not be
  published.
- `.deb` and `.apk` payload downloads are copied from the response body to a
  temporary staging file using bounded-size buffers.
- Size and checksum verification for package payloads is performed while
  streaming the response body or by streaming the staged file, not by loading
  the whole payload into memory.
- A checksum-invalid, size-invalid, incomplete, or otherwise rejected payload
  is removed from staging before the next source is attempted.
- After a package payload is fully downloaded and verified, it may be moved
  from staging into its final published path before the rest of the sync cycle
  completes.
- After repository metadata has been fetched and verified, package payload
  downloads for that repository run concurrently. The implementation must be
  able to have multiple package payload requests in flight for the same
  repository when there are multiple packages to fetch and the effective
  global in-flight request limit, per-source in-flight request limit, and
  source connection limits permit it.
- Source fallback order is preserved independently for each package. If a
  package payload fails from one configured source, the next source for that
  same package is tried in declaration order, while other package payloads may
  continue downloading concurrently.
- A failed package download does not cancel unrelated in-flight package
  downloads unless the enclosing sync context is canceled or the implementation
  needs to fail the repository sync after all sources for that package have
  been exhausted.
- Moving a verified package payload from staging to the published tree must use
  an atomic rename on the same filesystem. Cross-filesystem copy-and-delete
  moves must not be used for publishing verified payloads.
- Repository files newly written or moved into the published tree, including
  metadata and package payloads, must have mode `0644`. Published repository
  directories created or touched during publishing must have mode `0755`.
  These modes are exact and must not depend on the process umask. Existing
  payloads reused during sync are not mode-repaired by normal sync.
- Signed metadata files may be buffered in memory when their expected size is
  small enough for normal repository metadata processing. APT Packages and
  Sources indexes and the APKINDEX member must be decompressed and parsed
  incrementally; their complete decompressed contents must not be retained in
  memory. Package payload verification memory usage must remain bounded by
  buffer size and the number of concurrently streamed payloads.

## In-Flight Request Limits

In-flight request limits constrain concurrent outbound source requests. They
do not constrain request starts per second, response body throughput, or
bandwidth.

Supported fields:

- `sync.download.max_in_flight_requests`: global maximum in-flight outbound
  source requests across all configured repositories, sources, and packages in
  one sync cycle.
- `sync.download.max_in_flight_requests_per_source`: default maximum
  in-flight outbound source requests for each configured source.
- Source-level `max_in_flight_requests`: maximum in-flight outbound requests
  for one configured source, overriding the default.

An outbound source request is in flight from the point where `mirrorsync` is
ready to issue that request until the response body has been fully consumed or
the request has failed and its response body, if any, has been closed.

The effective concurrency for a source is bounded by both the global
`sync.download.max_in_flight_requests` limit and that source's effective
`max_in_flight_requests` limit. Established connection limits are applied
separately and may impose a lower practical concurrency for HTTP/1.1 sources
or for sources and proxies that do not support enough concurrent HTTP/2
streams.

## APT Keyring Semantics

APT repository signature verification uses the configured `keyring`.

Requirements:

- A local keyring path, whether configured as absolute or relative, is resolved
  to an absolute path and loaded by `mirrorsync` as trusted OpenPGP key
  material for that APT repository.
- Keyring paths must point to files that exist on the local filesystem.
- Keyring paths must not use URL schemes such as `https://` or `file://`.
- Keyring parsing and OpenPGP signature verification must happen in-process.
  `mirrorsync` must not shell out to `gpg`, `gpgv`, or other signature
  verification tools.
- If the keyring cannot be resolved, read, parsed, or used for signature
  verification, the affected APT repository sync fails before metadata
  verification.

### APT Keyring Examples

Absolute local path:

```yaml
apt:
  repositories:
    - name: ubuntu-absolute-keyring
      publish_path: ubuntu-absolute
      keyring: /etc/mirrorsync/keyrings/ubuntu-archive-keyring.gpg
```

Relative local path:

```text
/etc/mirrorsync/
  config.yaml
  keyrings/
    ubuntu-archive-keyring.gpg
```

```yaml
apt:
  repositories:
    - name: ubuntu-relative-keyring
      publish_path: ubuntu-relative
      keyring: keyrings/ubuntu-archive-keyring.gpg
```

When `-config /etc/mirrorsync/config.yaml` is used, the relative keyring path
resolves to `/etc/mirrorsync/keyrings/ubuntu-archive-keyring.gpg`.

## APT Repository Semantics

For each configured APT suite, component, and architecture, `mirrorsync` must:

- Fetch both signed metadata forms from `primary_source`: `InRelease` and the
  detached `Release` plus `Release.gpg` pair.
- Treat only HTTP 404 as an absent signed-metadata file. Timeouts, connection
  failures, other HTTP statuses, and other request errors fail the sync.
- Verify each available signed form independently in-process with the configured
  `keyring`. Publish a valid `InRelease` whenever one is available, and publish
  `Release` and `Release.gpg` only as a complete, valid pair. If either detached
  pair member returns 404, skip the entire pair.
- Ignore a malformed or signature-invalid form when the other form is valid. If
  neither signed form is valid and complete, fail without publishing new
  metadata.
- When both forms are valid and contain matching Release cleartext, preserve and
  publish all three upstream files and use `InRelease` to drive index downloads.
  When both forms are valid but differ, prefer and publish only `InRelease`.
- Parse the selected verified Release metadata.
- Download referenced `Packages.*`, Debian Installer `Packages.*`, and
  `Sources.*` indexes from `primary_source`.
- If a configured suite, component, or architecture combination has no matching
  index entry in the verified `Release` file, treat that combination as absent
  and skip it.
- Verify each index against hashes from the verified `Release` file, preferring
  the strongest supported checksum present.
- Treat `Acquire-By-Hash` as an optional Deb822 boolean whose default is `no`.
  When it is `yes`, publish each selected, locally served index at its canonical
  path and at `<index-dir>/by-hash/<algorithm>/<digest>` for every advertised
  supported checksum (`SHA512`, `SHA256`, `SHA1`, and `MD5Sum`).
- Derive by-hash paths only from verified `Release` cleartext. Do not fetch
  upstream by-hash URLs, crawl directory listings, alter upstream metadata, or
  create by-hash objects for package payloads or suite-level signed metadata.
- Publish by-hash objects as regular files or hard links whose bytes remain
  unchanged when the canonical index path is atomically replaced. Symlinks to
  mutable canonical paths are not valid by-hash objects.
- Make all current canonical indexes and by-hash objects visible before
  publishing a new `Release`, `Release.gpg`, or `InRelease`.
- Retain the current and two previous distinct by-hash objects per canonical
  index and checksum algorithm when pruning is enabled. Store the versioned,
  atomically updated retention manifest under repository staging state, never
  inside the served repository.
- When newly published signed metadata changes `Acquire-By-Hash` to `no`,
  update retention state before pruning the suite's obsolete by-hash objects.
- Parse binary package entries for `Architecture`, `Filename`, `Size`, and a
  supported checksum, and keep only configured architectures plus `all`.
- Parse source package entries from `Sources.*` and mirror the referenced
  source payload files.
- Reuse existing published APT payloads when they are regular files and their
  size matches verified package metadata.
- Download missing or wrong-size `.deb`, `.udeb`, and source payloads from
  `mirror_sources` in order when configured, then from `primary_source` as the
  final fallback.
- Accept a newly downloaded APT payload only when its size and strongest
  supported checksum match verified metadata.
- Preserve upstream files under `dists/` unchanged in the published mirror.

If a mirror source returns a missing, incomplete, or checksum-invalid payload,
`mirrorsync` must reject that payload and try the next source. The sync fails
only after all configured sources fail to provide a valid payload.

## APK Repository Semantics

For each configured Alpine version, repository, and architecture, `mirrorsync`
must:

- Fetch official `APKINDEX.tar.gz` from `primary_source`.
- Verify the embedded APK index signature in-process with keys from `keys_dir`.
- Parse package names, versions, sizes, and checksums from the verified index.
- Reuse existing published `.apk` payloads when they are regular files and
  their size matches verified APK index metadata.
- Download missing or wrong-size `.apk` payloads from `mirror_sources` in order
  when configured, then from `primary_source` as the final fallback.
- Accept a newly downloaded `.apk` only when it matches the verified APK index
  metadata.
- Preserve upstream `APKINDEX.tar.gz` unchanged in the published mirror.

If a mirror source returns a missing, incomplete, or checksum-invalid payload,
`mirrorsync` must reject that payload and try the next source. The sync fails
only after all configured sources fail to provide a valid payload.

## Repository Execution Semantics

A sync cycle may process multiple configured repositories concurrently.
Repository execution is not required to be serial unless constrained by
global in-flight request limits, per-source in-flight request limits, source
connection limits, or per-repository locks.

Requirements:

- `sync.download.max_in_flight_requests` bounds total in-flight outbound
  source requests across APT and APK repositories within a sync cycle.
- Repository coordination goroutines that are waiting for work do not count as
  in-flight source requests.
- Different configured repositories may download, verify, stage, and publish
  concurrently when in-flight request limits and source connection limits
  permit it.
- Each configured repository run is isolated from other repository runs in the
  same cycle. Repository-local failures, retries, locks, staging state, and
  publish decisions must not alter the execution state of another configured
  repository.
- A failed repository does not cancel other repositories in the same sync,
  verify, or prune cycle. The command waits for every configured repository to
  finish and reports all failed repositories.
- Whole-repository retries apply only to sync cycles. Verify and prune cycles
  report failed repositories without retrying them.
- A successful repository in a sync cycle is not rerun because another
  repository failed.
- Whole-repository retry backoff is linear: wait one second before the first
  retry, two seconds before the second retry, and so on. Parent context
  cancellation, such as interrupt or SIGTERM, cancels all in-progress
  repositories and prevents further repository retries.
- A single configured repository may download, verify, stage, and publish
  multiple package payloads concurrently when in-flight request limits and
  source connection limits permit it.
  Repository-local package payload processing must not require one package to
  finish before another package in the same repository can start.
- Package payload scheduling must be bounded. An implementation must not start
  one goroutine, thread, task, or equivalent execution unit per package when a
  repository contains many packages. It should use a bounded worker pool or an
  equivalent mechanism sized from available source request capacity, capped by
  the number of pending packages.
- For a repository with pending missing packages and available source capacity,
  simultaneous package payload requests to one source may reach the lowest of
  the global `sync.download.max_in_flight_requests` limit, the source's
  effective `max_in_flight_requests` limit, and any practical concurrency
  imposed by the source's effective connection limit and negotiated HTTP
  protocol.
- A repository sync must hold that repository's per-repository lock before
  mutating its staging or published paths.
- Repository locks must use OS-backed advisory file locking, such as `flock`
  or `fcntl` on Unix-like systems, on an opened lock file.
- The existence of a lock file on disk must not by itself be treated as an
  active lock. After a crash or power loss, a stale lock file may remain, and a
  later `mirrorsync` process must be able to acquire the OS advisory lock on
  that file when no live process holds it.
- Repository lock files must be stored outside the published repository tree.
- Repository lock files should be stored under `storage.staging/locks/` unless
  an implementation provides another non-published internal state directory.
- Lock file paths must be derived from validated repository identity and must
  not allow repository names or publish paths to escape the lock directory.
- Two sync operations for the same repository must not overlap.
- Publishing atomicity is scoped per repository; one repository may publish
  successfully while another repository in the same sync cycle fails.
- For the `sync` command, the command exits non-zero if any configured
  repository fails during the cycle.
- For the `run` command, scheduled cycles do not overlap with each other, but
  repositories inside a single scheduled cycle may run concurrently.

## Publishing Semantics

Publishing must be atomic from a client consistency perspective.

Requirements:

- Each repository sync uses a per-repository lock.
- Lock files, temporary files, journals, state files, and other internal
  coordination artifacts must not be created inside a published repository
  directory.
- Downloads are staged outside the active published tree.
- Partial downloads are never served to clients.
- During sync and prune, the only files that may be added, updated, or deleted
  under a published repository directory are upstream repository files that
  clients are expected to fetch.
- A verified package payload may be published as soon as that individual
  payload has been completely downloaded and verified.
- It is safe for clients to observe extra valid package payloads that are not
  referenced by the currently published metadata.
- Metadata is staged separately and must not be published until every package
  payload referenced by that metadata is present in the published tree with the
  expected size.
- After acquiring the repository lock, staged metadata left by previous
  interrupted sync attempts must be deleted or ignored. Each sync must fetch
  and verify authoritative metadata from `primary_source` before deciding which
  staged package payloads may be reused.
- Package payloads are published before metadata that references them.
- Signed metadata is published last.
- Metadata from failed sync attempts is not published.
- Existing published metadata remains active when a sync fails before the
  publish step.
- Pruning runs only after new metadata is visible and must keep every file
  referenced by current metadata.
- A missing APT by-hash history manifest is reconstructed from locally verified
  signed metadata. A corrupt manifest disables deletion of unknown by-hash
  objects for that cycle and is replaced atomically only after a successful
  publication.

## Verification Semantics

`verify` checks the published repository state against local published metadata.
It does not fetch upstream metadata. When referenced package payloads are
missing or invalid, it downloads replacement payloads from configured payload
sources, verifies them against local metadata, and publishes the repaired
payloads.

For APT repositories, verification must confirm:

- Published metadata signatures validate with the configured keyring.
- Published package indexes match hashes in the verified `Release` metadata.
- Every current by-hash object advertised by `Acquire-By-Hash: yes` exists as a
  regular file with the expected size and digest. Missing or corrupt current
  objects are repaired from the verified local canonical index without fetching
  new upstream Release metadata or an upstream by-hash URL.
- Referenced binary, installer, and source payload files exist, or are repaired
  from payload sources.
- Referenced APT payload files match expected size and strongest supported
  checksum after repair.

For APK repositories, verification must confirm:

- Published `APKINDEX.tar.gz` validates with the configured keys.
- Referenced package files exist, or are repaired from payload sources.
- Referenced package files match expected metadata from the verified index after
  repair.

## Failure Handling

`mirrorsync` must fail safely.

- Invalid configuration stops before network or filesystem mutation.
- Signature verification failure stops the affected repository sync.
- Checksum mismatch rejects the downloaded file.
- Stale lock files left by crashed or killed processes do not block future
  syncs when no OS advisory lock is held.
- Staged metadata left by interrupted sync attempts is not trusted on later
  runs and is deleted or ignored before new authoritative metadata is fetched
  and verified.
- A failed package download does not publish new metadata.
- A failed publish leaves the last successfully published repository usable
  whenever the underlying filesystem permits it.
- Error output must identify the repository, file path or URL, source, and
  verification step that failed.

## Acceptance Criteria

- The built `mirrorsync` executable performs mirroring, hashing, archive
  parsing, and signature verification without invoking third-party command-line
  tools.
- The final `mirrorsync` executable is statically linked, including when the
  implementation uses third-party Go packages.
- The Go implementation is split into focused files or packages by
  responsibility and does not put all runtime code in one source file.
- The repository provides `make build`, `make test`, and `make e2e` targets
  for common build, test, and real end-to-end validation workflows.
- The built release executable is minimized in size, including stripped
  unnecessary symbol and debug information.
- Package payload downloads are streamed with bounded memory usage and are not
  stored entirely in memory before being staged or verified.
- `mirrorsync run` performs periodic sync cycles using its built-in scheduler
  and does not require cron, systemd timers, shell loops, or other external
  schedulers.
- `mirrorsync run` always performs an immediate startup sync after successful
  validation to reconcile repository contents before waiting for scheduled
  cycles.
- `mirrorsync run` can start sync cycles from a configured crontab-style
  expression, such as `"0 3 * * *"` in a configured timezone.
- Scheduled sync cycles do not overlap, and a failed scheduled cycle does not
  stop later scheduled cycles.
- Multiple configured repositories may sync in parallel within one sync cycle,
  bounded by global and per-source in-flight request limits, source connection
  limits, and per-repository locks.
- Multiple package payloads within the same configured repository may download
  in parallel within one sync cycle, bounded by global and per-source
  in-flight request limits and source connection limits.
- Sync operations for the same configured repository do not overlap.
- Per-repository locking is enforced with OS advisory file locks; stale lock
  files without an active OS lock do not block subsequent syncs.
- Published repository directories contain only repository files; lock files
  and other `mirrorsync` internal artifacts are stored outside the publish
  tree.
- APT clients can run `apt update` against the mirror using the original
  `signed-by` keyring.
- Alpine clients can run `apk update` against the mirror using the original
  Alpine keys.
- APT keyring paths must refer to existing local files; URL keyrings are
  rejected.
- An APT repository can verify upstream metadata with a relative keyring path
  resolved from the configuration file directory.
- Configuration validation rejects duplicate publish paths after resolving
  them to absolute paths under `storage.published`.
- A stale or incomplete local mirror source does not corrupt the published
  mirror; valid payloads are fetched from later sources.
- When an HTTPS proxy URL is configured, traffic between `mirrorsync` and the
  proxy is encrypted for both HTTP and HTTPS source URLs.
- When an HTTP proxy URL is configured, traffic between `mirrorsync` and the
  proxy is not encrypted by the proxy connection.
- A source-level proxy URL overrides `sync.download.proxy` and
  `MIRRORSYNC_PROXY` settings for that source.
- A source-level `proxy.enabled: false` bypasses inherited
  `sync.download.proxy` and `MIRRORSYNC_PROXY` settings for that source.
- A source-level `proxy.enabled: true` explicitly activates inherited
  `sync.download.proxy` or `MIRRORSYNC_PROXY` settings for that source.
- When source-level proxy configuration and `sync.download.proxy` are unset,
  `MIRRORSYNC_PROXY` is set, and proxy inheritance is enabled by default,
  `mirrorsync` uses the proxy from the environment variable.
- HTTPS source URLs work through the configured proxy by using `CONNECT`.
- Repeated requests to the same source or proxy reuse existing connections when
  the peer permits keep-alive.
- Source connection limits prevent `mirrorsync` from opening more than the
  configured number of established connections for a source.
- HTTP/2 downloads use streams on established source connections, and
  `mirrorsync` may maintain multiple HTTP/2 source connections up to the
  configured source connection limit.
- HTTPS sources and HTTPS proxies use HTTP/2 instead of HTTP/1.1 when ALPN
  negotiation selects HTTP/2.
- Corrupt partial downloads are never accepted.
- Verified package payloads are moved from staging to the published tree with
  atomic same-filesystem renames, not cross-filesystem copy-and-delete moves.
- During sync, already published package payloads are reused after regular-file
  and size checks instead of being downloaded again.
- Metadata is not published before every referenced package file is present.
- Prune keeps all files referenced by current metadata.
- `plan` reports intended actions without changing the publish tree.
- `verify` detects and repairs missing or checksum-invalid published package
  files.
