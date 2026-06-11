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
- `mirrorsync` does not throttle bandwidth; rate limits apply only to request
  starts.

## Implementation Organization

The Go implementation must be organized into small packages and files by
responsibility. The implementation must not place all runtime code in one large
source file.

Recommended package boundaries include:

- Command-line entrypoint and command dispatch.
- Configuration loading, normalization, and validation.
- Outbound HTTP source clients, proxy resolution, rate limiting, retries, and
  connection limit handling.
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
- `sync` downloads and verifies metadata and package payloads, then publishes a
  complete mirror update.
- `verify` validates the current published mirror against upstream metadata and
  package checksums without publishing changes.
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
`apt` and `apk` sections.

```yaml
version: 1

storage:
  root: /srv/mirrors
  staging: /srv/mirrors/.staging

sync:
  concurrency: 16
  prune: true
  schedule:
    cron: "0 3 * * *"
    timezone: Asia/Tehran
    run_on_start: true
  download:
    retries: 3
    max_connections_per_source: 4
    proxy:
      url: https://proxy.example.com:8443
    rate_limit:
      requests_per_second: 50
      requests_per_second_per_host: 10
      burst: 20

apt:
  repositories:
    - name: ubuntu
      publish_path: ubuntu
      keyring: keyrings/ubuntu-archive-keyring.gpg
      rate_limit:
        requests_per_second: 30
        burst: 50
      primary_source:
        url: https://archive.ubuntu.com/ubuntu
        max_connections: 2
        proxy:
          url: https://metadata-proxy.example.com:8443
        rate_limit:
          requests_per_second: 5
          burst: 10
      mirror_sources:
        - url: http://local-ubuntu-mirror.example.com/ubuntu
          max_connections: 8
          proxy:
            mode: direct
          rate_limit:
            requests_per_second: 20
            burst: 40
        - url: https://archive.ubuntu.com/ubuntu
          proxy:
            url: http://fallback-proxy.example.com:8080
          rate_limit:
            requests_per_second: 5
            burst: 10
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
            mode: direct
        - url: https://dl-cdn.alpinelinux.org/alpine
      architectures: [x86_64]
      versions:
        - name: v3.24
          repositories: [main, community]
```

### Configuration Rules

- `version` must be `1`.
- `storage.root` is the served mirror root.
- `storage.staging` is used for temporary downloads and must not be inside a
  client-visible repository path unless it is hidden from clients.
- `storage.staging` is the default location for internal sync state such as
  per-repository lock files.
- `storage.staging` and `storage.root` must be on the same filesystem so
  verified package payloads can be moved into the published tree with atomic,
  metadata-only rename operations.
- `publish_path` is relative to `storage.root`.
- `publish_path` must not be absolute and must not escape `storage.root`.
- Each configured `publish_path` is resolved against `storage.root`, cleaned,
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
- `mirror_sources` are attempted in declaration order for package payloads when
  configured.
- When `mirror_sources` is omitted or empty, package payloads are downloaded
  from `primary_source`.
- The same URL used in `primary_source.url` may also appear in
  `mirror_sources` to provide an explicit fallback position in the source
  order.
- Source-level rate limits override repository-level limits.
- Repository-level rate limits override global download limits from
  `sync.download.rate_limit`.
- Missing optional rate-limit fields inherit from the next broader scope.
- `sync.concurrency`, when set, must be a positive integer and bounds total
  concurrent sync work across all configured repositories in each sync cycle,
  including cycles started by `sync` and `run`.
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
- `sync.schedule.run_on_start`, when unset, defaults to `true`.
- The `sync` command runs exactly one sync cycle and does not repeat when
  `sync.schedule` is configured.
- `sync.download` configures outbound source downloads for one-shot and
  scheduled sync cycles.
- `sync.download.retries`, when set, must be a non-negative integer.
- `sync.download.max_connections_per_source`, when set, is the default maximum
  number of established outbound connections used for each configured source.
- Source-level `max_connections`, when set on `primary_source` or a
  `mirror_sources` entry, overrides
  `sync.download.max_connections_per_source` for that source.
- Connection limit values must be positive integers.
- A proxy may be configured globally with `sync.download.proxy`, per source
  with `primary_source.proxy` or `mirror_sources[].proxy`, or globally from
  the `MIRRORSYNC_PROXY` environment variable.
- Proxy `url` values and `MIRRORSYNC_PROXY`, when set, must use the `http` or
  `https` scheme.
- A proxy object must specify exactly one of `url` or `mode: direct`.
- `mode: direct` disables proxy use for that scope.
- Source-level proxy configuration takes precedence over `sync.download.proxy`.
- `sync.download.proxy` takes precedence over `MIRRORSYNC_PROXY`.
- An empty `MIRRORSYNC_PROXY` value is treated as unset.
- Sources with no source-level proxy inherit `sync.download.proxy` when it is
  set.
- Sources with no source-level proxy and no `sync.download.proxy` inherit
  `MIRRORSYNC_PROXY` when it is set.
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
- When `sync.schedule.run_on_start` is `true`, `run` starts the first sync
  cycle immediately after successful startup validation, then uses the
  configured schedule for later cycles.
- When `sync.schedule.run_on_start` is `false`, `run` waits one full interval
  before starting the first interval-based sync cycle, or waits until the next
  time matching the cron expression before starting the first cron-based sync
  cycle.
- For cron schedules, `mirrorsync` evaluates the configured expression in
  `sync.schedule.timezone`.
- For cron schedules, daylight-saving transitions must not create duplicate
  sync cycles for the same matched local time.
- If a cron-matched wall-clock time does not exist on a calendar date because
  of a daylight-saving transition, `mirrorsync` starts that sync cycle at the
  next valid local time after the matched time.
- Each scheduled cycle uses the same download, verification, publishing,
  pruning, proxy, rate-limit, and connection-reuse semantics as `sync`.
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
- Rate limits apply to request starts and are independent of whether a reused
  or newly opened connection carries the request.

## Download Semantics

Package payload downloads must be streamed to staging storage while checksums
and sizes are computed incrementally. `mirrorsync` must not read a complete
package payload into memory before writing it to disk or before checksum
verification.

Requirements:

- Before downloading a package payload, `mirrorsync` must first check whether
  the package already exists at its final published path and matches the
  expected size and checksum from current verified metadata. A matching
  published payload is reused and must not be downloaded again.
- If the package is missing from the published path, `mirrorsync` may check for
  a previously staged payload for the same repository and relative package
  path. A staged payload may be reused only after it is verified against the
  current metadata.
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
- Moving a verified package payload from staging to the published tree must use
  an atomic rename on the same filesystem. Cross-filesystem copy-and-delete
  moves must not be used for publishing verified payloads.
- Metadata files and package indexes may be buffered in memory when their
  expected size is small enough for normal repository metadata processing, but
  package payload memory usage must remain bounded by buffer size and
  concurrency.

## Rate Limiting

Rate limits constrain request starts, not response body throughput.

Supported fields:

- `requests_per_second`: maximum request starts per second for the scope.
- `requests_per_second_per_host`: maximum request starts per second for each
  host in the scope.
- `burst`: maximum burst size for the scope.

If no rate limit is configured, `mirrorsync` may issue requests up to the
effective repository concurrency limit and applicable source connection limits.

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

- Fetch `InRelease` from `primary_source` when available.
- Fall back to `Release` plus `Release.gpg` when `InRelease` is unavailable.
- Verify upstream OpenPGP signatures in-process with the configured `keyring`.
- Parse the verified `Release` metadata.
- Download referenced `Packages.*` indexes from `primary_source`.
- Verify each package index against hashes from the verified `Release` file.
- Parse package entries for at least `Filename`, `Size`, and `SHA256`.
- Download `.deb` payloads from `mirror_sources` in order when configured,
  otherwise from `primary_source`.
- Accept a `.deb` only when its size and SHA256 match the verified package
  metadata.
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
- Download `.apk` payloads from `mirror_sources` in order when configured,
  otherwise from `primary_source`.
- Accept an `.apk` only when it matches the verified APK index metadata.
- Preserve upstream `APKINDEX.tar.gz` unchanged in the published mirror.

If a mirror source returns a missing, incomplete, or checksum-invalid payload,
`mirrorsync` must reject that payload and try the next source. The sync fails
only after all configured sources fail to provide a valid payload.

## Repository Execution Semantics

A sync cycle may process multiple configured repositories concurrently.
Repository execution is not required to be serial unless constrained by
the effective repository concurrency limit, source connection limits, rate
limits, or per-repository locks.

Requirements:

- The effective repository concurrency limit bounds total concurrent sync work
  across APT and APK repositories within a sync cycle.
- The effective repository concurrency limit is `sync.concurrency` when
  configured, otherwise the implementation default.
- Different configured repositories may download, verify, stage, and publish
  concurrently when concurrency limits permit it.
- A repository sync must hold that repository's per-repository lock before
  mutating its staging or published paths.
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
  payload referenced by that metadata is present and verified in the published
  tree.
- Package payloads are published before metadata that references them.
- Signed metadata is published last.
- Metadata from failed sync attempts is not published.
- Existing published metadata remains active when a sync fails before the
  publish step.
- Pruning runs only after new metadata is visible and must keep every file
  referenced by current metadata.

## Verification Semantics

`verify` checks the published repository state without modifying it.

For APT repositories, verification must confirm:

- Published metadata signatures validate with the configured keyring.
- Published package indexes match hashes in the verified `Release` metadata.
- Referenced package files exist.
- Referenced package files match expected size and SHA256.

For APK repositories, verification must confirm:

- Published `APKINDEX.tar.gz` validates with the configured keys.
- Referenced package files exist.
- Referenced package files match expected metadata from the verified index.

## Failure Handling

`mirrorsync` must fail safely.

- Invalid configuration stops before network or filesystem mutation.
- Signature verification failure stops the affected repository sync.
- Checksum mismatch rejects the downloaded file.
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
- `mirrorsync run` can start sync cycles from a configured crontab-style
  expression, such as `"0 3 * * *"` in a configured timezone.
- Scheduled sync cycles do not overlap, and a failed scheduled cycle does not
  stop later scheduled cycles.
- Multiple configured repositories may sync in parallel within one sync cycle,
  bounded by the effective repository concurrency limit and source limits.
- Sync operations for the same configured repository do not overlap.
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
  them to absolute paths under `storage.root`.
- A stale or incomplete local mirror source does not corrupt the published
  mirror; valid payloads are fetched from later sources.
- When an HTTPS proxy URL is configured, traffic between `mirrorsync` and the
  proxy is encrypted for both HTTP and HTTPS source URLs.
- When an HTTP proxy URL is configured, traffic between `mirrorsync` and the
  proxy is not encrypted by the proxy connection.
- A source-level proxy URL overrides `sync.download.proxy` and
  `MIRRORSYNC_PROXY` settings for that source.
- A source-level `mode: direct` bypasses inherited `sync.download.proxy` and
  `MIRRORSYNC_PROXY` settings for that source.
- When source-level proxy configuration and `sync.download.proxy` are unset
  and `MIRRORSYNC_PROXY` is set, `mirrorsync` uses the proxy from the
  environment variable.
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
- Already published package payloads and valid staged payloads are reused after
  checksum and size verification instead of being downloaded again.
- Metadata is not published before every referenced package file is present.
- Prune keeps all files referenced by current metadata.
- `plan` reports intended actions without changing the publish tree.
- `verify` detects missing or checksum-invalid published package files.
