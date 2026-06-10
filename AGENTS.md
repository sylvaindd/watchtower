# AGENTS.md

Watchtower: a Go daemon that auto-updates running Docker containers by polling registries for new images and recreating containers with their original config. Single binary, `main.go` -> `cmd.Execute()` (cobra).

> Upstream `containrrr/watchtower` is archived/unmaintained (see README banner). This is a fork.

## Build / Test / Lint

Go 1.20 (pinned in `go.mod` and CI). Run from repo root:

```bash
go build                                              # bare build
./build.sh                                            # build with version stamped from `git describe --tags`
go test ./... -v                                      # all tests
go test ./pkg/container/ -v                           # single package
go test -v -coverprofile coverage.out -covermode atomic ./...   # exact CI test command
staticcheck ./...                                     # CI lint (staticcheck 2023.1.6); this is the ONLY linter gate
```

CI (`.github/workflows/pull-request.yml`) runs three independent jobs: **lint** (staticcheck), **test** (matrix: ubuntu/macos/windows), **build** (goreleaser snapshot). There is no `make`, no formatter gate beyond `gofmt` defaults, and no required command ordering.

Version is injected via ldflag `-X github.com/containrrr/watchtower/internal/meta.Version=...`; a plain `go build` leaves it unset — use `./build.sh` or goreleaser when version matters.

## Layout

- `cmd/` — cobra root command + `Run`/`PreRun` wiring; the main update loop lives in `cmd/root.go`.
- `internal/actions/` — core update orchestration (`Update`, `CheckForSanity`); the real "what happens each cycle" logic.
- `internal/flags/` — ALL CLI flags + env-var binding (viper). Add new options here.
- `internal/meta/` — version var (ldflag target).
- `pkg/container/` — Docker client wrapper; `Client` interface is the seam mocked in tests.
- `pkg/registry/` — manifest/digest/auth logic for "is there a newer image?" (`auth`, `digest`, `manifest`, `helpers` subpkgs).
- `pkg/notifications/`, `pkg/api/` (`metrics`, `update` HTTP endpoints), `pkg/lifecycle/`, `pkg/session/`, `pkg/sorter/`, `pkg/filters/`, `pkg/metrics/`, `pkg/types/` (shared interfaces: `Notifier`, `Container`, `Filter`).

## Conventions

- **Container labels** drive behavior, namespaced `com.centurylinklabs.watchtower.*` (e.g. `.enable`, `.monitor-only`, `.depends-on`, `.lifecycle.pre-update`, `.scope`). Grep these when touching selection/lifecycle logic. The image label `com.centurylinklabs.watchtower=true` marks the watchtower container itself.
- **Testing is mixed**: Ginkgo/Gomega BDD suites (`*_suite_test.go` + `Describe`/`It` in `internal/actions`, `pkg/container`, `pkg/notifications`, `pkg/registry`) coexist with plain testify table tests elsewhere. Match the style already in the package you edit. `go test` runs both transparently.
- Mock Docker via the `container.Client` interface — do not call the real Docker daemon in unit tests.
- `.editorconfig`: Go files use tabs (size 4); LF endings; final newline required. CSS uses 2-space indent.

## Operational notes

- `docker-compose.yml` is a local demo stack (watchtower + prometheus + grafana + parent/child nginx) built from `dockerfiles/Dockerfile.dev-self-contained`; `command:` shows representative flags. Use it to exercise behavior end-to-end.
- Self-contained build images live in `dockerfiles/` (`Dockerfile.dev-self-contained` = local source, `Dockerfile.self-contained` = pulls from GitHub). The release `Dockerfile` is `FROM scratch` and copies a prebuilt `watchtower` binary — it does NOT compile Go.
- Integration scripts in `scripts/` need a running Docker daemon and build throwaway images (e.g. `lifecycle-tests.sh` spins up node containers and asserts on HTTP responses) — slow, not part of unit `go test`.
- Releases: `goreleaser.yml` (linux/windows × amd64/386/arm/arm64) pushes multi-arch images to Docker Hub + ghcr. Docs are MkDocs (`mkdocs.yml`, `docs/`) published separately.
