# AGENTS.md

Go 1.27.1, module `github.com/projectdiscovery/nuclei/v3`. Binary entrypoint: `cmd/nuclei/main.go`. SDK entrypoint: `lib/` (`sdk.go`, `multi.go`).

## Commands

- `make build` — builds `./bin/nuclei` with `CGO_ENABLED=0`, `-trimpath`, `-pgo=auto`. Use it, don't hand-roll `go build`.
- `make vet` (= `go mod verify` + `go vet ./...`) — CI runs this in the lint job before tests. Run it before pushing.
- `make test` — `go test -race -timeout 1h -count 1 ./...`. Race detector is ~2-3x slower; CI only uses `-race` on ubuntu. Locally use `make test RACE=` for faster non-ubuntu-equivalent runs.
- Single test: `go test -v ./pkg/path/to/pkg -run TestName -count 1`.
- `make integration` — `go test -tags=integration -timeout 40m ./internal/tests/integration`. Builds a fresh `nuclei` binary in `TestMain` (`internal/tests/integration/integration_test.go`); needs network/loopback. Single case: `go test -tags=integration ./internal/tests/integration -run TestX -v`. Debug passthrough: `make integration-debug GO_TEST_ARGS="-run TestX" INTEGRATION_ARGS="..."`.
- `make functional` — requires a released `nuclei` on `PATH` plus builds `./bin/nuclei` as dev binary, then diffs them (`RELEASE_BINARY` vs `DEV_BINARY`, `-tags=functional`, 1h timeout). CI-only; don't run casually.
- `make template-validate` — requires `make build` first (it runs `./bin/nuclei -ut` and two `-validate` passes with `-et`/`-ept` exclusions).
- `go fmt ./...` before committing. No pre-commit hook; CI lint is golangci-lint + `make vet`.

## Architecture (non-obvious)

- Flow: `cmd/nuclei` (flags) → `internal/runner` (orchestration) → `pkg/core` (engine, work pools, template clustering) → `pkg/protocols/*` (http/dns/network/ssl/websocket/whois/javascript/code) → `pkg/operators` (matchers/extractors). Templates load via `pkg/catalog/loader`, compile via `pkg/templates`.
- Each protocol implements `Compile()` / `ExecuteWithResults()` / `Match()` / `Extract()` and embeds operators. Check the protocol's `request.go`, not `internal/runner`, for execution bugs.
- Templates live in a separate `nuclei-templates` repo; this repo only has test fixtures under `internal/tests/*/testdata`. `nuclei-jsonschema.json` + `SYNTAX-REFERENCE.md` are generated (`make docs` / `make syntax-docs` via `bin/docgen`); don't hand-edit.
- `pkg/js/generated/` is codegen output (bindgen/tsgen from `pkg/js/libs`). Never edit; change `pkg/js/libs/` then run `make jsupdate-all`. Memoized JS helpers need `make memogen` (`cmd/memogen`).

## Gotchas

- Integration tests are gated behind the `integration` build tag — plain `go test ./...` skips them silently. Same for `regression` (`-tags=regression ./lib/tests -run TestScaleRegression`, opt-in scale harness via `NUCLEI_SCALE_HOSTS`).
- `internal/fuzzplayground` is a deliberately vulnerable mock server; CodeQL alerts there are expected — don't "fix" them.
- Security-sensitive work: read `SECURITY_CONTEXT.md` first. Recurring traps: signature/`-code`/`DisableUnsignedTemplates` checks must hold on direct + workflow + DAST load paths; every JS lib/protocol file path must enforce `-lfa` + canonical containment; LDAP/proxy dialing must `IsHostAllowed` the actual target host. Don't reintroduce fixed bypasses.
- Windows CI is ~4x slower on integration (Defender scans the ~200MB binary per case); prefer linux for iteration.
