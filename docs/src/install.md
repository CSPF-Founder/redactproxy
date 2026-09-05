# Install

redactproxy is a single binary with no runtime to install and no
database server to run. It needs [Go](https://go.dev/dl/) 1.26.6 or
newer to build.

## With `go install`

```bash
go install github.com/CSPF-Founder/redactproxy/cmd/redactproxy@latest
```

## From a clone

Use this if you plan to change anything, or want the `make` targets.

```bash
git clone https://github.com/CSPF-Founder/redactproxy.git
cd redactproxy
make install        # builds into $(go env GOPATH)/bin
```

## Check your shell can find it

```bash
redactproxy version
```

If that comes back "command not found", `$GOPATH/bin` isn't on your
`PATH`. Either add it, or run `make build` instead and use
`./bin/redactproxy` everywhere `redactproxy` appears in this manual.

`redactproxy version` prints the build the binary was made from. For a
binary from `go install ...@v1.2.3` that's the module version; for one
built from a clone it prints `(devel)`. Include it in any bug report.

## For a team

`make dist` cross-compiles a stripped static binary per platform into
`dist/`:

```bash
make dist            # linux/darwin/windows, amd64/arm64
```

Those are meant to be copied straight onto a team member's machine.
They carry the version stamp from the nearest git tag, so
`redactproxy version` still answers usefully on a machine that never
had the source.

## What it needs at runtime

Nothing beyond a writable data directory, `$HOME/.redactproxy` by
default. See [Engagements and storage](./engagements.md).

Next: [Your first engagement](./quickstart.md).
