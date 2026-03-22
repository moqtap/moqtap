# moqtap-cli

The `moqtap` command-line tool for MoQT debugging and tracing.

This crate builds the `moqtap` binary — a cross-platform CLI that uses moqtap-client and moqtap-trace to intercept, log, and inspect MoQT/QUIC/WebTransport connections from the command line.

## Install

```sh
cargo install moqtap-cli
```

Or download pre-built binaries from [GitHub Releases](https://github.com/moqtap/moqtap/releases).

## Commands

### subscribe

Connect to a MoQT server and subscribe to a track:

```sh
moqtap subscribe -s 127.0.0.1:4443 -n live/stream -t video --insecure
moqtap subscribe -s 127.0.0.1:4443 -n live/stream -t audio -f largest --trace out.moqtrace
```

Options:
- `-s, --server` — Server address (host:port)
- `-n, --namespace` — Track namespace (slash-separated)
- `-t, --track` — Track name
- `-f, --filter` — Filter type: `next-group`, `largest`, `absolute-start`, `absolute-range`
- `--priority` — Subscriber priority (0-255, default 128)
- `--insecure` — Skip TLS certificate verification
- `--trace` — Write trace to a .moqtrace file

### fetch

Connect and fetch a track range:

```sh
moqtap fetch -s 127.0.0.1:4443 -n vod/clip -t video --start-group 10 --insecure
```

### trace

Read and display a .moqtrace file:

```sh
moqtap trace session.moqtrace
moqtap trace session.moqtrace -f json
```

## License

MIT
