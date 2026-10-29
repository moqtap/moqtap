# moqtap-monitor

Producer monitoring for [MoQT](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/)
publishers: encoders, ingest and origin services that publish to one or more
relays. Your code reports each object after your MoQ library has accepted it;
the monitor uploads the reports to moqtap Insight, which shows end-to-end
latency for the viewer sessions that received the same objects.

It works with any MoQ stack. It does not touch your connections, and object
payloads never leave the process: only names, ids, sizes and send times do.

## Usage

```rust,no_run
use std::time::Duration;
use moqtap_monitor::Monitor;

# async fn run() -> Result<(), moqtap_monitor::Error> {
let key = std::env::var("MOQTAP_SOURCE_KEY").expect("source key");
let monitor = Monitor::builder("encoder-fra-1", key).start()?;

// One handle per relay connection.
let relay = monitor.connection("https://relay.example.net/moq")?;

// After your MoQ library accepted object 0 of group 42:
let _ = relay.object_sent(&["live", "channel-7"], "video", 42, 0, 18_000, None);

// When publishing ends, and when the connection closes:
let _ = relay.publish_done(&["live", "channel-7"], "video", 0);
let _ = relay.close(None);

// Before the process exits: seal and send what is left.
monitor.shutdown(Duration::from_secs(5)).await;
# Ok(())
# }
```

`Monitor::builder` takes the source's slug and its secret key (`mqt_sk_…`),
both from the portal. Keep the key on the server: it is sent only in the
`Authorization` header and is never logged. A browser key (`mqt_pk_…`) is
refused.

The monitor runs on Tokio; `start()` spawns its tasks on the current runtime.

## What is reported

- **`object_sent(namespace, track, group, object, size, at)`**: one object,
  after your library accepted it. `size` is the payload in bytes; `at` is when
  it was handed over (`None` means now).
- **`stream_reset`, `request_error`, `track_request_error`, `publish_done`**:
  optional events, with their codes. A code past 2^53 - 1 is refused.
- **`set_draft`**: the MoQT draft the connection negotiated, when you know it.

Only the origin of a relay URL is kept (`https://relay.example.net`); the
path, query and userinfo never leave the process.

By default each group is reported once, with its first object, send time,
duration, object count and bytes (`Detail::Group`). An object of a group
already reported, or of a group 64 or more below its track's newest, is not
reported; it is counted in `stats().dropped`. `Detail::Object` also
reports every object, on plans that include per-object detail.

## Uploads and limits

Reports are uploaded every 60 seconds, in one upload for all of the source's
relay connections, and sooner when an upload reaches its size limit.

On a fast track the monitor reports only groups whose id is a multiple of
2^k, with k chosen from the track's group rate so that it still reports more
than `moqtap_monitor::TARGET_GROUPS_PER_SEC` groups a second.

A source reports at most 64 relay origins in a calendar month (UTC;
`moqtap_monitor::MAX_RELAYS_PER_MONTH`). Reports for a further origin are not
sent and are counted in `stats().over_relay_cap`; they are sent again from the
next month.

Reporting never blocks on the network and never panics. Invalid input is
refused with `Rejected` and counted; memory is bounded, and when ingest is
unreachable uploads are retried with backoff, up to a bounded backlog. If
ingest refuses the key (401 or 403) or the path (404), the monitor stops and
`stats().state` says why.

## License

[Functional Source License 1.1, MIT Future License](./LICENSE) (`FSL-1.1-MIT`).
Embed it in your service, commercial or not, modify it, ship it; the one thing
it withholds is publishing a competing product built from this code. Two years
after each release, that release becomes MIT.
