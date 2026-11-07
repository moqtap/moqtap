# moqtap-monitor

Producer monitoring for [MoQT](https://datatracker.ietf.org/doc/draft-ietf-moq-transport/)
publishers: encoders, ingest and origin services that publish to one or more
relays. Your code reports each object as it hands it to your MoQ library;
the monitor uploads the reports to moqtap Insight, which shows end-to-end
latency for the viewer sessions that received the same objects.

It works with any MoQ stack. It does not touch your connections, and object
payloads never leave the process: only names, ids, sizes and handoff times do.

## Usage

```rust,no_run
use std::time::Duration;
use moqtap_monitor::{Delivery, Monitor, Sent};

# async fn run() -> Result<(), moqtap_monitor::Error> {
let key = std::env::var("MOQTAP_SOURCE_KEY").expect("source key");
let monitor = Monitor::builder("encoder-fra-1", key).start()?;

// One handle per relay connection.
let relay = monitor.connection("https://relay.example.net/moq")?;
relay.set_draft(14).ok();

// As your MoQ library takes each object:
let sent = Sent {
    group: 42,
    delivery: Delivery::Subgroup(0),
    object: 0,
    size: 18_000,
    starts_group: true,
    opens_subgroup: true,
    ends_group: false,
};
let _ = relay.object_sent(&["live", "channel-7"], "video", sent, None);

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

- **`object_sent(namespace, track, sent, at)`**: one object, once per relay
  connection, as it is handed to your MoQ library. Each call counts as one
  publication, even when it repeats ids, so report a re-publication again
  and a library's own re-sends (per subscription, FETCH answers) not at all.
  `at` is when it was handed over (`None` means now).
  - **`object_sent_span(namespace, track, sent, start, end)`** reports an
    object whose payload you hand over in pieces, from `start` to `end`. An
    `end` before `start` is refused.
  - `delivery`: `Delivery::Subgroup(id)` with the subgroup id your library
    writes, or `Delivery::Datagram`.
  - `starts_group`: the first object your application publishes in the
    group. `opens_subgroup`: the first object of its subgroup.
    `ends_group`: the group's last object. Set them from your library's
    group and subgroup calls; ids alone never decide them.
  - A zero-length object is reported with `size: 0`.
- **`status_sent`**: a status sent in place of an object (End of Group, End
  of Track, and the others of your draft).
- **`gap_sent`**: a Prior Group ID Gap or Prior Object ID Gap you declared.
- **`stream_reset`, `request_error`, `track_request_error`, `publish_done`**:
  events, with their codes. A code past 2^53 - 1 is refused.
- **`set_draft`**: the MoQT draft the connection negotiated. With it, ids past
  2^62 - 1 are refused on drafts up to 16, and a status or gap the draft does
  not have is refused. Without it, any 64-bit id is taken.

Names are byte strings: the namespace fields and track name exactly as your
library sends them, `&str` or `&[u8]`, empty or not UTF-8. They must be what
viewers subscribe to, field for field, or no latency can be matched.

Of a relay URL, the scheme, host, port and path are kept
(`https://relay.example.net/moq`); the query, fragment and userinfo never
leave the process. Viewers' latency is matched on the same URL, path
included. A reconnect is a new `connection()`.

## Uploads and limits

Reports are sealed every 15 seconds (`MonitorBuilder::seal_interval`, 5 to
60 seconds) into one upload for all of the source's relay connections, and
sooner when an upload reaches its size limit. While someone watches a session
this source feeds, ingest can ask for shorter intervals for a while. An upload
is sealed at every interval, empty when there is nothing to report, and each
one but the last states when the next is due.

Every group of every track is reported. To report less on fast tracks, set
a target with `MonitorBuilder::sample_target(groups_per_sec)` (1 to
1,000,000): the monitor then reports a sample of whole groups per track,
still more than the target each second, and states which groups it left
out. The viewer side reports every group, and those left out are shown as
sampled.

Each reported object carries its own start, end and size.
`MonitorBuilder::timing(Timing::Group)` reports one time and one byte count per
run of objects instead, which uploads less. Ingest can also ask for that; if
either asks for group timing, the monitor uses it.

At most 256 tracks may be published at once, and 1024 over the life of one
connection.

Reporting never blocks on the network and never panics. Invalid input is
refused with `Rejected` and counted in `stats().rejected`.

## Delivery

Every sealed upload is kept until ingest accepts it, up to 16 MiB of them
(`MonitorBuilder::buffer_bytes`); past that the oldest is given up and
counted in `stats().bodies_lost`. `buffer_bytes(0)` turns the buffer off: an
upload that is not accepted at once is given up.

- Network errors, timeouts, 408, 425, 429 and 5xx are retried with the same
  upload, backing off up to a minute; `Retry-After` is honoured up to a
  minute.
- If ingest refuses the key (401 or 403) or the path (404), the monitor keeps
  collecting and keeping the data, and tries the oldest upload again every
  minute. `stats().state` is `Refused` with the status until one is accepted.
- Any other 4xx means ingest will never take that upload: it is given up and
  counted in `stats().bodies_lost`.

A retried upload is byte-for-byte the one first sent, so ingest counts it
once.

**Call `shutdown` before the process exits.** It seals the last upload and
sends everything kept, waiting at most the timeout you give it. Dropping the
`Monitor` does not wait: whatever is unsent when the runtime stops is lost.

## Clock

Times are taken from the monotonic clock and placed on ingest's clock by a
short exchange with every upload, plus one when the monitor starts. If your
application has a clock synchronised to UTC, such as PTP,
`MonitorBuilder::app_clock` hands it to the monitor too.

## Proxies and certificates

Uploads use the proxy in `HTTPS_PROXY` (or `https_proxy`) unless `NO_PROXY`
(or `no_proxy`) names the endpoint's host. They go through an HTTP `CONNECT`
tunnel, so the proxy never sees the key; credentials in the proxy URL
(`http://user:password@proxy:3128`) are sent as `Proxy-Authorization`.
`MonitorBuilder::proxy` overrides the environment: `Proxy::Direct`, or
`Proxy::Url` with an `http://` or `https://` proxy. Any other proxy URL makes
`start` fail with `Error::InvalidProxy`.

Ingest's certificate is checked by the operating system's verifier, so root
certificates installed on the machine, such as an enterprise's, are trusted.
On Linux, a host with no CA store (a slim or distroless image without
`ca-certificates`) verifies against Mozilla's root certificates instead.

## License

[Functional Source License 1.1, MIT Future License](./LICENSE) (`FSL-1.1-MIT`).
Embed it in your service, commercial or not, modify it, ship it; the one thing
it withholds is publishing a competing product built from this code. Two years
after each release, that release becomes MIT.
