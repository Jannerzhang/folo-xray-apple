# Hev evaluation Packet-I/O contract v1

Status: `SPECIFIED / STAGE-05`  
Scope: public-core evaluation artifact and its private Packet Tunnel caller.

This is an independently designed boundary between an Apple
`NEPacketTunnelFlow` adapter and the Hev evaluation session. It is a packet
transport contract, not a copy of an upstream tunnel implementation. The
private client consumes only this narrow contract and never receives Hev
source, a generic Xray listener, or a native tunnel descriptor.

## 1. Data model

One packet is one complete IPv4 or IPv6 packet, including its IP header.

| Field | Rule |
| --- | --- |
| `bytes` | Non-null for the duration of the call; owned by the caller for input and by the session for output until the callback returns |
| `length` | `1..65535`; the IPv4 total-length or IPv6 payload-length field must match exactly |
| `family` | Derived from the first nibble (`4` or `6`); any caller-supplied family hint must agree |
| `protocol` | Derived from the IPv4 protocol or IPv6 next-header field; it is metadata only and does not select a proxy protocol |

The session validates the packet before it enters the engine. A malformed,
truncated, over-sized, or family-mismatched packet is rejected with
`malformed_packet`; it is never silently truncated or forwarded as a partial
packet. The contract does not parse DNS, routes, subscriptions, Xray JSON, or
proxy credentials.

For the adopted stream prototype, the byte-level frame is fixed and
big-endian:

```text
offset  size  field
0       2     magic 0x4650 ("FP")
2       1     version 1
3       1     family 4 or 6
4       1     protocol / IPv6 next-header
5       1     reserved, zero
6       4     complete IP packet length
10      2     reserved, zero
12      n     complete IP packet
```

The stream reader performs exact reads for the 12-byte header and payload;
partial POSIX stream reads are not packet boundaries. The writer performs
exact writes for the complete frame and can abort through the Hev task
yielder during cancellation. The declared family, protocol, and packet
length are checked against the IP header before the packet reaches lwIP.

## 2. Narrow callback ABI

The eventual C ABI uses the following logical operations. Names are normative;
the concrete header belongs to the public core implementation in stage 08.

```text
session = create(validated_profile, callbacks, callback_context)
start(session)
write_batch(session, input_packets, input_count, input_bytes)
poll_output(session, output_packets, output_capacity, output_bytes_capacity)
cancel(session)
stop(session)
destroy(session)
```

The callback set contains only:

```text
on_output(callback_context, packet_bytes, packet_length, family, protocol)
on_wakeup(callback_context)
```

`on_output` is the only engine-to-host data path. It is invoked with a
borrowed, read-only packet view; the host copies it before returning and must
not retain the pointer. The callback must not call `write_batch`, `cancel`, or
`stop` recursively. It must be bounded and non-blocking so engine workers are
never held on an Apple packet-flow write.

`write_batch` is synchronous copy-in. The session may retain a private copy
only until the packet is consumed or explicitly discarded during cancellation.
The caller may reuse or release every input buffer immediately after the call
returns. The session never retains a pointer into `NEPacketTunnelFlow`'s
callback arrays.

`poll_output` is an optional host-polling form of the same output boundary. It
copies complete packets into caller-owned buffers and returns `would_block`
when no packet is ready. An output buffer that cannot hold the next complete
packet returns `buffer_too_small` without consuming that packet.

## 3. Batch and backpressure semantics

- A batch has `1..64` packets and its declared byte total must equal the sum of
  the packet lengths. A zero-count batch is a no-op.
- The batch is all-or-none: if any packet is invalid or the bounded ingress
  budget cannot admit the complete batch, no packet from that batch is
  accepted. The result reports `malformed_packet` or `resource_limit`.
- A successful call returns the accepted packet count and byte count. The
  caller may submit another batch only after the result is returned.
- The session exposes its measured packet-count and byte budgets through the
  stage 06 diagnostics surface. Stage 09 chooses the concrete queue budget;
  no fixed TCP connection ceiling is implied by this packet contract.
- Overload is observable (`resource_limit`) and must be handled by the caller
  as a bounded failure or retry after wakeup. Packets are never silently
  dropped to make a test pass.
- Output delivery is one complete packet per callback. The callback may be
  called repeatedly; a callback invocation is never interpreted as a batch and
  cannot carry a partial packet.

## 4. Ownership, cancellation, and lifetime

1. `create` validates the profile and callback table but does not start worker
   threads or emit packets.
2. `start` transitions `idle -> starting -> running`. No packet callback is
   made until `running` is observable to the caller.
3. `cancel` is idempotent. It marks the session `draining`, wakes all waits,
   rejects new input, and allows workers to leave their current bounded
   operation. Pending packets that cannot be delivered are counted as a
   cancellation discard; they are not hidden as successful output.
4. `stop` is idempotent and waits for workers and in-flight callbacks to
   quiesce. After it returns, no callback can start and all session-owned
   buffers have been released. `stop` must be called outside an active
   callback.
5. `destroy` is valid only after `stop` and releases the session object. A
   repeated `stop` after `destroy` is not valid because the handle no longer
   exists.

The legal state transitions are:

```text
idle -> starting -> running -> draining -> stopped
  \-> failed -----> draining -> stopped
starting ---------> failed
```

An engine I/O failure is reported once as `io_error`, transitions the session
to `failed`, and then follows the same cancellation/drain path. A stopped or
failed session never restarts; the host creates a new generation instead.

## 5. Stable status categories

The public adapter maps implementation-specific errors into this closed set:

| Category | Meaning |
| --- | --- |
| `ok` | Operation completed |
| `invalid_argument` | Null handle, inconsistent count/byte total, or invalid option |
| `invalid_state` | Operation is not legal in the current lifecycle state |
| `malformed_packet` | Packet shape, length, family, or metadata validation failed |
| `unsupported_family` | Packet is neither IPv4 nor IPv6 |
| `resource_limit` | A bounded packet-count or byte budget cannot admit the request |
| `buffer_too_small` | The next complete output packet does not fit; it remains queued |
| `would_block` | No output packet is currently available |
| `cancelled` | The operation was interrupted by cancellation |
| `closed` | The session has reached its terminal state |
| `io_error` | The controlled outbound path or engine failed |

No raw Xray, socket, errno, destination, node, credential, or packet payload
is placed in the status string or diagnostics record.

## 6. Integration prohibitions

The implementation must not use KVC, private Network Extension APIs, a private
`utun` file descriptor, process file-descriptor scanning, or an undocumented
Apple symbol. The Hev candidate's native macOS `tun_fd` entry point is not an
input to this contract. The only accepted iOS ingress/egress owner is the
public `NEPacketTunnelFlow` callback plus the explicit callback/polling ABI
above.

This contract does not claim real proxy traffic, DNS behavior, IPv6 reachability,
or device success. Those are separate, evidence-bearing gates in stages
07-23.
