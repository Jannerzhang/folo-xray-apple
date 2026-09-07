# RoutePolicy v1

The Apple Go wrapper accepts a versioned, non-secret routing object that is
also emitted by the App handoff. `schemaVersion` is `1`; `revision` is the
positive profile generation. Domain rules use `domain:`, `full:`, or
`keyword:` prefixes; IP rules are single IPs or CIDRs.

Every decision is represented by the stable fields `schemaVersion`, `revision`,
`action`, `reason`, and `provenance`. The priority is:

```text
security block
> explicit proxy/direct
> DNS mapping with the active revision
> sniffed domain
> IP set
> mode/default
```

Global/direct modes only affect the default action and cannot bypass a
security block. A stale DNS attribution is ignored instead of being applied to
a newer flow.
