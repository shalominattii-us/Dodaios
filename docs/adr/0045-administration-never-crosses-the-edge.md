# ADR-0045 — Administration never crosses the edge; the host moves off the desk

**Status:** Accepted · **Date:** 2026-11-05

## Context

Jarvis runs on the owner's machine and is published through a forwarding
intermediary — a Cloudflare edge worker in front of the local web surface on
port 3000. That gives remote reach, which is the point. It also put
administration on the far side of a relay: a request that arrives with a valid
session cookie is, to every route downstream, indistinguishable from the person
sitting at the machine.

`surface_security` already refuses *open local access* to a relayed request
(`_RELAY_INDICATOR_HEADERS`: `forwarded`, `x-forwarded-for`, `x-forwarded-host`,
`x-real-ip`, `via`, `cf-connecting-ip`, `true-client-ip`, `fly-client-ip`), so
the edge can never ride the loopback exemption. What it did not do is tell a
relayed request apart from the person *after* authentication. `person_at_window`
answered "yes" for any valid session cookie, so an owner-authenticated request
relayed through the edge could stand in for the person at the window on the two
decisions reserved for them (P9, P4: confirming that macOS may record a grant
for the app that started Jarvis, and an explicit click that skips the re-ask
cooldown), and could count as a person-typed prompt in the self-build loop.

The tempting fix is a script: strip or gate `/api/admin*` in the worker. That is
the wrong layer. The worker is one deployment of one relay; the invariant is
about the *host*, and a rule written in front of the host is a rule the next
relay never inherits. It also cannot be written as a list of admin paths, because
the paths change and the classification is the thing that must not drift.

## Decision

1. **The transport fact becomes first-class.** `surface_security.relay_forwarded(scope)`
   is the public question "did an intermediary stamp this request?", reading the
   same header set the transport decisions already use. One definition, one place.
2. **A relayed request is never the person at the window.** `control_auth.person_at_window`
   answers no for a relayed request *before* inspecting any credential. A session
   cookie proves who signed in; it does not prove anyone is standing at this
   machine. So: reachable remotely — yes; administrable remotely — no.
3. **Nothing else narrows.** The Control Key, the session cookie, and open local
   access keep their existing meaning everywhere else. A remote caller can do
   everything an agent can do, including *asking* for the decision. It cannot
   *be* the decision. When a privileged step needs the person, the ask surfaces at
   the machine (or the person runs it there), and the request from the edge is
   refused with `403 confirmation_requires_ui`.
4. **The durable answer is the host, not the header.** The ROG install moves to a
   cloud host that the worker fronts directly. Header-stamping then stops being
   load-bearing: there is no laptop behind a relay, administration has one
   addressable place to happen, and the local machine becomes a client rather
   than the trust root. Until that lands, this ADR's gate is the boundary, and it
   is deliberately fail-closed rather than clever.

## Consequences

- A headerless L4 relay (`ssh -L`, `socat`) is still invisible to request
  inspection and remains the documented caveat. This is the argument for (4), not
  a gap that a better header list closes.
- Remote administration narrows to: read, converse, and request. Anything that
  touches the OS, the app's own settings, or an elevation prompt waits for the
  machine. That is a product behavior change, and it is the behavior that was
  asked for.
- Nine tests pin it: the local WebView and a local session still answer yes; a
  session, a control key, and a browser-shaped local signal relayed with any of
  four edge headers all answer no; and `relay_forwarded` itself reads the same
  header set.
