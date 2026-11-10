# NTLM message MIC failure and context recovery

## Summary

When a protected NTLM message fails its Message Integrity Check (MIC), the pure-Python NTLM context
(`NTLMProxy`, including NTLM nested inside SPNEGO) rejects the bad message and **permanently retires the
receive side of that context**. Every later `verify`, `unwrap`, `unwrap_iov`, or `unwrap_winrm` call on the
same context raises `BadMICError` with a stable message until a brand new security context is negotiated.

Catching the `BadMICError` and continuing to feed messages into the same context is not supported. The only
recovery is to re-authenticate and build a new context.

## Why the context cannot be resynchronised

NTLM message protection (MS-NLMP) is built on top of RC4 and on per-message sequence numbers:

* Each direction keeps a running RC4 keystream. `wrap`/`sign` advance the **outbound** handle; `unwrap`/
  `verify` advance the **inbound** handle. The two peers only stay in sync while every message is processed
  exactly once and in order.
* `unwrap` decrypts the payload *before* the MIC is checked, and `verify` computes the expected signature
  (which itself consumes RC4 bytes when key exchange or the non-ESS MAC is used) *before* comparing it. By the
  time the mismatch is detected, the inbound handle and sequence counter have already moved.
* How far they moved depends on the length of the rejected, untrusted message. RC4 is a stream cipher with
  no way to seek backwards, and there is no length the application can trust to rewind or skip. Simply
  decrementing the sequence number does not restore the keystream position and would leave the context
  accepting misaligned data.

Because there is no safe in-place recovery, the context fails closed: it records the failure and refuses all
further receive operations rather than producing misleading "bad MIC" errors on what were actually valid
messages. This matches Windows SSPI, where `DecryptMessage`/`VerifySignature` report
`SEC_E_MESSAGE_ALTERED` for a context that has processed an altered message.

### Extended session security vs. legacy NTLM

* With `NTLMSSP_NEGOTIATE_EXTENDED_SESSION_SECURITY` (the default for NTLMv2) the two directions use
  independent RC4 handles and sequence counters. A failed inbound message retires the receive side only;
  `wrap`/`sign` on the outbound side keep working, which is useful for sending a final error/close notice.
* Without ESS (legacy NTLMv1, e.g. `LM_COMPAT_LEVEL` below 2) NTLM uses a **single shared RC4 handle and a
  single sequence counter for both directions**. There is no directional separation at all, so once the
  shared state is desynchronised neither side can protect or read further messages. Re-authentication is
  mandatory.

## Recommended handling

Treat a `BadMICError` from any per-message operation as fatal to the protected connection:

1. Stop processing inbound messages on that context; retrying will keep raising the same error.
2. If needed, use the outbound side (ESS only) to signal the failure to the peer.
3. Tear the connection down and **re-establish it from scratch** - run the NTLM (or SPNEGO) authentication
   exchange again to obtain a fresh context with new keys, sequence counters, and RC4 keystreams.

## Example

```python
import spnego
from spnego.exceptions import BadMICError

client = spnego.client("DOMAIN\\user", "password", protocol="ntlm",
                       options=spnego.NegotiateOptions.use_ntlm)
server = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
server.step(client.step(server.step(client.step())))

wrapped = client.wrap(b"hello")
try:
    server.unwrap(wrapped.data)
except BadMICError:
    # The receive side is now retired. These calls keep raising BadMICError with a
    # "context must be re-established" message instead of silently corrupting state.
    #
    # Correct recovery: discard both contexts and re-authenticate.
    client = spnego.client("DOMAIN\\user", "password", protocol="ntlm",
                           options=spnego.NegotiateOptions.use_ntlm)
    server = spnego.server(protocol="ntlm", options=spnego.NegotiateOptions.use_ntlm)
    server.step(client.step(server.step(client.step())))
```
