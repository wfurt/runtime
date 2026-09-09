# Pluggable TLS implementations and `SocketsHttpHandler`

Investigation notes for [dotnet/runtime#132848][issue] — *"Make SslStream's
`NegotiatedApplicationProtocol` and all overloads of `AuthenticateAs*` virtual to allow for pluggable
TLS implementations"*.

This branch is **evidence, not a proposed change**. It exists so the reasoning is not lost if the
design discussion sits for a while. The tactical product edits here are deliberately *workarounds*;
see [Design options](#design-options) for what a durable fix looks like.

Baseline: `ea09718b076` (upstream/main, 2026-09-09).

---

## TL;DR

| Question | Answer |
|---|---|
| Can a custom `SslStream` subclass work with `HttpClient` today? | **Yes, over HTTP/1.1** — verified end to end, no product change needed. |
| Over HTTP/2? | **No.** Blocked by exactly one member: `SslStream.NegotiatedApplicationProtocol`. |
| Can that member be overridden or shadowed? | **No.** `override` is CS0506; `new` shadowing compiles but is bypassed. |
| Is anything `sealed`? | **No.** Not the class, not one member. The blocker is the *absence* of `virtual`. |
| Is adding `virtual` a breaking change? | **Yes**, per this repo's own rules, and the hazard is real (verified in IL). |
| Do the new .NET 11 `TlsContext`/`TlsSession` types help? | **Not as shipped** — they solve the mirror-image problem. **But** they are the best available foundation, because `[Experimental]` removes the compat objection. |

---

## 1. What already works

A subclass of `SslStream` that never runs the built-in handshake — reads return a canned buffer,
writes are captured — carries a complete HTTP/1.1 request/response through `HttpClient` when returned
from `SocketsHttpHandler.ConnectCallback`.

Test: `ConnectCallback_CustomTlsImplementation_Success` in
`src/libraries/System.Net.Http/tests/FunctionalTests/SocketsHttpHandlerTest.cs`.
**Passes against unmodified product code.**

```text
status=OK version=1.1
body='Hello from a custom TLS implementation!'
IsAuthenticated=False          <- the built-in TLS stack was never engaged
```

This capability is currently **undocumented and untested**. The only pre-existing derived-`SslStream`
coverage in the repo is `ConnectCallback_DerivedSslStream_OK` plus the `MySsl` helper — and `MySsl` is
an *empty* subclass that still performs a real handshake. There was no coverage at all of a subclass
that actually overrides behaviour.

## 2. What blocks HTTP/2

One line, `HttpConnectionPool.Http2.cs`:

```csharp
SslStream sslStream = (SslStream)stream;
if (sslStream.NegotiatedApplicationProtocol == SslApplicationProtocol.Http2)
```

The getter calls `ThrowIfExceptionalOrNotHandshake()`, which throws when `_connectionInfo.Protocol == 0`
— always true when the built-in handshake never ran:

```text
InvalidOperationException: This operation is only allowed using a successfully authenticated context.
```

**That property is the only gate.** Verified by forcing `_connectionInfo` via reflection so the getter
reports `h2`: the failure moved past the ALPN check into genuine protocol work — the handler wrote the
58-byte HTTP/2 preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` + SETTINGS) to the custom stream and then
failed only because that stub does not speak h2. The `sslStream.SslProtocol` read on the very next line
is `virtual` and therefore fine.

Confirmed constructively too: `ConnectCallback_CustomTlsImplementation_Http2_Success` runs **real
HTTP/2 traffic** over a pass-through custom TLS stream once the gate is handled.

### Secondary bug: the exception is not wrapped

For HTTP/2 the `InvalidOperationException` escapes `HttpClient.SendAsync` raw, rather than wrapped in
`HttpRequestException`. Worth filing separately.

## 3. Why you cannot work around it in a derived class

Three routes, all checked rather than assumed:

1. **`override`** — compile error:
   ```text
   error CS0506: cannot override inherited member SslStream.NegotiatedApplicationProtocol
   because it is not marked virtual, abstract, or override
   ```

2. **`new` shadowing** — compiles, but useless. `HttpConnectionPool` holds an `SslStream`-typed
   reference, and shadowing is resolved by static type:
   ```text
   via derived type : h2
   via SslStream ref THREW: InvalidOperationException: ...
   ```

3. **Reflection into the private `_connectionInfo`** — technically works, but it is a private
   implementation detail with per-platform layout, hostile to trimming/AOT. Not supportable.

## 4. Nothing is `sealed` — the inventory

Neither the class nor a single member carries `sealed`. `SslStream` is a plain
`public partial class SslStream : AuthenticatedStream`. The blocker is purely the absence of `virtual`.

Most of the type *is* virtual: `SslProtocol`, `NegotiatedCipherSuite`, `CipherAlgorithm`/`Strength`,
`HashAlgorithm`/`Strength`, `KeyExchangeAlgorithm`/`Strength`, `LocalCertificate`, `RemoteCertificate`,
`CheckCertRevocationStatus`, every legacy `AuthenticateAs*`/`BeginAuthenticateAs*` overload,
`ShutdownAsync`, `NegotiateClientCertificateAsync` — plus all `Stream` I/O, which is `override` and so
re-overridable.

The complete non-virtual public set:

| Member | Blocks HttpClient? |
|---|---|
| `NegotiatedApplicationProtocol` | **Yes — the entire H/2 problem** |
| `TransportContext` | Only channel binding |
| `TargetHostName` | No — HttpClient never reads it |
| `AuthenticateAsClient(SslClientAuthenticationOptions)` | No — called by the user in the callback |
| `AuthenticateAsClientAsync(SslClientAuthenticationOptions, CT)` | No |
| `AuthenticateAsServer(SslServerAuthenticationOptions)` | No |
| `AuthenticateAsServerAsync(SslServerAuthenticationOptions, CT)` | No |
| `AuthenticateAsServerAsync(ServerOptionsSelectionCallback, object?, CT)` | No |
| `Write(byte[])` | No — forwards to the virtual `Write(byte[],int,int)` |

**Two gaps in the proposal as written:**

* It omits `AuthenticateAsServerAsync(ServerOptionsSelectionCallback, object?, CancellationToken)`, the
  third non-virtual server overload — leaving the set inconsistent.
* **`GetChannelBinding` is `internal`, not merely non-virtual.** A derived class can *never* supply
  channel binding, so extended protection with Negotiate/NTLM over a custom TLS implementation stays
  broken **even if the entire proposal is accepted**. `TransportContext` still hands out an
  `SslStreamContext` that calls it. This is a strong argument for the session/interface route over the
  `virtual` route.

## 5. Adding `virtual` is a breaking change

`docs/coding-guidelines/breaking-change-rules.md:225` lists **"Adding `virtual` to a member"** under
✗ **Disallowed**. The issue's claim of *"100% compatible"* contradicts it and should be corrected.

The documented rationale is not theoretical. Disassembling two call sites against the real property:

| Call site | IL opcode | Effect after adding `virtual` |
|---|---|---|
| `s.NegotiatedApplicationProtocol` | `callvirt` (0x6F) | picks up a derived override ✅ |
| `s?.NegotiatedApplicationProtocol` | **`call` (0x28)** | **silently bypasses the override** ❌ |

So already-compiled third-party callers using null-propagation keep hitting the base implementation.
Not a compile or load failure — a *"your override silently does not take effect"* hazard.

What is **not** broken, and worth stating: no existing type can have an override today, and
`new` / `new virtual` members occupy their own vtable slot, so nothing silently changes meaning.
In-box is safe too, since System.Net.Http and System.Net.Security ship recompiled together. The risk
is narrow — but it needs an explicit API-review exception, not a claim that no break exists.

## 6. Do `TlsContext` / `TlsSession` help?

**As shipped: no.** They are the mirror image of what is needed — they let you use **.NET's built-in
TLS engine over your own transport** (`TlsBufferSession` = buffer-to-buffer, `TlsSocketSession` = raw
`SafeSocketHandle`). The issue needs **your own TLS engine over .NET's HTTP stack**. Every door is shut:

* `TlsSession` is `abstract` but its ctor is `private protected` (`TlsSession.cs:127`) — **not
  derivable** outside the assembly.
* `TlsContext` is `sealed` with an `internal` ctor; obtainable only via `CreateClient`/`CreateServer`
  from `Ssl*AuthenticationOptions`, i.e. always the in-box engine.
* Both concrete sessions (`TlsBufferSession`, `TlsSocketSession`) are `sealed`.
* `TlsSession` has **zero** virtual members.

They are also not `Stream`s, so `ConnectCallback` (returning `ValueTask<Stream>`) cannot return one.

**As design leverage: yes, substantially.**

1. **The right vocabulary already exists.** All *I/O* (`Handshake`, `Read`, `Write`, `Shutdown`,
   `DrainPendingOutput`) sits on the sealed leaves, while the abstract `TlsSession` base carries exactly
   the *negotiated-state* members — `NegotiatedApplicationProtocol`, `NegotiatedProtocol`,
   `NegotiatedCipherSuite`, `TargetHostName`, `GetRemoteCertificate()`, `GetChannelBinding()`,
   `IsHandshakeComplete`, `LocalCertificate`. That is precisely the set `HttpConnectionPool` and
   `HttpConnectionBase` read off `SslStream` — **including `GetChannelBinding`**, which `SslStream`
   cannot expose at all (§4).
2. **`[Experimental]` removes the compat objection — but only until .NET 12.** Per
   `docs/project/list-of-diagnostics.md:311`, `[Experimental]` APIs exist to be refined before becoming
   official; SYSLIB5007 is .NET 11 with removal "TBD". Widening `private protected` → `protected` and
   adding `virtual` is **free right now**. That window closes when the attribute comes off.
3. **It unifies two requests** — "my transport + your TLS" and "your transport + my TLS" — into one
   vocabulary.

## 7. Design options

The real flaw: the contract between `ConnectCallback` and the handler is *"be an `SslStream`"* — an
implementation type — rather than *"tell me these facts."*

### A. Make the members `virtual` (the filed proposal)

✗ Disallowed by repo rules (§5); still leaves channel binding broken (§4); and keeps the fragile
"derive from a heavyweight concrete class and hope you overrode all ~20 members" model. A custom engine
inherits `SslStream`'s buffers, safe handles, finalizer and platform state that it neither wants nor can
initialise.

### B. Capability interface  ⭐ recommended shape

A small interface carrying the negotiated-state set, implemented by `SslStream` *and* `TlsSession`; the
pool does `stream is ITls…` instead of `stream is SslStream`. Its presence also becomes the
"already secured" signal, replacing the `stream as SslStream` check in `HttpConnectionPool.cs`.

Three properties make this strictly better than (A):

1. **Explicitly non-breaking.** *"Adding an interface implementation to a type"* is ✓ Allowed at
   `breaking-change-rules.md:141`. No `virtual` anywhere, no behaviour change.
2. **It delivers polymorphism without `virtual`.** Interface **re-implementation** in a derived class
   overrides dispatch *even when the base member is non-virtual*. Verified:
   ```text
   via class ref     THREW: not authenticated     <- base, non-virtual
   via interface ref : h2                         <- derived re-implementation wins
   ```
   This is the argument that should settle the thread: the interface route achieves exactly what the
   proposal wants while side-stepping the ✗ Disallowed rule instead of asking for an exception to it.
3. **It drops the inheritance requirement.** A custom engine derives from `Stream`.

**Layering constraint:** the interface must live in **System.Net.Security**, not System.Net.Http.
`System.Net.Http` has a `ProjectReference` to `System.Net.Security` and not the reverse, so an interface
declared in System.Net.Http could never be implemented by `SslStream`.

**Precedent:** ASP.NET Core hit this exact problem server-side and solved it with
`ITlsHandshakeFeature`/`ITlsConnectionFeature` rather than casting to `SslStream`.

### C. `SslStream(TlsSession)` constructor

Inverts extensibility from inheritance to **composition**: instead of "derive from `SslStream` and
override ~20 members correctly," it becomes "implement a session; we adapt it to a `Stream`." This fixes
*all* the non-virtual properties at once, because `SslStream` would source its state from the session
rather than `_connectionInfo` — **no `virtual` on `SslStream` at all** — and it fixes channel binding,
since `TlsSession.GetChannelBinding` is public.

Caveat: `TlsSession` today carries in-box engine state (OpenSSL handles in `TlsSession.OpenSsl.cs`) and
all its I/O lives on the sealed leaves. Making it externally derivable means third parties inherit
machinery they cannot use. It likely needs splitting into an abstract contract vs. the in-box
implementation *before* widening `private protected` → `protected`.

(B) and (C) compose well: (C) is the extensibility point, (B) is how the HTTP layer consumes it.

### D. ✗ "Cast whatever `ConnectCallback` returns to `TlsSession`"

**Cannot work as stated.** `ConnectCallback` returns `ValueTask<Stream>`; `TlsSession` is a class that
does not derive from `Stream`. One object cannot be both, so the cast can never succeed. To work, the
returned `Stream` must *expose* a session via a property or interface — additive and allowed, but not
"without API change." This collapses into (C) + a small accessor.

## 8. Separate the two motivations

The issue conflates:

* **(a) non-extractable keys** — HSM, smart card, Key Vault;
* **(b) genuinely alternative TLS stacks** — rustls, BouncyCastle, for FIPS/compliance.

**(a) mostly does not need a pluggable TLS stack at all** — it needs the *private-key operation* to be
delegable. Windows/Schannel already supports this via CNG/KSP-backed certificates (smart cards work
today) and OpenSSL has the provider model. Solving (a) in the base product would remove most of the
demand and leave (b) as the genuinely-needs-extensibility case. Worth splitting before choosing a design.

## 9. Also found: diagnostics can fail a working request

`HttpConnectionBase.TraceConnection` reads ten `SslStream` properties that all throw for a custom
implementation. Enabling `NetEventSource` turns the *working* HTTP/1.1 scenario into a failed request:

```text
[NetEventSource tracing ENABLED]
=== request version 1.1 ===
FAILED: InvalidOperationException: This operation is only allowed using a successfully authenticated context.
```

Turning on tracing must never change whether a request succeeds. This is a bug on its own terms,
independent of the API decision, and is concrete support for the review comment that derived classes are
not considered when APIs are added.

## 10. What is on this branch

| File | Kind |
|---|---|
| `…/tests/FunctionalTests/SocketsHttpHandlerTest.cs` | **Keep** — two tests (H/1.1 passes unmodified; H/2 needs the workaround below) |
| `…/SocketsHttpHandler/ConnectHelper.cs` | Workaround — `TryGetNegotiatedApplicationProtocol` |
| `…/ConnectionPool/HttpConnectionPool.Http2.cs` | Workaround — honour the explicitly requested version when ALPN is undeterminable |
| `…/ConnectionPool/HttpConnectionPool.cs` | Workaround — safe trace (also fixes a stray `$` typo) |
| `…/SocketsHttpHandler/HttpConnectionBase.cs` | Workaround — `TraceConnection` must not throw |

The product edits are **tactical workarounds retained as evidence**, not a proposed design.

### Reproducing

```bash
./build.sh clr+libs -rc release          # baseline, ~17 min
./build.sh libs.sfx                      # after editing library source
./dotnet.sh build src/libraries/System.Net.Http/tests/FunctionalTests/System.Net.Http.Functional.Tests.csproj \
  /t:Test /p:XunitMethodName='System.Net.Http.Functional.Tests.SocketsHttpHandlerTest_ConnectCallback_Http11.ConnectCallback_CustomTlsImplementation_Success'
```

Both tests pass (`Total: 1, Errors: 0, Failed: 0` each). Note that building only the test project does
**not** pick up library source changes — `./build.sh libs.sfx` is required first.

[issue]: https://github.com/dotnet/runtime/issues/132848
