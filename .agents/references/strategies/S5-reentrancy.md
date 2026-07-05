# Strategy S5: Lifetime & State Violation (Re-entrancy, Error Paths, Races, State Machines)

**Target:** Object lifetime or state invariant violated by unexpected control flow —
a callback fires, an error path skips cleanup, a thread races, or API calls arrive
in an order the implementation doesn't handle.

**Review gate:** after 8 paths examined across these classes with 0 testcase leads, rotate strategy. Do not stop while a reachable state sequence still needs a probe.

## Class 1: Callback Re-entrancy

```
Function A holds raw reference to Object X
  → A calls function B (event dispatch, script execution)
    → Callback C fires
      → C destroys/releases Object X
  → A returns from B, dereferences stale pointer → lifetime issue
```

**Procedure:**
1. Find functions holding raw pointers that call re-entrant APIs
2. Trace: between pointer capture and pointer use, can any callback destroy the object?
3. Key question: is the reference RefPtr/prevent-destroy, or raw?

```bash
rg -l 'MOZ_CAN_RUN_SCRIPT' --type cpp <dir>/
rg -l 'DispatchEvent|FireEvent|RunScript|EventTarget::Dispatch' --type cpp <dir>/
rg -l '\w+\* ' --type cpp <dir>/
```

## Class 2: Error-Path Incomplete Rollback

When an error occurs mid-operation, partial work must be undone. Incomplete rollback
→ lifetime issues, or leak-to-reuse.

**Procedure:**
1. Find multi-step operations with error paths
2. For each error path: list everything allocated/registered BEFORE the error point
3. Is EACH one freed/unregistered on the error path? Are pointers nulled?

```bash
rg -l 'goto (err|fail|cleanup|done|bail)' --type cpp <dir>/
rg -l 'NS_FAILED.*return|if.*FAILED.*goto' --type cpp <dir>/
rg -n 'NS_ERROR_OUT_OF_MEMORY|OOM\b' --type cpp <dir>/ | head -30
```

## Class 3: Thread Races

Shared mutable state accessed from multiple threads without proper synchronization.

**Procedure:**
1. Find shared mutable state (fields accessed from multiple threads)
2. Is the access under a lock? Is it the RIGHT lock? Can the lock be bypassed?
3. For lock-free code: is memory ordering correct?

```bash
rg -n 'MOZ_GUARDED_BY|MOZ_REQUIRES|GUARDED_BY' --type cpp <dir>/ | head -30
rg -n 'Mutex::Lock|AutoLock|MutexAutoLock|lock_guard' --type cpp <dir>/ | head -30
rg -n 'Atomic|memory_order|Relaxed|SeqCst' --type cpp <dir>/ | head -20
```

## Class 4: State Machine Sequence Misuse (forward search)

Bugs requiring specific sequences of API calls to reach a dangerous intermediate
state. Single-threaded, order-dependent.

**LLM advantage:** fuzzers generate random sequences; an LLM can reason about
state transitions and construct targeted sequences.

**Procedure (forward — start from the API surface, look for trouble):**
1. Identify stateful objects with multiple operations (streams, media elements,
   database transactions, connections, workers, channels)
2. Map the state machine: what states exist, what transitions are valid,
   which operations assume a state but **don't verify** it?
3. Construct a sequence that puts the object in state Y while code expects X:
   - Call operations out of spec order
   - Trigger callbacks mid-transition
   - Race two operations on the same object (via microtask / promise scheduling)

```bash
rg -l 'mState = |SetState\(|ChangeState\(' --type cpp <dir>/
rg -l 'MOZ_ASSERT.*mState ==' --type cpp <dir>/
rg -l 'MOZ_CAN_RUN_SCRIPT.*void Set|Fire.*Event.*void Set' --type cpp <dir>/
```

## Class 5: Stateful Primitive Construction (backward planning)

Class 4 is forward search ("try out-of-order calls, see what breaks"). Class 5
is the inverse: **declare the primitive you want, then plan the call sequence
backwards to achieve it.**

**Why this matters:** real high-impact bugs in stateful targets (kernel ioctls,
TLS state machines, IPC handlers, database transactions, multi-message protocols)
are almost never reachable in a single API call. The Mythos kernel example chains
six sequential RPC requests because the seventh — the one that issues the
out-of-range write — depends on heap and register state set up by the first six.
Random sequence generation will not find that chain in any reasonable budget.
A model that reasons backwards from the desired primitive will.

### Step 1 — Declare the desired primitive

Pick from the catalog. Each primitive is the *capability* you want at the end of
the chain; subsequent steps work backwards to find the call sequence that yields it.

| Primitive | Shape | Why it matters |
|-----------|-------|----------------|
| **write-N-controlled-bytes-at-controlled-offset** | caller chooses both bytes and offset; bounded or unbounded N | Highest-value heap primitive |
| **write-N-controlled-bytes-at-caller-known-offset** | caller knows offset, may or may not control content | Sufficient for vtable / function-pointer overwrite |
| **write-fixed-bytes-at-controlled-offset** | content fixed by code path, offset caller-chosen | Useful for sentinel / refcount / length-field corruption |
| **read-N-bytes-at-controlled-offset** | info leak primitive; N bounded by sink | Defeats ASLR, leaks heap secrets |
| **lifetime: same heap object freed by two paths in the chain** | call sequence frees same allocation twice | Allocator metadata corruption, tcache poisoning |
| **lifetime: free then reallocate with caller-typed payload** | reused slot now holds caller-typed bytes the next deref reads | type-mismatch, vtable hijack |
| **type-mismatch at dispatch site** | producer writes tag A, consumer reads tag B | Direct control-flow bend |
| **uninitialised-read of caller-influenced bytes** | sink reads memory whose contents the chain placed there | Info leak, sometimes control |
| **refcount underflow on shared object** | drop count below zero → premature free | Lifetime corruption |
| **state-machine bypass to privileged state** | reach a state the spec gates behind authentication / capability check | Auth bypass, privilege escalation |
| **resource-exhaustion at controlled allocator** | trigger N allocations that the allocator cannot satisfy at a controlled site | Used to *shape* the heap for a follow-up primitive, not the primitive itself |

### Step 2 — Find the sink

For the chosen primitive, locate the code site that *would* perform the
dangerous operation if its preconditions were violated. Examples:

- **write-N-controlled-bytes-at-controlled-offset** → look for `memcpy(dst, src, len)`,
  `*(T*)(base + off) = val`, indexed array stores. The "sink" is the call site
  whose `dst`/`off`/`len`/`val` derive (transitively) from inputs the chain can set.
- **lifetime issue** → every `free()`, `delete`, `Release()`, custom deallocator.
  The sink is one whose pointer argument is reachable from a still-live alias
  after the free, or one that frees an object a second path already freed.
- **type-mismatch at dispatch site** → every `switch(tag)`, virtual call, function
  pointer dereference whose tag/vtable was written by code on a different path.

```bash
# Examples for write-N-controlled-bytes-at-controlled-offset:
rg -n '\bmemcpy\s*\([^,]+,[^,]+,\s*[a-zA-Z_]' --type c --type cpp <dir>/ | head -30
rg -n '\b(memmove|bcopy|copy_to_user|copyout)\s*\(' --type c --type cpp <dir>/ | head -30
rg -n '\[[a-zA-Z_][a-zA-Z0-9_]*\]\s*=\s*' --type c --type cpp <dir>/ | head -30  # indexed stores
# For lifetime issues:
rg -n '\b(free|kfree|g_free|moz_free|delete\s+)' --type c --type cpp <dir>/ | head -30
# For type-mismatch at dispatch sites:
rg -n 'switch\s*\([^)]*[Tt]ag\|[Tt]ype\|[Kk]ind' --type c --type cpp <dir>/ | head -30
```

### Step 3 — Plan backwards from the sink

For each candidate sink, build the chain in reverse:

```
SINK requires:  pointer P, length L, value V, AND state S
  ↑ what call last wrote P?           → CALL_n
  ↑ what call set length L?           → CALL_{n-1}
  ↑ what call placed value V?         → CALL_{n-2}
  ↑ what call brought target to S?    → CALL_{n-3}
  ↑ what setup is required to make CALL_{n-3} legal? → CALL_{n-4}
  ... continue until every prerequisite is reachable from an empty
      (initial) state via legitimate API calls
```

For each step, ask three things:
1. **Reachability:** is there ANY call path from the initial state that satisfies this prerequisite?
2. **Caller control:** how much of the value (bytes, offset, length, type) is caller-determined vs. fixed by the implementation?
3. **Side-effects:** does the call also mutate other state in a way that breaks an earlier prerequisite?

If every step has a reachable, caller-influenced answer and the side-effects do
not collide, the chain is real. Write the testcase with explicit comments naming
each step's role:

```js
// Step 1/6: place sentinel object S at allocator slot K so step 5's reuse hits it.
//   API:   new ResizableArrayBuffer(K)
// Step 2/6: ...
```

This commenting is part of the technique — the chain is the bug. A reviewer
can audit the chain even before the testcase runs. Because the chain is the
bug, file (or augment) its `findings/FIND-*` as soon as the chain is
source-proven and security-relevant — before running the testcase (see
"FILE FIND FIRST" in session-rules.md).

### Step 4 — Iterate when the chain breaks

Most chains break the first time. The break tells you something:
- **Step prerequisite not reachable** → either the spec forbids it (real defense)
  or the implementation has a check the spec doesn't mention (find the check, decide
  if it's a friction-class guard worth probing past, see strategies/README.md)
- **Side-effect collision** → a later call resets state an earlier call established.
  Insert a "freeze" call between them (cache, persist, snapshot) or pick a different
  sink that doesn't depend on the colliding state.
- **Caller control too narrow** → the chain reaches the sink, but the bytes/offset/
  length the caller actually controls are too constrained to be a useful primitive.
  Demote to a lower primitive (write-controlled-offset → write-known-offset) or
  abandon and pick a different sink.

### Recurring chain shapes

These shapes appear across many targets — recognise them when planning backwards:

| Shape | Pattern |
|-------|---------|
| **Setup-then-trigger** | N-1 calls prepare allocator/refcount/state; final call runs the unchecked operation against that state |
| **Two-pass with mutation between** | Pass 1 reads input to compute a size/decision; pass 2 acts on it; chain forces input mutation between the two passes (TOCTOU; cross-link to S3 fast-path) |
| **Cleanup-with-callback** | Call A registers a callback; call B begins teardown; the callback fires mid-teardown and re-enters a partially-destructed object |
| **Capability borrow + drop** | Call A grants a temporary capability/handle; call B drops the underlying resource while A's capability is still live |
| **Tag mismatch** | Call A writes a discriminator/tag with one identity; call B (different code path, same union/variant) reads it as another |
| **Async ordering** | Calls A, B, C posted to a queue; arrival order at the consumer is not the post order; consumer assumes post order |
| **Prepared statement / cache poisoning** | Call A populates a cache or prepared statement; call B evicts the source data; subsequent uses of the cache see stale or caller-aliased data |

### Worked example template (write-fault primitive on a hypothetical RPC target)

```
PRIMITIVE: write-controlled-bytes-at-controlled-offset on the kernel-mapped
           RPC reply buffer.

SINK: rpc_reply_writev(handle, iov, iovcnt) at file.c:NNN — does memcpy
      from caller iov into a fixed-size kernel buffer with no length check
      when iov->len > buffer remaining.

PREREQUISITE CHAIN (each step a public RPC call):
  Step 1: rpc_open(SLOT) → returns handle H. State: H ∈ {bound, empty}.
  Step 2: rpc_attach(H, FAKE_DESC) → State: H ∈ {bound, attached}, caller
          controls FAKE_DESC->elem_size.
  Step 3: rpc_grow(H, BIG_N) → buffer remaining=N. Skipped check at file.c:MMM
          when FAKE_DESC->kind==CACHED.
  Step 4: rpc_seek(H, OFFSET) → Sets internal cursor. caller controls OFFSET.
  Step 5: rpc_prepare_iov(H, IOV_TEMPLATE) → Stages iov with caller bytes.
          caller controls iov->base and iov->len (post-bug).
  Step 6: rpc_reply_writev(H, iov, 1) → reaches SINK; memcpy uses caller
          OFFSET+iov->len bytes from caller iov->base into the kernel buffer.

SIDE-EFFECT CHECK: Step 4 resets the seek but not iov staging from step 5; OK.
                   Step 3's grow does not invalidate H from step 1; OK.

CALLER CONTROL AT SINK: bytes=full (iov->base), offset=full (rpc_seek),
                        length=bounded by FAKE_DESC->elem_size which step 2
                        sets without a sanity check.

VERDICT: chain is plausible. Write 6-step testcase with comments mapping each
        step to its role. Run under appropriate sanitizer to confirm.
```

This is the template the agent should produce *before* writing code. The
chain is the hypothesis; the testcase is the verification.

```bash
# Search for stateful APIs (multi-call objects) by their typical shape:
rg -l 'fn (open|attach|grow|seek|prepare|finalize|commit|abort|cancel)\b' --type rust <dir>/
rg -l '(Open|Attach|Grow|Seek|Prepare|Finalize|Commit|Abort|Cancel|Init|Reset)\s*\(' --type cpp <dir>/
# Find sinks whose dst/len/offset arguments derive from caller-controlled fields:
rg -n 'memcpy\s*\([^,]+,\s*[a-zA-Z_]+->\w+,\s*[a-zA-Z_]+->\w+\)' --type c --type cpp <dir>/ | head -20
```

## Priority targets

**Class 1:** DOM mutation (dom/base/), layout reflow, editor, media state changes.
**Class 2:** Any code with multi-step init/setup, transaction/commit patterns, codec open/close.
**Class 3:** Media pipeline (decoder threads), network (socket vs main thread), WebRTC, IPC dispatch.
**Class 4:** Streams API, Media Elements, Workers, IndexedDB, WebRTC, WebSocket, WebTransport — any object with explicit open/close/abort/cancel lifecycle.
**Class 5:** Kernel syscalls / ioctls, RPC handlers (XPCOM, JSON-RPC, gRPC, kRPC), TLS state machines, SSH / IPSec key exchange, database transaction processors, multi-message protocols (HTTP/2 frames, QUIC packets, WebTransport streams), driver command queues. Any target where a single call can never reach the dangerous primitive but a chain of N calls can.
