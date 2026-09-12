# Bug classes

A finding's `Class` field carries exactly one canonical bug-class token. The
vocabulary is the one Anthropic Red's [coordinated vulnerability disclosure
dashboard](https://red.anthropic.com/2026/cvd/) files findings under, so a
TokenFuzz class breakdown reads on the same axis as a public disclosure ledger.
The harness keeps a few classes of its own beside it where folding them into a
dashboard class would change the CVSS impact shape or lose a sanitizer-grade
distinction; each of those says why.

`lib/bug_classes.py` is the source of truth for the vocabulary. It drives four
parts of TokenFuzz:

- **Reports.** Agents and the model-direct baseline write one token in the
  `## Fields` table; the find-quality gate re-labels each accepted finding with
  the class its two reviewers establish.
- **Clusters.** Findings merge on `(family, file, line)`: every class belongs
  to one family, so `integer-overflow` and `oob-write` at the same line are one
  cluster. The class itself is the cluster's display label. See
  [Deduplication](../concepts/deduplication.md).
- **Metrics.** Benchmark class breadth counts canonical classes, so two
  spellings of one class cannot inflate it.
- **Severity.** With no sanitizer diagnostic or `Primitive` field,
  `bin/severity` scores a source-argued finding from its class at the impact
  the name establishes and no higher. Classes marked *review* have no single
  impact shape and stay `Needs review`.

This is the finding axis. Testcase headers and hypothesis rows still use the
six neutral categories (`bounds`, `lifetime`, `type`, `size`, `uninit`,
`state`); those name a sanitizer sink, not a finding class, and resolve to a
class here when a report carries one.

## Dashboard classes

| Class | Family | Severity primitive |
| --- | --- | --- |
| `heap-buffer-overflow` | memory-safety | heap read (small) |
| `stack-buffer-overflow` | memory-safety | stack read |
| `global-buffer-overflow` | memory-safety | global read |
| `buffer-overflow` | memory-safety | heap read (small) — bounds violation of unspecified region or direction |
| `oob-read` | memory-safety | heap read (small) |
| `oob-write` | memory-safety | heap write |
| `arbitrary-write` | memory-safety | wild write |
| `off-by-one` | memory-safety | heap read (small) |
| `use-after-free` | memory-safety | use-after-free read |
| `double-free` | memory-safety | double free |
| `type-confusion` | memory-safety | type confusion |
| `integer-overflow` | memory-safety | integer overflow (precursor) |
| `integer-underflow` | memory-safety | integer overflow (precursor) |
| `null-deref` | memory-safety | null dereference |
| `segv` | memory-safety | fault at an unknown address (availability) |
| `stack-overflow` | dos | stack exhaustion — ASan's `stack-overflow` is recursion, not a stack buffer |
| `denial-of-service` | dos | DoS amplification, graded by `Availability loss` |
| `uncaught-exception` | dos | DoS amplification — kept only when the exception ends the process, not the request |
| `sql-injection` | injection | SQL injection |
| `command-injection` | injection | command injection |
| `code-injection` | injection | code execution |
| `rce` | injection | code execution |
| `xss` | injection | cross-site scripting |
| `deserialization` | deserialization | insecure deserialization |
| `auth-bypass` | auth | authentication bypass |
| `broken-access-control` | auth | authorization bypass |
| `privilege-escalation` | auth | privilege escalation |
| `idor` | auth | insecure direct object reference |
| `session-fixation` | auth | authentication bypass |
| `confused-deputy` | auth | authorization bypass |
| `crypto-failure` | crypto | weak/broken cryptography |
| `improper-cert-validation` | crypto | improper certificate validation |
| `signature-bypass` | crypto | signature bypass |
| `info-disclosure` | info-disclosure | information disclosure |
| `toctou` | race | race condition (source-argued) |
| `path-traversal` | boundary | path traversal |
| `symlink-following` | boundary | path traversal |
| `arbitrary-file-write` | boundary | arbitrary file write |
| `ssrf` | boundary | server-side request forgery |
| `open-redirect` | boundary | open redirect |
| `cors-misconfig` | config | *review* |
| `logic-error` | logic | logic regression |
| `other` | other | *review* |

## Harness-native classes

| Class | Family | Severity primitive | Why it is kept |
| --- | --- | --- | --- |
| `invalid-free` | memory-safety | allocator mismatch | A source-argued free of the wrong allocator or address is an abort, not the code-execution row `double-free` scores. |
| `uninitialized-read` | memory-safety | information disclosure | MemorySanitizer's use-of-uninitialized-value lane, a distinct diagnostic from any dashboard class. |
| `data-race` | race | data race | A race-detector (ThreadSanitizer, Go `-race`) diagnostic is corruption-capable; a source-argued race is `toctou`, and severity redirects a `data-race` label without a detector diagnostic there. |
| `ssti` | injection | server-side template injection | Template injection reaches the template engine's interpreter: full-compromise impact, not a generic injection row. |
| `xxe` | injection | XML external entity | External-entity expansion reads files and reaches internal hosts; its own detector regex and impact row. |
| `csrf` | auth | cross-site request forgery | A forged request acts with the victim's authority: integrity-only impact no auth dashboard class carries. |
| `prototype-pollution` | deserialization | prototype pollution | Untrusted keys mutate shared object state; low-impact until a consumer turns it into another class. |
| `sandbox-escape` | boundary | sandbox escape | The escaped-to host is a subsequent system; `privilege-escalation` scores the vulnerable system only. |

## Aliases and legacy labels

Any other spelling resolves to a canonical class before it is clustered,
counted, or scored: sanitizer class names (`heap-use-after-free`,
`stack-buffer-underflow`), common synonyms (`uaf`, `sqli`, `privesc`,
`redos`), the six neutral categories, and the `top:sub` labels earlier quality
gates wrote (`memory-safety:lifetime` is `use-after-free`; `injection:sql` is
`sql-injection`). The top keeps the family the reviewer chose: a sub-label
refines the class only inside that family, so `memory-safety:stack-overflow`
stays memory-safety. A sub-label that names no class leaves the family alone
(`auth:bypass` clusters as `auth` and stays `Needs review`, because
authentication and authorization score differently). Anything
unrecognised is `other`; an unrecognised `*overflow*` label is
`buffer-overflow`.

Classes the dashboard folds into `other` fold there here too: request
smuggling, cache poisoning and supply-chain confusion have no impact shape of
their own. A side channel resolves to `info-disclosure`, the consequence it
establishes.
