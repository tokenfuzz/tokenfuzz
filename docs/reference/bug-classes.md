# Bug classes

A finding's `Class` field carries exactly one canonical bug-class token, such
as `heap-buffer-overflow`, `auth-bypass`, or `ssrf`. Use this page to pick
the token when you write or review a finding, and to read a class breakdown,
a cluster label, or a class-derived severity.

The vocabulary is the one Anthropic Red's [coordinated vulnerability
disclosure dashboard](https://red.anthropic.com/2026/cvd/) files findings
under, so a TokenFuzz class breakdown reads on the same axis as a public
disclosure ledger. TokenFuzz adds a few [harness-native
classes](#harness-native-classes) where folding them into a dashboard class
would change the CVSS impact or lose a sanitizer-grade distinction.

`lib/bug_classes.py` is the source of truth; `tests/test_bug_classes.py`
checks that this page, `bin/severity`, and the prompts that ask for a class
cover every class it defines.

## Where the class is used

- **Reports.** Agents and the model-direct baseline write one token in the
  `Class` row of the report's `## Fields` table; their prompts list the
  whole vocabulary. When a finding is accepted, the find-quality gate
  records the class its review established (`class` in the finding's
  `.llm-find-quality.json`).
- **Clusters.** Every class belongs to one *family* (`memory-safety`,
  `auth`, `injection`, …), and findings merge on `(family, file, line)`. So
  `integer-overflow` and `oob-write` at the same line form one cluster, and
  the class is only its display label. Clustering uses the gate's class for
  an accepted finding and the report's own `Class` otherwise; see
  [Deduplication](../concepts/deduplication.md).
- **Metrics.** Benchmark class breadth counts distinct canonical classes, so
  two spellings of one class cannot inflate it.
- **Severity.** `bin/severity` uses the class only as a fallback. A
  sanitizer diagnostic wins, then the report's `Primitive` or `Class` field,
  then a memory-safety or availability primitive read from the report text.
  Only when those leave the finding unclassified, or classified from prose
  keywords alone, does it use the class the find-quality gate accepted (two
  or more accepting reviews), scored at the impact its name establishes and
  no higher. Classes marked *review* stay `Needs review`.

Testcase `CATEGORY:` headers and hypothesis rows use a different, smaller
vocabulary: `bounds`, `lifetime`, `type`, `size`, `uninit`, and `state`.
Those name a sanitizer sink, not a finding class; see [Aliases and legacy
labels](#aliases-and-legacy-labels) for how each resolves in a report.

## Reading the severity column

The *Severity primitive* column names the row of `bin/severity`'s
`CVSS4_CLASS` table the class maps to, which is also the `primitive_key` in
a finding's `severity.json`. It fixes the base CVSS impact before surface
and environmental adjustments. Read and write tiers differ sharply:

- A read primitive (`heap_read_small`, `stack_read`, `global_read`,
  `uaf_read`) scores low availability impact only. A sanitizer proves the
  fault, not that the bytes reach an attacker.
- A write primitive (`heap_write`, `wild_write`), `double_free`, and
  `type_confusion` score high confidentiality, integrity, and availability,
  because the corruption can be code-execution capable.

So file a source-argued bounds violation of unknown direction as
`buffer-overflow` (read tier), and use `oob-write` only when the report
establishes a write.

**Availability-only classes.** The `dos` family (`stack-overflow`,
`denial-of-service`, `uncaught-exception`) still maps to a primitive, but
denial of service is [not
scored](../concepts/benchmark.md#denial-of-service-is-not-scored). The
finding gate rejects a `dos`-family report before any review, with an
`out-of-scope:` reason, unless the finding is pinned or its `Primitive`
field names something other than an availability-only primitive (those
include `null_deref`, `segv`, and `oom`). The quality review applies the
same policy to availability loss filed under another class.

## Dashboard classes

| Class | Family | Severity primitive |
| --- | --- | --- |
| `heap-buffer-overflow` | memory-safety | `heap_read_small` |
| `stack-buffer-overflow` | memory-safety | `stack_read` |
| `global-buffer-overflow` | memory-safety | `global_read` |
| `buffer-overflow` | memory-safety | `heap_read_small` (a bounds violation of unspecified region or direction) |
| `oob-read` | memory-safety | `heap_read_small` |
| `oob-write` | memory-safety | `heap_write` |
| `arbitrary-write` | memory-safety | `wild_write` |
| `off-by-one` | memory-safety | `heap_read_small` |
| `use-after-free` | memory-safety | `uaf_read` |
| `double-free` | memory-safety | `double_free` |
| `type-confusion` | memory-safety | `type_confusion` |
| `integer-overflow` | memory-safety | `integer_overflow` (a precursor: low availability only) |
| `integer-underflow` | memory-safety | `integer_overflow` |
| `null-deref` | memory-safety | `null_deref` |
| `segv` | memory-safety | `segv` (a fault at an unknown address: availability) |
| `stack-overflow` | dos | `stack_exhaustion`; ASan's `stack-overflow` is recursion, not a stack buffer |
| `denial-of-service` | dos | `dos_amplification` |
| `uncaught-exception` | dos | `dos_amplification` (an exception ending a request or process) |
| `sql-injection` | injection | `sqli` |
| `command-injection` | injection | `command_injection` |
| `code-injection` | injection | `code_execution` |
| `rce` | injection | `code_execution` |
| `xss` | injection | `xss` |
| `deserialization` | deserialization | `deserialization` |
| `auth-bypass` | auth | `authn_bypass` |
| `broken-access-control` | auth | `authz_bypass` |
| `privilege-escalation` | auth | `privilege_escalation` |
| `idor` | auth | `idor` |
| `session-fixation` | auth | `authn_bypass` |
| `confused-deputy` | auth | `authz_bypass` |
| `crypto-failure` | crypto | `crypto_weakness` |
| `improper-cert-validation` | crypto | `improper_cert_validation` |
| `signature-bypass` | crypto | `signature_bypass` |
| `info-disclosure` | info-disclosure | `info_leak` |
| `toctou` | race | `race_condition` (a race argued from source) |
| `path-traversal` | boundary | `path_traversal` |
| `symlink-following` | boundary | `path_traversal` |
| `arbitrary-file-write` | boundary | `arbitrary_file_write` |
| `ssrf` | boundary | `ssrf` |
| `open-redirect` | boundary | `open_redirect` |
| `cors-misconfig` | config | *review* |
| `logic-error` | logic | `logic_regression` |
| `other` | other | *review* |

## Harness-native classes

| Class | Family | Severity primitive | Why it is kept |
| --- | --- | --- | --- |
| `invalid-free` | memory-safety | `allocator_mismatch` | A source-argued free of the wrong allocator or address is an abort, not the code-execution row `double-free` scores. |
| `uninitialized-read` | memory-safety | `info_leak` | MemorySanitizer's use-of-uninitialized-value lane: scored as disclosure, but a distinct diagnostic from any dashboard class. |
| `data-race` | race | `data_race` | A race-detector diagnostic (ThreadSanitizer, Go `-race`) is corruption-capable. A race argued from source is `toctou`, and `bin/severity` scores a `data-race` label with no detector diagnostic as `race_condition`. |
| `ssti` | injection | `ssti` | Template injection reaches the template engine's interpreter: full-compromise impact, not the low-impact row of a generic injection. |
| `xxe` | injection | `xxe` | External-entity expansion reads files and reaches internal hosts; it has its own detector pattern and impact row in `bin/severity`. |
| `csrf` | auth | `csrf` | A forged request acts with the victim's authority: an integrity-only impact no auth dashboard class carries. |
| `prototype-pollution` | deserialization | `prototype_pollution` | Untrusted keys mutate shared object state; low impact until a consumer turns it into another class. |
| `sandbox-escape` | boundary | `sandbox_escape` | The escaped-to host is a subsequent system; `privilege-escalation` scores the vulnerable system only. |

## Aliases and legacy labels

Any other spelling resolves to a canonical class before it is clustered,
counted, or scored. Matching ignores case and surrounding backticks, and
reads spaces and underscores as hyphens, so `Heap Buffer Overflow` is
`heap-buffer-overflow`.

| Canonical class | Also accepted |
| --- | --- |
| `use-after-free` | `heap-use-after-free`, `uaf`, and the category `lifetime` |
| `stack-buffer-overflow` | `stack-buffer-underflow` |
| `buffer-overflow` | the category `bounds`, and any unrecognised label containing `overflow` |
| `type-confusion` | the category `type` |
| `integer-overflow` | the category `size` |
| `uninitialized-read` | the category `uninit` |
| `sql-injection` | `sqli` |
| `privilege-escalation` | `privesc` |
| `denial-of-service` | `redos`, `memory-leak` |
| `toctou` | `race-condition` |
| `info-disclosure` | `side-channel`, `timing`: the consequence a side channel establishes |
| `other` | any other unrecognised label, including request smuggling, cache poisoning, and dependency confusion |

The category `state` pins only the `memory-safety` family, so it clusters
there and names no class.

**Legacy `top:sub` labels** from earlier quality gates resolve inside the
family the reviewer chose: `memory-safety:lifetime` is `use-after-free` and
`injection:sql` is `sql-injection`, but `memory-safety:stack-overflow` stays
in `memory-safety` rather than becoming a `dos` class. A sub-label that names
no class leaves only the family, so `auth:bypass` clusters as `auth` and
stays `Needs review`, because authentication and authorization bypasses score
differently. An `other:<sub>` label means "no listed top fit", so its
sub-label alone decides.
