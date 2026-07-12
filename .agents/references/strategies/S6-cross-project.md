# Strategy S6: Cross-Project Variant Mining

**Target:** unfixed analogues in the audit target of bug *classes* fixed in
peer projects. Independent implementations of the same spec, format, or
algorithm hit the same bug classes independently — a fix in peer A is a free
roadmap to the unfixed analogue in peer B.

**This is NOT Strategy S1.** S1 mines the target's OWN history. S6 mines
*peer* projects' history and asks whether the target has the same class.

**Review gate:** after 5 peer fixes analyzed with 0 target analogues, rotate.
Do not stop while a target analogue still needs mapping or a testcase.

## Procedure

1. **Pick the right peer set.** Use the taxonomy below — peers must implement
   the same spec, format, protocol, or algorithm. "Same language" is not a
   peer relationship; "same input grammar" is.

2. **Pull peer fixes from the last 3 years.** Prefer security-tagged or
   advisory-linked commits. Three years catches slow-moving spec parsers
   (TLS, ASN.1, font, archive) where fixes land sparsely; for fast-moving
   targets you can narrow the OSV/VCS time filter without changing this
   strategy. Examples per VCS in the Commands section.

3. **For each fix, distill the bug *class* — not the CVE, not the line.**
   Use neutral vocabulary. Good distillations:
   - "Length field read from input is used to size allocation without
      checking against remaining-bytes."
   - "Two-pass codec computes size in pass 1 and fills in pass 2; mutable
      shared input changes between passes."
   - "Error path frees X but leaves a pointer to it reachable from caller."
   - "Optimization pass elides a check the slow path performs."
   - "State machine reaches state Y from state X on an event the spec
      forbids."

4. **Map the class to the target's analogous subsystem.** Format: `peer fix
   → target subsystem to inspect`. Examples (target on the right):
   - peer libwebp lossless fix → if target is libavif / libjxl / libheif,
     inspect the lossless decode buffer-sizing path
   - peer openssl ASN.1 fix → if target is boringssl / mbedtls / wolfssl,
     inspect X.509 parsing for the same recursion or length-prefix gap
   - peer V8 Turbofan typer fix → if target is SpiderMonkey, inspect
     WarpBuilder; if target is JSC, inspect DFG — for the equivalent
     type-narrowing assumption

5. **Verify the analogue is real before writing a hypothesis.** Read the
   target's code at the analogous file/function and check:
   - Does the same untrusted input reach the same kind of operation?
   - Is the guard the peer added missing here?
   - Or is the target already safe via a different invariant? (If yes,
     record that and move on — do not file a hypothesis.)

6. **Write the hypothesis with target-specific file:function:line** and a
   one-sentence note pointing to the peer fix as the lead source.

## Peer-project taxonomy

Pick rows where the target appears. If the target is not listed, find the
closest format / protocol / algorithm match and use the corresponding peers.
Sources for each row are OSS-Fuzz peers + well-known independent
implementations.

| Domain | Target → peers to mine |
|--------|------------------------|
| **TLS / crypto stacks** | openssl ↔ boringssl, libressl, gnutls, mbedtls, wolfssl, botan, bearssl, rustls |
| **Crypto primitives** | libsodium, libgcrypt, openssl/crypto, mbedtls, cryptopp, ring |
| **Compression — DEFLATE** | zlib ↔ zlib-ng, libdeflate, miniz, zopfli |
| **Compression — modern** | zstd ↔ brotli, lz4, snappy, lzma/xz, bzip2 |
| **HTTP/1 + URL** | curl ↔ libsoup, libwget, nghttp2/aria2, h2o, ada-url, whatwg-url |
| **HTTP/2 + HTTP/3** | nghttp2 ↔ ls-http2, oghttp2 (envoy), aioquic, ngtcp2, quiche, msquic |
| **DNS** | c-ares ↔ unbound, knot-resolver, bind9, ldns, getdns |
| **IDN / IRI** | libidn2 ↔ icu uidna, idnkit |
| **XML / SGML** | libxml2 ↔ expat, libxslt, gumbo-parser, html5ever, lxml |
| **JSON** | nlohmann/json ↔ rapidjson, jansson, json-c, simdjson, serde_json, jsmn |
| **YAML / TOML** | libyaml ↔ ryml, yaml-cpp, tomlplusplus, tomlkit, serde_yaml |
| **Regex** | pcre2 ↔ re2, rust-regex, oniguruma, hyperscan, hsregex |
| **Image — PNG/lossless** | libpng ↔ spng, lodepng, libwebp (lossless mode), libjxl (lossless mode) |
| **Image — JPEG family** | libjpeg-turbo ↔ mozjpeg, libjxl, openjpeg (j2k), libavif (mdat) |
| **Image — modern** | libavif ↔ libheif, libjxl, dav1d (frame parse), libwebp (cross-listed: also under PNG/lossless) |
| **Image — TIFF/legacy** | libtiff ↔ giflib, libpng, libheif (HEVC tile parse) |
| **Audio codecs** | libvorbis ↔ libflac, libopus, libmpg123, faad2, libsndfile |
| **Video — H.264/265** | ffmpeg/h264 ↔ libde265, x265 (encode), openh264 |
| **Video — AV1/VPx** | libaom ↔ dav1d, libvpx, ffmpeg/aom |
| **Container demux** | ffmpeg/demux ↔ gstreamer, libmkv, mp4v2, libdvbpsi |
| **Font / shaper** | harfbuzz ↔ freetype, fontconfig, ots, allsorts (rust) |
| **Archive** | libarchive ↔ libzip, minizip, unzip, p7zip, libtar, zlib gzip |
| **PDF** | poppler ↔ mupdf, pdfium, ghostscript, sumatrapdf |
| **Office docs** | apache-poi ↔ libreoffice, mammoth, docx4j, openpyxl |
| **Database — SQL** | sqlite ↔ duckdb, mariadb, postgres, h2 |
| **Database — KV** | leveldb ↔ rocksdb, lmdb, badger |
| **JS engines** | spidermonkey ↔ v8, jsc, hermes, quickjs, duktape, mujs |
| **Wasm runtimes** | spidermonkey-wasm ↔ v8-wasm, jsc-wasm, wasmtime, wasmer, wasm3, wabt |
| **SSH** | openssh ↔ libssh, libssh2, dropbear, paramiko |
| **Serialization** | protobuf ↔ capnproto, flatbuffers, msgpack, cbor (libcbor / cbor2), borsh |
| **Email parsers** | exim ↔ postfix, dovecot, mailutils, james-mime4j |
| **Compiler frontends** | clang ↔ gcc, mrustc, tcc |
| **Browser layout/DOM** | gecko ↔ blink (chromium), webkit, servo |
| **Browser network** | gecko/netwerk ↔ chromium/net, webkit/network |
| **Kernel — filesystem** | linux/ext4 ↔ linux/btrfs, linux/xfs, linux/f2fs, openzfs, freebsd/ufs |
| **Kernel — net stack** | linux/net ↔ freebsd/net, openbsd/net, netbsd/net |

For unlisted targets: find the spec/RFC/ISO standard the target implements,
then search OSS-Fuzz (`https://github.com/google/oss-fuzz/tree/master/projects`)
or `awesome-*` lists for two or more independent implementations.

## What classes of bugs cross-port well

These patterns recur across independent implementations of the same spec.
When you see one in a peer, search for the analogue in the target.

| Class | Peer-fix shape | What to grep in target |
|-------|----------------|------------------------|
| **Length-prefix vs remaining-bytes** | "Used `len` from header without checking `len <= avail`" | `memcpy.*len`, `read_bytes.*length` near network/file parse |
| **size issue in `size * count`** | "Allocation size computed without overflow check" | `malloc.*\*`, `* sizeof`, `size\b.*\*\b.*count` |
| **Off-by-one in chunk loop** | "Last iteration writes one past end" | loops over chunk-headers or scanline arrays |
| **Two-pass TOCTOU** | "Pass 1 sizes, pass 2 fills, shared input mutates" | `Span.*Shared`, `ComputeSize.*Fill`, encode/decode round-trips |
| **Error-path lifetime** | "Free on error path leaves pointer reachable" | `goto.*err`, `cleanup:` labels with shared ptrs |
| **Truncated input accepted** | "Decoder treats EOF as success without finalize check" | parsers that don't validate `state == DONE` at EOF |
| **Recursion depth unchecked** | "Nested grouping/encoding overflows stack" | recursive `parse_*`, ASN.1, JSON, regex `(` nesting |
| **Sentinel collision** | "-1 / 0xFFFF / MAX matches a valid input value" | `== -1`, `== 0xFFFF`, `INT_MAX` as "absent" markers |
| **type-mismatch in tagged dispatch** | "Producer wrote tag A, consumer read tag B" | union/variant tag fields, `switch (kind)` near IPC |
| **Optimization elides validation** | "JIT/fast-path skips check the slow path enforces" | `MaybeOptimize`, `tryInline`, `FastPath`, `specialize` |
| **State-machine illegal transition** | "Async event reaches state Y from forbidden state X" | callback handlers near sockets / TLS / codec init |
| **Encoding boundary** | "Surrogate pair / BOM / NUL splits a token mid-byte" | UTF-8/16 decode loops, IDN, normalization |
| **Floating-point NaN/Inf bypass** | "Comparison treats NaN as ordered" | `< 0`, `> max` checks on float; codec gain/sample paths |

## Commands by source type

### Source coverage at a glance

No single source covers every peer. Pick by target shape:

| Source | Best for | Failure mode |
|--------|----------|--------------|
| **OSV (osv.dev)** | Libraries in OSS-Fuzz / GHSA / Debian / Ubuntu ecosystems | Misses fixes that never got a CVE; sparse for older fixes (~pre-2020) and obscure projects |
| **OSS-Fuzz issue tracker** | C/C++ targets actively fuzzed by Google | Project must be opted into OSS-Fuzz; some bug details require login |
| **Project-specific tracker** | Big projects with security teams (Mozilla, Chromium, WebKit, GNOME, Apache) | Per-project API; security view restricted on some |
| **VCS log keyword search** | *Any* git/hg repo — universal fallback | Noisy; depends on commit-message discipline |
| **CHANGELOG / SECURITY.md / NEWS** | Mature projects with maintainer-curated release notes | Format varies wildly; needs LLM or regex per project |
| **Vendor advisory mirrors** | CVE backports (RHSA, USN, DSA) | Usually redundant with OSV |

For a peer with no OSV entries, **VCS log + project tracker is the only path** —
the strategy still applies, the sourcing is just more work.

### Preferred for advisory-covered peers: OSV (osv.dev)

The command examples in this section use `curl` and `jq`. The GitHub severity
fallback additionally uses the authenticated `gh` CLI. Install only the tools
for the path you use; TokenFuzz itself does not require them.

OSV aggregates OSS-Fuzz, GHSA, Debian DSA, Ubuntu USN, Alpine, etc., into one
JSON schema. Each entry carries a fix commit hash you can `git show`. Highest
structured signal when the peer is in the ecosystem.

```bash
# 1. List issues for a peer (try OSS-Fuzz ecosystem first, then
#    Debian for projects with longer histories like openssl).
#
#    Notes on the jq filter:
#    - .events[] contains heterogeneous entries — {introduced}, {fixed},
#      {last_affected}, {limit}. Bare `.events[]?.fixed` would emit `null`
#      for non-fixed entries, so we use `.fixed // empty` to drop them
#      before collecting; otherwise [0] can return null when an
#      "introduced" event sorts first.
#    - 3-year window via `.modified >= "<cutoff>"`. Adjust the cutoff to
#      narrow or widen.
CUTOFF=$(date -u -v-3y +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -d '3 years ago' +%Y-%m-%dT%H:%M:%SZ)
curl -s -X POST 'https://api.osv.dev/v1/query' -H 'Content-Type: application/json' \
  -d '{"package":{"name":"<peer>","ecosystem":"OSS-Fuzz"}}' \
  | jq --arg cutoff "$CUTOFF" '
      .vulns[]
      | select((.modified // .published // "") >= $cutoff)
      | {id, summary, modified,
         fix: ([.affected[]?.ranges[]?
                | select(.type=="GIT")
                | .events[]? | .fixed // empty][0])}
      | select(.fix)'

# Pagination: if the response includes `.next_page_token`, re-POST with
# `"page_token": "<token>"` merged into the body and concatenate results.
# Most peers fit in one page (libxml2: ~56, pcre2: ~11, openssl: ~10) but
# long-history packages on Debian/Ubuntu ecosystems may paginate.

# 2. Look up a single CVE (works regardless of ecosystem). The response
#    includes references[] (advisory + fix URLs) and affected[].ranges[]
#    GIT events with fixed/introduced commit hashes. Replace the CVE id
#    with whichever advisory you are investigating.
curl -s 'https://api.osv.dev/v1/vulns/CVE-2025-24928' | jq    # illustrative

# 3. Resolve a fix commit to a diff. Works for any peer once you've cloned
#    or shallow-fetched its repo. (Shallow: `git clone --filter=blob:none
#    --no-checkout <url>` then `git fetch origin <hash>:refs/peer-fix`.)
git -C <peer> show <hash>              # full diff (commit message + diff)
git -C <peer> show <hash> --stat       # commit message + files-changed table
git -C <peer> show <hash> --name-only  # files only
```

OSV ecosystem coverage notes (validated 2026-05-09):
- **OSS-Fuzz** — clean, project-canonical, has GIT events with fix commits.
  Best for libxml2 (56), pcre2 (11), openssl (10). Try first.
- **Debian / Ubuntu** — longer history, IDs are `DSA-*` / `USN-*` (not CVE).
  Use when OSS-Fuzz is sparse; resolve DSA → CVE via `aliases` field, then
  hit `/v1/vulns/CVE-...` for upstream fix events.
- **Repo-published GHSA via `gh api repos/<o>/<r>/security-advisories`** —
  patchy. libxml2 (0), openssl (0), pcre2 (1), curl (0), zlib (0). Treat
  as a supplement, not a primary source.

### Severity fallback: GitHub global advisory database

OSV often carries CVSS data already (`severity[]` array, or
`database_specific.severity` for ecosystems like GHSA). Read OSV's severity
fields first. Only fall back to the GitHub `/advisories` endpoint when an
OSV entry has no severity attached and you need a CVSS-derived
low/medium/high/critical bucket to prioritize reading.

```bash
# Direct CVE lookup — precise, no false positives. Returns ghsa_id, cve_id,
# summary, severity (low/medium/high/critical), references[]. Replace the
# CVE id with whichever advisory you are investigating.
gh api 'advisories?cve_id=CVE-2025-24928' \
  --jq '.[] | {ghsa_id, cve_id, severity, summary, refs: [.references[]?][0:5]}'

# Workflow: enumerate via OSV → check `.severity[]` / `.database_specific`
# on each entry → only for entries missing severity, hit the GitHub
# advisory endpoint → sort by severity → read the highest-severity diffs
# first.
```

Notes on other GitHub advisory queries:
- `?keywords=<peer>` — capped at 100 results and matches anywhere in the
  body (false positives common). Avoid for enumeration.
- `?ecosystem=<eco>` — does NOT include OSS-Fuzz. Valid values are package
  managers (npm, pip, maven, …) plus `other`. C/C++ OSS falls under
  `other` but the filter is too coarse to be useful.

### Universal fallback: VCS log (works for any peer)

When OSV is sparse, VCS log is the only mechanical source. Not a last resort
for advisory-thin projects — it's the primary path. Three filters in order
of precision:

```bash
# git — most precise first: explicit CVE references.
git -C <peer> log --since="3 years ago" --oneline --grep='CVE-' | head -40

# Broaden: security keywords + small-diff filter. Security commits tend to
# be small (<50 lines changed) and touch one or two files. This filter pairs
# log search with --shortstat to surface that shape.
git -C <peer> log --since="3 years ago" --shortstat -E \
    --grep='CVE|security|fix.*overflow|fix.*bound|fix.*uninit|fix.*free|fix.*leak|sanitize' \
    | awk '/^commit / {commit=$2} /file.*changed/ {if (($1+0)<=3 && ($4+0)<=50) print commit, $0}' \
    | head -30

# Narrow by subsystem when the fix-class is known (e.g., codec, parser):
git -C <peer> log --all --oneline -- <subsystem>/ | head -40

# mercurial (Firefox, some Mozilla): tag-based + keyword.
hg log -k "sec-high" -k "sec-critical" -d "-1095" \
   --template "{node|short} {desc|firstline}\n" | head -40
hg log -d "-1095" --keyword=CVE --template "{node|short} {desc|firstline}\n"
```

After surfacing candidates, read the diff (`git show <hash>`) and ask:
*does this look like a prior fix or a feature change?* Heuristic — prior
fixes usually add a guard (`if (x > N) return`, bounds check, null check) or
narrow a type. Feature changes touch more files and add new behavior.

### OSS-Fuzz issue tracker (high-signal for fuzz-covered C/C++ peers)

For any peer that is in OSS-Fuzz, the issue tracker lists every fuzz-detected
bug with reproducer + fix-commit links. Often more granular than OSV's
post-advisory aggregation.

```text
https://issues.oss-fuzz.com/issues?q=projectId:<peer-name>
# Example: https://issues.oss-fuzz.com/issues?q=projectId:libxml2
```

Verify the peer is on OSS-Fuzz: `https://github.com/google/oss-fuzz/tree/master/projects/<peer>`.

### Project-specific trackers (when the peer has a security team)

Each major project has its own tracker with more detail than OSV. Pull
security-tagged issues directly when available:

| Project family | Tracker URL pattern | Security tag/keyword |
|----------------|---------------------|----------------------|
| Mozilla (Firefox, NSS) | `bugzilla.mozilla.org` | `sec-high`, `sec-critical`, `sec-moderate` |
| Chromium / V8 | `crbug.com` | `Type=Bug-Security`, `Restrict-View-SecurityTeam` (restricted view; only public-after-fix) |
| WebKit | `bugs.webkit.org` | `Security` keyword |
| GNOME (libxml2, glib, gdk-pixbuf) | `gitlab.gnome.org/<project>/-/issues` | `Security` label |
| KDE | `bugs.kde.org` | Security keyword |
| Apache (httpd, tomcat, etc.) | `bz.apache.org/bugzilla/` or `httpd.apache.org/security/` | Project-specific |
| Linux kernel | `lore.kernel.org/security/` | Mailing list — full-text search |
| Debian source-package | `https://security-tracker.debian.org/tracker/source-package/<peer>` | Link out to upstream patches |
| Arch | `https://security.archlinux.org/package/<peer>` | Same shape as Debian |

### Maintainer-curated release notes (CHANGELOG / SECURITY.md / NEWS)

Many mature projects describe prior fixes in human prose in their release
notes — often more accurate than commit messages, and they explicitly mark
what was a prior fix:

```bash
# Common file names — check the peer's repo root:
ls <peer>/{CHANGELOG,CHANGES,NEWS,SECURITY,RELEASE-NOTES,HISTORY}.{md,rst,txt} 2>/dev/null
# Specific examples:
#   curl: CHANGES + docs/SECURITY-ADVISORY.md
#   openssl: CHANGES.md + security/ directory with advisories
#   libxml2: NEWS file with per-release fix descriptions
```

Grep the file for security signals — "CVE", "security", "buffer", "overflow",
"underflow", "leak", "free", "race", "bounds". An LLM can also distill the
class from the prose description (often clearer than a one-line commit msg).

### Peer metadata: `output/<slug>/target.toml`

S6 peers live only in the active target config:

```toml
[s6_peers]
domain = "XML / SGML"
peers = ["expat", "libxslt", "html5ever"]
```

`bin/audit --new-target` runs `bin/suggest-peers <slug> --apply` when an
LLM backend is available. Existing targets can run `bin/suggest-peers
<slug> --apply` manually. Review the generated list before relying on it.

The work-card ranking regex intentionally matches only generic S6
vocabulary (`peer-fix`, `upstream advisory`, `cross-project`,
`oss-fuzz`, `cve-NNNN`, and similar terms). It does not embed target or
vendor names.

## What this strategy is NOT

- **Not a port-the-fix-verbatim exercise.** The fix is a *signal*; the bug
  *class* is the unit of reuse. Two parsers of the same RFC will both have
  the length-prefix gap, but the exact fix lines won't transplant.
- **Not "every CVE everywhere".** Filter to peers that share spec / format /
  algorithm. A bug in a Java SAX parser does not predict a bug in a Rust
  TOML parser.
- **Not S1.** If you find yourself reading the *target's* own changelog,
  switch to S1 and stop logging time against S6.

## Token efficiency

- Read ONE peer fix at a time, distill it, search target, move on. Do not
  bulk-load 50 patches into context.
- Use the advisory feed (release notes, SECURITY.md, vendor security pages) before reading raw `git log` output.
- Skip peer fixes older than 3 years unless the target subsystem is
  unchanged across that span (some long-lived parsers / TLS / archive
  code rarely change — older fixes still cross-port).
- After 5 peer fixes with 0 target analogues, rotate strategy.
