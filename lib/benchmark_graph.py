#!/usr/bin/env python3
"""Time-to-discovery graph appended to the benchmark crosstab HTML.

Why this exists in its own module: the audit's in-run counter (`totals=N
findings` in audit.log) is an *inventory*, not a discovery log — it falls when a
finding is demoted and finalization re-adjudicates it in either direction, so it
cannot carry a curve. This builds the honest one instead:

  * the pooled per-condition directories are authoritative for *what* survived,
    so the curve ends exactly on the number the table reports;
  * each result is placed at *when* it was found, resolved from the cells;
  * results use the clusterers' own membership; rejected legacy rows without
    clustering evidence remain visible as an explicitly marked upper bound.

The curve is therefore monotonic by construction. Anything whose discovery time
cannot be resolved is placed at the end of the run rather than dropped, so the
endpoint always equals the table.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path

import finding_dedup
import finding_signature

_TS = re.compile(r"^\[(\d\d):(\d\d):(\d\d)\]")


def _report_text(directory: Path) -> str:
    for name in ("report.md", "REPORT.md"):
        candidate = directory / name
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8", errors="replace")
    return ""


def _signature(directory: Path, kind: str) -> tuple | None:
    """Join key for one artifact, or None when it cannot be identified.

    Must survive pooling: pooling renames FIND-002-foo to FIND-0001, so a
    name-based key can never join a pooled result back to the cell that found
    it. Crashes therefore fall back to sanitizer.txt — the evidence the real
    crash clusterer keys on — before giving up. Giving up returns None rather
    than a name, because an identity that cannot join is worse than an admitted
    unknown: it silently lands the result at the run's end.
    """
    text = _report_text(directory)
    if kind == "find":
        if not text:
            return None
        return tuple(str(p) for p in finding_signature.finding_signature(text)["key"])
    state = finding_dedup.crash_state(text, want=3) if text else ()
    if not state:
        sanitizer = directory / "sanitizer.txt"
        if sanitizer.is_file():
            state = finding_dedup.crash_state(
                sanitizer.read_text(encoding="utf-8", errors="replace"), want=3,
            )
    return state or None


def _cell_start(cell_dir: Path) -> float | None:
    """Epoch seconds when the cell started doing work.

    The audit log sits beside cell.json, not down in the nested results tree.
    Probing next to results/ silently found nothing, and a missing origin
    rebases every curve onto its own first artifact — planting "hour zero"
    wherever the first result happened to land instead of at the run's start.

    started_at is authoritative when the cell recorded it (it also covers
    model-direct, which keeps no audit log); the audit's first iteration stamp
    is the fallback that reads runs recorded before that field existed.
    """
    cell_dir = Path(cell_dir)
    try:
        meta = json.loads((cell_dir / "cell.json").read_text(encoding="utf-8"))
        started = meta.get("started_at")
        if started:
            return datetime.fromisoformat(started).timestamp()
    except (OSError, ValueError, TypeError):
        pass
    log = cell_dir / "audit.log"
    if not log.is_file():
        return None
    try:
        stamp = log.stat().st_mtime
    except OSError:
        return None
    first = None
    with log.open(errors="replace") as stream:
        for line in stream:
            match = _TS.match(line)
            if match and "Iteration 1 starting" in line:
                first = match.groups()
                break
    if not first:
        return None
    # audit.log stamps are local wall clock and carry no date, so anchor them
    # against the log's own mtime read in local time — reading that mtime as
    # UTC skews every hour by the zone offset.
    tail = datetime.fromtimestamp(stamp)
    anchor = tail.replace(hour=int(first[0]), minute=int(first[1]),
                          second=int(first[2]), microsecond=0)
    # the log's mtime is the run's tail, so a start reading later than the tail
    # means the run crossed midnight
    if anchor > tail:
        anchor -= timedelta(days=1)
    return anchor.timestamp()


def _artifact_time(directory: Path) -> float | None:
    """Earliest clock inside an artifact directory.

    A directory's own mtime moves whenever an entry is added or rewritten, so
    re-triage drags it to "now" and destroys the discovery signal. The earliest
    file inside it — written when the agent first filed the artifact — survives
    that, so prefer whichever is older.
    """
    stamps = []
    try:
        stamps.append(directory.stat().st_mtime)
        for child in directory.iterdir():
            try:
                stamps.append(child.stat().st_mtime)
            except OSError:
                continue
    except OSError:
        return None
    return min(stamps) if stamps else None


def _discovery_index(cells: list[Path]) -> dict[tuple, dict[tuple, float]]:
    """{kind: {signature: earliest hours-into-run it was seen}}."""
    index: dict[str, dict[tuple, float]] = {"find": {}, "crash": {}}
    for cell in cells:
        try:
            meta = json.loads((cell / "cell.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        results = Path(meta.get("results_dir") or "")
        if not results.is_dir():
            continue
        stamps = _event_stamps(results)
        origin = _cell_start(cell)
        roots = {
            "find": ("findings", "findings-rejected"),
            "crash": ("crashes", "crashes-rejected"),
        }
        found: dict[str, list[tuple[Path, float]]] = {}
        for kind, subdirs in roots.items():
            for sub in subdirs:
                root = results / sub
                if not root.is_dir():
                    continue
                for directory in sorted(root.iterdir()):
                    if not directory.is_dir():
                        continue
                    when = stamps.get(directory.name)
                    if when is None:
                        when = _artifact_time(directory)
                    if when is None:
                        continue
                    # key it once: _signature re-reads the report off disk
                    key = _signature(directory, kind)
                    if key is None:
                        continue
                    found.setdefault(kind, []).append((key, when))
        if not found:
            continue
        # One origin for the whole cell. Falling back per artifact kind gave
        # findings and crashes different zeroes, so the two panels of a row no
        # longer shared a clock.
        base = origin if origin else min(
            when for entries in found.values() for _, when in entries
        )
        for kind, entries in found.items():
            for key, when in entries:
                hours = max(0.0, (when - base) / 3600.0)
                previous = index[kind].get(key)
                if previous is None or hours < previous:
                    index[kind][key] = hours
    return index


def _event_stamps(results: Path) -> dict[str, float]:
    """finding_created stamps, when the run recorded them (new runs only)."""
    events = results / "state" / "events.jsonl"
    if not events.is_file():
        return {}
    out: dict[str, float] = {}
    with events.open(errors="replace") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("type") != "finding_created":
                continue
            stamp = row.get("mtime") or row.get("first_seen")
            try:
                out[row["id"]] = datetime.fromisoformat(stamp).timestamp()
            except (TypeError, ValueError, KeyError):
                continue
    return out


def _load_clusters(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data.get("clusters", []) if isinstance(data, dict) else []


def _cluster_times(
    run_dir: Path, cond: str, kind: str, rejected: bool,
    index: dict, members: dict, fallback: float,
) -> tuple[list[float], bool]:
    """Earliest discovery time per REAL cluster, from the clusterer's own JSON.

    The clusterers merge more than a raw signature key does, so a locally
    deduplicated list cannot be mapped onto their counts by truncation: given
    times 0.1 and 0.2 in one fuzzy cluster and 0.9 in another, dropping the tail
    yields [0.1, 0.2] when the honest answer is [0.1, 0.9]. Reading the real
    membership and taking each cluster's earliest member gives the right curve
    and the right length at once.

    Returns (times, approximate) — approximate when any cluster had no member we
    could place on the timeline.
    """
    sub = ("crashes" if kind == "crash" else "findings") + ("-rejected" if rejected else "")
    owner = members.get(sub, {}) or {}
    pool_dir = run_dir / "pool" / sub
    times: list[float] = []
    approximate = False
    for cluster in _load_clusters(run_dir / f"clusters-{sub}.json"):
        mine = [m for m in (cluster.get("members") or []) if owner.get(m) == cond]
        if not mine:
            continue
        best = None
        for member in mine:
            directory = pool_dir / member
            if not directory.is_dir():
                continue
            key = _signature(directory, kind)
            when = index.get(kind, {}).get(key) if key else None
            if when is not None and (best is None or when < best):
                best = when
        if best is None:
            # counted by the table, but nothing we can honestly place in time
            best = fallback
            approximate = True
        times.append(min(max(0.0, best), fallback) if fallback else max(0.0, best))
    return sorted(times), approximate


def _is_batch_quantized(times: list[float]) -> bool:
    """True when the clock is the gate's batch write, not per-result discovery.

    Without the finding_created stream the only surviving clock on an old
    artifact is whatever the quality gate wrote, and the gate validates in
    batches — so many results collapse onto one instant and the curve grows a
    vertical cliff it has not earned. Detect that directly rather than trusting
    the stamps' presence: a re-run of the gate writes stamps too, and they are
    just as batched.
    """
    if len(times) < 3:
        return False
    # a batch write spans a second or two, so bucket to ~36s rather than test
    # exact equality — 2.519h and 2.520h are the same write
    buckets: dict[int, int] = {}
    for value in times:
        key = round(value / 0.01)
        buckets[key] = buckets.get(key, 0) + 1
    return max(buckets.values()) / len(times) > 0.3


def _reconcile(times: list[float], count: int, wall: float) -> list[float]:
    """Make the curve land exactly on the count the table reports.

    The clusterers merge a little more than the raw signature key does, so a
    local dedup can differ by one or two. The table is authoritative for *how
    many*; this list only carries *when*. Extra entries drop from the tail (a
    merged pair is discovered when its earlier half was); a shortfall lands at
    the end of the run rather than inventing an early discovery.
    """
    if count <= 0:
        return []
    if len(times) > count:
        return times[:count]
    return times + [wall] * (count - len(times))


def build(bench_root: Path) -> dict:
    """Collect one series per target/backend/condition/run."""
    bench_root = Path(bench_root)
    series: list[dict] = []
    targets: dict[str, str] = {}
    for run_dir in sorted(bench_root.glob("*/*")):
        run_json = run_dir / "run.json"
        if not run_json.is_file():
            continue
        try:
            run = json.loads(run_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        try:
            members = json.loads((run_dir / "pool-members.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            members = {}
        report_path = run_dir / "report.json"
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        target = run.get("target", "?")
        targets.setdefault(target, (run.get("target_sha") or "")[:7])
        cells_by_cond: dict[str, list[Path]] = {}
        for cell in sorted((run_dir / "cells").glob("*")):
            if not (cell / "cell.json").is_file():
                continue
            name = cell.name
            cond = "harness" if name.startswith("harness") else "model-direct"
            cells_by_cond.setdefault(cond, []).append(cell)
        for condition in report.get("conditions", []):
            cond = condition.get("condition")
            cells = cells_by_cond.get(cond, [])
            if not cells:
                continue
            index = _discovery_index(cells)
            wall = (condition.get("wall_median") or 0) / 3600.0
            entry = {
                "target": target,
                "target_sha": targets[target],
                "backend": run.get("backend", "?"),
                "model": (run.get("model") or "").strip(),
                "condition": cond,
                "run_id": run_dir.name,
                "version": (run.get("tokenfuzz_sha") or "")[:7],
                "replicates": condition.get("replicates_done", 0),
                "wall_h": round(wall, 3),
            }
            for kind, uniq_key, rej_key, upper_key, mplus in (
                ("find", "unique_finding_clusters",
                 "unique_rejected_finding_clusters",
                 "rejected_finding_clusters_upper_bound", "medium_plus_findings"),
                ("crash", "unique_crash_clusters",
                 "unique_rejected_crash_clusters",
                 "rejected_crash_clusters_upper_bound", "medium_plus_bugs"),
            ):
                # the table's number is authoritative; these lists carry only the
                # timing of it, so the curve can never disagree with the table
                n_accepted = condition.get(uniq_key) or 0
                n_rejected = condition.get(rej_key) or 0
                declared_upper_bound = bool(condition.get(upper_key))
                acc_times, acc_approx = _cluster_times(
                    run_dir, cond, kind, False, index, members, wall)
                rej_times, rej_approx = _cluster_times(
                    run_dir, cond, kind, True, index, members, wall)
                # Reports written before the explicit bit can still reveal the
                # upper bound: more rejected results than clusters means some
                # rows had no clustering evidence or the cluster file failed.
                rejected_upper_bound = (
                    declared_upper_bound or len(rej_times) < n_rejected
                )
                accepted = _reconcile(acc_times, n_accepted, wall)
                rejected = _reconcile(rej_times, n_rejected, wall)
                entry[kind] = {
                    # approximate when a cluster could not be placed in time, when
                    # the table's count and the clusters we could read disagree, or
                    # when the only surviving clock is a batch write
                    "approx_timing": bool(
                        acc_approx or rej_approx
                        or rejected_upper_bound
                        or len(acc_times) != n_accepted
                        or len(rej_times) != n_rejected
                        or _is_batch_quantized(accepted)
                    ),
                    "accepted": n_accepted,
                    "rejected": n_rejected,
                    "rejected_upper_bound": rejected_upper_bound,
                    "medium_plus": condition.get(mplus, 0),
                    "accepted_times": [round(t, 4) for t in accepted],
                    "rejected_times": [round(t, 4) for t in rejected],
                }
            series.append(entry)
    order = [t for t in sorted(targets) if any(s["target"] == t for s in series)]
    return {"series": series, "targets": targets, "target_order": order}


# ── rendering ───────────────────────────────────────────────────────────────
# Palette validated for both light and dark surfaces (colourblind-safe):
# backend hue codex=blue, claude=magenta, gemini=violet — kept clear of the
# warm red/orange/green the report already spends on severity.
_CSS = """
.ttd{background:#f1f3f4;border-radius:20px;padding:1.3em 1.4em 1.5em;margin:1.6em 0 2em;
 box-shadow:0 1px 3px 1px rgba(32,33,36,.10),0 1px 2px rgba(32,33,36,.18);
 --ink1:#202124;--ink2:#5f6368;--muted:#80868b;--grid:#e8eaed;--axis:#b9bec4;
 --surf:#fff;--codex:#2a78d6;--claude:#d64f92;--gemini:#6f52c9;--noise:#9aa0a6;color:var(--ink1)}
.ttd *{box-sizing:border-box}
.ttd h2{font-size:1.35em;font-weight:700;margin:0 0 .15em;border:none;color:var(--ink1)}
.ttd .kick{font-size:.72em;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:var(--codex);margin:0 0 .3em}
.ttd .key{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1em 2.2em;
 background:var(--surf);border-radius:14px;padding:1.1em 1.3em;margin:1.2em 0 .3em;
 box-shadow:0 1px 2px rgba(32,33,36,.16)}
.ttd .ki{display:flex;gap:.8em;align-items:flex-start}
.ttd .ki svg{flex:none;width:26px;height:12px;margin-top:.35em;color:var(--ink2)}
.ttd .kt b{display:block;font-size:.86em;color:var(--ink1)}
.ttd .kt span{font-size:.81em;line-height:1.5;color:var(--ink2)}
.ttd .row{margin:1.4em 0 0}
.ttd .rh{display:flex;align-items:baseline;gap:.7em;flex-wrap:wrap;padding:0 2px .5em}
.ttd .rh h3{margin:0;font-size:1.05em;font-weight:700;color:var(--ink1)}
.ttd .rh .sha,.ttd .rh .meta{font-family:var(--mono);font-size:.78em;color:var(--muted);font-weight:500}
.ttd .grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.ttd .panel{background:var(--surf);border-radius:14px;padding:.9em 1em .7em;
 box-shadow:0 1px 2px rgba(32,33,36,.16);min-width:0}
.ttd .pt{font-size:.85em;font-weight:700;margin:0 0 .1em 2px;color:var(--ink1)}
.ttd svg.c{display:block;width:100%;height:auto;overflow:visible;font:inherit}
@media(max-width:860px){.ttd .grid{grid-template-columns:1fr}}
"""

_KEY = """
<div class="key">
 <div class="ki"><svg viewBox="0 0 26 12"><path d="M1 10 L8 10 L8 5 L17 5 L17 2 L25 2" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"/></svg>
  <div class="kt"><b>The curve — accepted over time</b><span>Count on the y-axis, productive audit-hours on the x. Each step is one deduplicated result the gate kept, placed at the hour it was found, so the line only ever climbs and ends on the table's number.</span></div></div>
 <div class="ki"><svg viewBox="0 0 26 12"><polygon points="13,1 19,6 13,11 7,6" fill="currentColor"/></svg>
  <div class="kt"><b>◇ Final total</b><span>The settled count for that cell — identical to the Unique accepted column above.</span></div></div>
 <div class="ki"><svg viewBox="0 0 26 12"><polygon points="8,1 8,11 19,6" fill="none" stroke="currentColor" stroke-width="2"/></svg>
  <div class="kt"><b>▷ model-direct control</b><span>The bare model with no harness — one shot, so it lands as a single point at the hour it stopped.</span></div></div>
 <div class="ki"><svg viewBox="0 0 26 12"><rect x="1" y="6" width="24" height="5" fill="currentColor" fill-opacity=".3"/><path d="M1 8 L9 8 L9 6 L25 6" fill="none" stroke="currentColor" stroke-width="1.25"/></svg>
  <div class="kt"><b>The strip below — rejected</b><span>What the gate cut, clustered where evidence permits, on the same clock but its own compact scale. A ≤ total is a conservative upper bound.</span></div></div>
 <div class="ki"><svg viewBox="0 0 26 12"><circle cx="7" cy="6" r="5" fill="#2a78d6"/><circle cx="19" cy="6" r="5" fill="#d64f92"/></svg>
  <div class="kt"><b>Label = model, colour = backend</b><span>Each row is named by the model that ran it (its model-direct control and tokenfuzz harness share that name); blue is codex, magenta is claude. Every target is audited on live, unfixed code — there is no planted bug to re-find.</span></div></div>
 <div class="ki"><svg viewBox="0 0 26 12"><path d="M1 6 L25 6" stroke="currentColor" stroke-width="1.5"/><circle cx="13" cy="6" r="2.5" fill="currentColor"/></svg>
  <div class="kt"><b>Reading a pair</b><span>Height is yield, the strip is wasted effort. &ldquo;% kept&rdquo; is how much of what the model proposed survived the gate; when rejects are an upper bound, &ldquo;≥% kept&rdquo; is a lower bound. It is not precision: that needs an answer key, and a live target has none.</span></div></div>
</div>
"""

_JS = r"""
(function(){
var D=JSON.parse(document.getElementById("ttd-data").textContent),NS="http://www.w3.org/2000/svg";
var HUE={codex:"#2a78d6",claude:"#d64f92",gemini:"#6f52c9"};
function el(t,a,k){var e=document.createElementNS(NS,t);for(var x in a)if(a[x]!=null)e.setAttribute(x,a[x]);
 (k||[]).forEach(function(c){e.appendChild(c)});return e}
function tx(s){return document.createTextNode(String(s))}
function nice(v,n,i){if(!(v>0))v=1;var s=v/(n||4),p=Math.pow(10,Math.floor(Math.log10(s))),q=s/p;
 var st=(q<=1?1:q<=2?2:q<=2.5?2.5:q<=5?5:10)*p;if(i)st=Math.max(1,Math.round(st));
 return{step:st,top:Math.ceil(v/st-1e-9)*st}}
// a discovery curve is cumulative: one step up per result, at the hour it was found
function steps(times){var p=[[0,0]];times.forEach(function(t,i){p.push([t,i]);p.push([t,i+1])});return p}
function path(pts,X,Y){return pts.map(function(p,i){return (i?"L":"M")+X(p[0]).toFixed(2)+","+Y(p[1]).toFixed(2)}).join(" ")}
function panel(host,tg,kind,rows){
 var W=600,ml=46,mr=64,pw=W-ml-mr,chips=rows.filter(function(r){return r.condition==="harness"});
 var mt=18+chips.length*16,ph=206,xa=38,sh=rows.length?16+rows.length*22:0,H=mt+ph+xa+sh+8;
 var maxY=1,maxX=.5,maxR=1;
 rows.forEach(function(r){var m=r[kind];maxY=Math.max(maxY,m.accepted);maxR=Math.max(maxR,m.rejected);
  maxX=Math.max(maxX,r.wall_h||.5);(m.accepted_times||[]).forEach(function(t){maxX=Math.max(maxX,t)})});
 var ys=nice(maxY*1.12,4,true),xs=nice(maxX*1.04,4);
 var X=function(v){return ml+(v/xs.top)*pw},Y=function(v){return mt+ph-(v/ys.top)*ph};
 var s=el("svg",{class:"c",viewBox:"0 0 "+W+" "+H,role:"img"});
 var cy=11;
 chips.forEach(function(r){var m=r[kind],c=HUE[r.backend]||HUE.codex,u=!!m.rejected_upper_bound,
  raw=(m.accepted+m.rejected)?100*m.accepted/(m.accepted+m.rejected):null,
  k=raw==null?null:(u?Math.floor(raw):Math.round(raw));
  s.appendChild(el("circle",{cx:ml+4,cy:cy-3.5,r:4,fill:c}));
  s.appendChild(el("text",{x:ml+14,y:cy,"font-size":11,"font-weight":700,fill:"#202124"},[tx(r.model||r.backend)]));
  s.appendChild(el("text",{x:ml+150,y:cy,"font-size":11,fill:"#5f6368"},[tx(m.accepted+" accepted")]));
  s.appendChild(el("text",{x:ml+242,y:cy,"font-size":11,fill:"#5f6368"},[tx((u?"≤ ":"")+m.rejected+" rejected")]));
  if(k!=null)s.appendChild(el("text",{x:ml+336,y:cy,"font-size":11,"font-weight":700,fill:"#202124"},[tx((u?"≥ ":"")+k+"% kept")]));
  cy+=16});
 for(var v=0;v<=ys.top+1e-9;v+=ys.step){var yv=Math.round(v*1e6)/1e6;
  s.appendChild(el("line",{x1:ml,x2:ml+pw,y1:Y(yv),y2:Y(yv),stroke:yv?"#e8eaed":"#b9bec4","stroke-width":yv?1:1.5}));
  s.appendChild(el("text",{x:ml-8,y:Y(yv)+4,"text-anchor":"end","font-size":10.5,fill:yv?"#80868b":"#5f6368"},[tx(yv)]))}
 s.appendChild(el("text",{x:ml-8,y:mt-5,"text-anchor":"end","font-size":10,"font-weight":700,fill:"#80868b"},[tx("count")]));
 for(var xv=0;xv<=xs.top+1e-9;xv+=xs.step){var q=Math.round(xv*1e6)/1e6;
  s.appendChild(el("text",{x:X(q),y:mt+ph+16,"text-anchor":"middle","font-size":10.5,fill:"#80868b"},[tx((q%1?q.toFixed(1):q)+"h")]))}
 s.appendChild(el("text",{x:ml,y:mt+ph+30,"font-size":10,"font-weight":700,fill:"#80868b"},[tx("productive audit-hours →")]));
 rows.forEach(function(r){var m=r[kind],c=HUE[r.backend]||HUE.codex;
  if(r.condition!=="harness"){ // single-shot control: one point where it stopped
   if(!m.accepted)return;var x=X(r.wall_h||.4),y=Y(m.accepted);
   s.appendChild(el("polygon",{points:[[x-6,y-6],[x-6,y+6],[x+6,y]].map(function(p){return p.join(",")}).join(" "),
    fill:"#fff",stroke:c,"stroke-width":2,"stroke-linejoin":"round"}));
   s.appendChild(el("text",{x:x+10,y:y+4,"font-size":10.5,fill:"#5f6368"},[tx(m.accepted)]));return}
  var pts=steps(m.accepted_times||[]);
  if(!pts.length)return;
  var end=pts[pts.length-1];
  s.appendChild(el("polygon",{points:pts.map(function(p){return X(p[0]).toFixed(2)+","+Y(p[1]).toFixed(2)})
    .concat([X(end[0]).toFixed(2)+","+Y(0),X(0)+","+Y(0)]).join(" "),fill:c,"fill-opacity":".10"}));
  s.appendChild(el("path",{d:path(pts,X,Y),fill:"none",stroke:c,"stroke-width":2.5,"stroke-linejoin":"round","stroke-linecap":"round"}));
  var ex=X(end[0]);
  s.appendChild(el("polygon",{points:[[ex,Y(end[1])-5.5],[ex+5.5,Y(end[1])],[ex,Y(end[1])+5.5],[ex-5.5,Y(end[1])]]
    .map(function(p){return p.join(",")}).join(" "),fill:c,stroke:"#fff","stroke-width":2}));
  s.appendChild(el("text",{x:ex+10,y:Y(end[1])+4,"font-size":11.5,"font-weight":700,fill:"#202124"},[tx(m.accepted)]))});
 if(chips.some(function(r){return r[kind].approx_timing})){
  s.appendChild(el("text",{x:ml+pw,y:mt+13,"text-anchor":"end","font-size":9.5,
   "font-style":"italic",fill:"#9aa0a6"},
   [tx("timing approximate — one or more discovery times unavailable")]))}
 if(rows.length){var st=mt+ph+xa;
  s.appendChild(el("text",{x:ml,y:st+8,"font-size":9.5,"font-weight":700,fill:"#9aa0a6"},
   [tx("REJECTED BY THE GATE — clustered where possible, shared scale 0–"+maxR)]));
  rows.forEach(function(r,i){var m=r[kind],c=HUE[r.backend]||HUE.codex;
   var top=st+16+i*22,base=top+14,hg=12,Ys=function(v){return base-(v/maxR)*hg};
   s.appendChild(el("line",{x1:ml,x2:ml+pw,y1:base,y2:base,stroke:"#e8eaed","stroke-width":1}));
   var rt=(m.rejected_times||[]),rp=steps(rt);
   if(rp.length){s.appendChild(el("polygon",{points:rp.map(function(p){return X(p[0]).toFixed(2)+","+Ys(p[1]).toFixed(2)})
     .concat([X(rp[rp.length-1][0]).toFixed(2)+","+base,X(0)+","+base]).join(" "),fill:c,"fill-opacity":".28"}));
    s.appendChild(el("path",{d:path(rp,X,Ys),fill:"none",stroke:c,"stroke-width":1.25,"stroke-opacity":".9"}))}
   s.appendChild(el("circle",{cx:ml-10,cy:base-hg/2,r:3,fill:c}));
   s.appendChild(el("text",{x:ml+pw+8,y:base+3,"font-size":10.5,"font-weight":700,fill:"#5f6368"},[tx((m.rejected_upper_bound?"≤ ":"")+m.rejected)]))})}
 host.appendChild(s)}
var host=document.getElementById("ttd-rows");
D.target_order.forEach(function(tg){
 var rows=D.series.filter(function(s){return s.target===tg});
 if(!rows.length)return;
 var vers={},reps=0;rows.forEach(function(r){vers[r.version]=1;if(r.condition==="harness")reps=Math.max(reps,r.replicates)});
 var sec=document.createElement("section");sec.className="row";
 sec.innerHTML='<div class="rh"><h3>'+tg+' <span class="sha">'+(D.targets[tg]||"")+'</span></h3>'+
  '<span class="meta">harness '+Object.keys(vers).join(" · ")+(reps?" · "+reps+" replicate"+(reps>1?"s":"")+" pooled":"")+'</span></div>';
 var g=document.createElement("div");g.className="grid";
 [["find","Security findings"],["crash","Security crashes"]].forEach(function(kk){
  var p=document.createElement("div");p.className="panel";
  var t=document.createElement("div");t.className="pt";t.textContent=kk[1];p.appendChild(t);
  panel(p,tg,kk[0],rows);g.appendChild(p)});
 sec.appendChild(g);host.appendChild(sec)});
})();
"""


def render(data: dict) -> str:
    """Self-contained fragment: no external assets, safe to inline in the page."""
    if not data.get("series"):
        return ""
    payload = json.dumps(data, separators=(",", ":")).replace("<", "\\u003c")
    return (
        "<style>" + _CSS + "</style>\n"
        '<section class="ttd">\n<p class="kick">Time to discovery</p>\n'
        "<h2>What each backend found, and what survived the gate</h2>\n"
        + _KEY
        + '<div id="ttd-rows"></div>\n</section>\n'
        '<script type="application/json" id="ttd-data">' + payload + "</script>\n"
        "<script>" + _JS + "</script>\n"
    )


def inject(html: str, bench_root: Path) -> str:
    """Place the graph directly after the results table it visualises."""
    fragment = render(build(bench_root))
    if not fragment:
        return html
    marker = "</table>\n</div>\n"
    index = html.find(marker)
    if index < 0:
        return html
    index += len(marker)
    return html[:index] + fragment + html[index:]
