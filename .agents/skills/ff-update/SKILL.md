---
name: ff-update
description: "Update the Firefox mozilla-unified source tree to latest tip. Use before rebuilding Firefox sanitizer builds or starting a fresh audit on current upstream source."
---

# Update Firefox Source

Pull and update `targets/firefox` to the latest mozilla-unified tip.

## Steps

### 1. Pull and update
```bash
hg -R targets/firefox pull -u
```

### 2. Handle expected local patch conflicts
If `hg pull -u` aborts with conflicting changes, inspect the modified files:
```bash
hg -R targets/firefox status -mard
```

The expected local compatibility patches are:
- `build/moz.configure/toolchain.configure`
- `third_party/zucchini/chromium/components/zucchini/suffix_array_unittest.cc`

If those are the only modified tracked files, shelve, update, and unshelve:
```bash
hg -R targets/firefox shelve --name local-patches
hg -R targets/firefox update
hg -R targets/firefox unshelve --name local-patches
```

If `hg status -mard` shows other tracked file changes, or if unshelving
reports merge conflicts, stop and report the conflict. Do not force-resolve.

### 3. Verify the revision
```bash
hg -R targets/firefox log -l 1 --template "{node|short} {date|isodate} {desc|firstline}\n"
```

## After Updating

Firefox sanitizer builds are stale after a source update. Use `ff-bsan` with
`asan`, `ubsan`, `msan`, `coverage`, or `all` to rebuild the needed
configurations.
