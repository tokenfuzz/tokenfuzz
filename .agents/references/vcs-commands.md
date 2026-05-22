# VCS Abstraction

Detect at session start: `test -d .hg && echo "hg" || echo "git"`

| Operation | git | hg |
|-----------|-----|-----|
| Current revision | `git log --oneline -1` | `hg log -l 1 --template "{node\|short} {desc\|firstline}\n"` |
| Security history | `git log --all --oneline --grep="CVE\|sec-" -- <dir>` | `hg log -k "CVE" -k "sec-" <dir> --template "{node\|short} {desc\|firstline}\n"` |
| Recent changes | `git log --since="6 months ago" --oneline -- <dir>` | `hg log -d "-180" <dir> --template "{node\|short} {desc\|firstline}\n"` |
| Show commit | `bin/show-patch COMMIT [path/file.cpp]` (`--unified=10` default; widen with `PATCH_CONTEXT=80` or pass `--unified=N`) | `hg diff -c REV path/file.cpp` |
| File at revision | `git show COMMIT:path/file.cpp` | `hg cat -r REV path/file.cpp` |
| Search commits | `git log --all --grep='Bug NNNNN'` | `hg log -k "Bug NNNNN"` |
| Symbol history | `git log -S"FuncName" -- <file>` | `hg log -k "FuncName" <file>` |
| Blame | `git blame file.cpp` | `hg annotate file.cpp` |
| Save proposed-patch diff | `git -C <target_root> diff -- <file> > $FIND_DIR/patch.diff` | `hg -R <target_root> diff <file> > $FIND_DIR/patch.diff` |
| Revert working tree | `git -C <target_root> checkout -- <file>` | `hg -R <target_root> revert <file>` |
