# leakhound — spec

Fast credential/secret scanner. Single static binary, C++17, **zero external
dependencies** (standard library only). Target compilers: MSVC 2022 (`cl`) and
g++/clang. Must compile warning-clean at `/W4` / `-Wall -Wextra`.

## CLI

```
leakhound [options] <path>...
  --json           machine-readable output (one JSON object, findings array)
  --no-entropy     disable entropy heuristics (pattern rules only)
  --max-size N     skip files larger than N bytes (default 2 MiB)
  --quiet          suppress per-finding lines, print summary only
  -h, --help       usage
```

- Paths may be files or directories (recursed).
- Exit code: 0 = no findings, 1 = findings, 2 = usage/IO error.

## Scanning behavior

- Skip directories named: `.git`, `node_modules`, `vendor`, `dist`, `build`,
  `target`, `__pycache__`, `.venv`, `venv`.
- Skip binary files: if the first 4096 bytes contain a NUL byte.
- Read files in one shot (they are capped by --max-size).
- Track line numbers for findings.

## Detection rules (pattern tier — high confidence)

Implement with hand-rolled matchers or std::regex, whichever is cleaner, but
each rule gets an id, a human name, and a severity (HIGH/MEDIUM):

1. `aws-access-key`   — `AKIA[0-9A-Z]{16}` (HIGH)
2. `github-token`     — `gh[pousr]_[A-Za-z0-9]{36,}` (HIGH)
3. `slack-token`      — `xox[baprs]-[A-Za-z0-9-]{10,}` (HIGH)
4. `stripe-live-key`  — `sk_live_[A-Za-z0-9]{16,}` (HIGH)
5. `private-key-pem`  — line containing `-----BEGIN` + (`RSA`|`EC`|`OPENSSH`|`DSA`|`PGP`)? + `PRIVATE KEY` (HIGH)
6. `google-api-key`   — `AIza[0-9A-Za-z_-]{35}` (HIGH)
7. `npm-token`        — `npm_[A-Za-z0-9]{36}` (HIGH)
8. `jwt`              — `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}` (MEDIUM)
9. `generic-assignment` — key names (`api_key`, `apikey`, `secret`, `token`,
   `passwd`, `password`, `auth`) followed by `=` or `:` and a quoted literal
   of 12+ chars that is not an obvious placeholder (reject values containing
   `example`, `changeme`, `placeholder`, `xxxx`, `your_`, `<`, `>`, `${`, `%s`) (MEDIUM)

## Entropy tier (heuristic — LOW severity)

- Tokenize each line into runs of `[A-Za-z0-9+/=_-]` of length 24–128.
- Shannon entropy over the token's bytes; flag when > 4.5 bits/char and the
  token contains at least one digit and mixed case (cuts English-word noise).
- Skip tokens already covered by a pattern finding on the same line.
- Skip lines that look like lockfile/hash noise: filename ends in
  `.lock`, `-lock.json`, `.sum`, or line contains `integrity` or `sha512-`.

## Output

Console (default): `SEVERITY rule-id path:line  <match, redacted>`.
Redaction: show first 6 and last 4 chars of the match, `…` between.
Summary line: files scanned, files skipped, findings by severity, wall time.
JSON mode: `{"version":1,"findings":[{"rule","severity","path","line","redacted"}...],"stats":{...}}`.
No color codes in --json mode. Console colors via ANSI only when stdout is a
TTY (use `_isatty(_fileno(stdout))` on Windows, `isatty(1)` elsewhere; enable
VT processing on Windows with SetConsoleMode).

## Layout

```
src/leakhound.cpp     (single translation unit is fine; keep functions small)
tests/run_tests.py    (python3: builds fixtures in a temp dir, runs the binary,
                       asserts exit codes, finding counts, JSON validity,
                       redaction, placeholder rejection, binary/dir skipping)
CMakeLists.txt        (minimal, C++17, /W4 or -Wall -Wextra)
build.bat             (MSVC one-liner fallback: cl /std:c++17 /O2 /W4 /EHsc src\leakhound.cpp /Fe:leakhound.exe)
README.md             (usage, rules table, exit codes, build instructions)
.gitignore            (build artifacts)
```

## Non-goals

Do not add: config files, network calls, git history scanning, multithreading
(keep it simple; it is IO-bound at typical repo sizes).
