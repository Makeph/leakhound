# leakhound

`leakhound` is a fast local credential and secret scanner. It is a single C++17
binary with no external dependencies.

## Build

With CMake:

```sh
cmake -S . -B build
cmake --build build --config Release
```

On Windows with the MSVC command prompt:

```bat
build.bat
```

The batch file runs:

```bat
cl /std:c++17 /O2 /W4 /EHsc src\leakhound.cpp /Fe:leakhound.exe
```

## Usage

```text
leakhound [options] <path>...
  --json           machine-readable output (one JSON object, findings array)
  --no-entropy     disable entropy heuristics (pattern rules only)
  --max-size N     skip files larger than N bytes (default 2 MiB)
  --quiet          suppress per-finding lines, print summary only
  -h, --help       usage
```

Paths may be files or directories. Directories are scanned recursively, while
common generated or dependency directories such as `.git`, `node_modules`,
`vendor`, `dist`, `build`, `target`, `__pycache__`, `.venv`, and `venv` are
skipped.

Default output:

```text
HIGH aws-access-key path/to/file.txt:12  AKIA12...CDEF
Summary: files scanned=4, files skipped=1, HIGH=1, MEDIUM=0, LOW=0, wall time=3ms
```

JSON output:

```sh
leakhound --json .
```

## Rules

| Rule ID | Severity | Pattern |
| --- | --- | --- |
| `aws-access-key` | HIGH | `AKIA[0-9A-Z]{16}` |
| `github-token` | HIGH | `gh[pousr]_[A-Za-z0-9]{36,}` |
| `slack-token` | HIGH | `xox[baprs]-[A-Za-z0-9-]{10,}` |
| `stripe-live-key` | HIGH | `sk_live_[A-Za-z0-9]{16,}` |
| `private-key-pem` | HIGH | PEM private key header lines |
| `google-api-key` | HIGH | `AIza[0-9A-Za-z_-]{35}` |
| `npm-token` | HIGH | `npm_[A-Za-z0-9]{36}` |
| `jwt` | MEDIUM | JWT-shaped three-part token |
| `generic-assignment` | MEDIUM | Secret-like key assigned to a quoted non-placeholder value |
| `high-entropy-token` | LOW | High-entropy mixed-case token heuristic |

The entropy heuristic tokenizes each line into runs of
`[A-Za-z0-9+/=_-]` from 24 to 128 characters, then flags tokens with Shannon
entropy greater than 4.5 bits per character that contain at least one digit and
mixed case. Use `--no-entropy` to disable this tier.

## Exit Codes

| Code | Meaning |
| --- | --- |
| 0 | Scan completed with no findings |
| 1 | Scan completed with findings |
| 2 | Usage or IO error |

## Tests

```sh
python tests/run_tests.py
```

The test runner builds temporary fixtures, runs the scanner, checks exit codes,
validates JSON output, verifies redaction and placeholder rejection, and checks
binary, directory, and max-size skipping. If no compiler is available, set
`LEAKHOUND_BIN` to an existing scanner binary.
