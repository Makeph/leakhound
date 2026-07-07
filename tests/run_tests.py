#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(cmd, **kwargs):
    return subprocess.run(
        cmd, text=True, encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs
    )


def compiler_available(name):
    return shutil.which(name) is not None


def build_binary():
    env_bin = os.environ.get("LEAKHOUND_BIN")
    if env_bin:
        path = Path(env_bin)
        if not path.exists():
            raise AssertionError(f"LEAKHOUND_BIN does not exist: {path}")
        return path

    exe_name = "leakhound.exe" if os.name == "nt" else "leakhound"
    direct_exe = ROOT / exe_name
    if direct_exe.exists():
        return direct_exe

    build_dir = ROOT / "build" / "tests"
    build_dir.mkdir(parents=True, exist_ok=True)

    if compiler_available("cmake"):
        cfg = run(["cmake", "-S", str(ROOT), "-B", str(build_dir)])
        if cfg.returncode == 0:
            bld = run(["cmake", "--build", str(build_dir), "--config", "Release"])
            if bld.returncode == 0:
                candidates = [
                    build_dir / exe_name,
                    build_dir / "Release" / exe_name,
                    build_dir / "Debug" / exe_name,
                ]
                for candidate in candidates:
                    if candidate.exists():
                        return candidate
            else:
                raise AssertionError(bld.stderr or bld.stdout)
        else:
            raise AssertionError(cfg.stderr or cfg.stdout)

    if os.name == "nt" and compiler_available("cl"):
        out = build_dir / "leakhound.exe"
        cmd = [
            "cl",
            "/std:c++17",
            "/O2",
            "/W4",
            "/EHsc",
            str(ROOT / "src" / "leakhound.cpp"),
            f"/Fe:{out}",
        ]
        result = run(cmd, cwd=ROOT)
        if result.returncode != 0:
            raise AssertionError(result.stderr or result.stdout)
        return out

    for compiler in ("c++", "g++", "clang++"):
        if compiler_available(compiler):
            out = build_dir / "leakhound"
            cmd = [
                compiler,
                "-std=c++17",
                "-O2",
                "-Wall",
                "-Wextra",
                str(ROOT / "src" / "leakhound.cpp"),
                "-o",
                str(out),
            ]
            result = run(cmd, cwd=ROOT)
            if result.returncode != 0:
                raise AssertionError(result.stderr or result.stdout)
            return out

    raise AssertionError("no leakhound binary or C++17 compiler found; set LEAKHOUND_BIN")


def write_text(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def make_fixture(root):
    scan = root / "scan"
    scan.mkdir()
    write_text(
        scan / "secrets.txt",
        "\n".join(
            [
                "const aws = 'AKIA1234567890ABCDEF';",
                "password = \"CorrectHorseBattery99\"",
                "api_key = 'sk_live_4eC39HqLyjWDarjtT1zd'",
                "token = \"example_placeholder_value\"",
                "random = aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW",
                "",
            ]
        ),
    )
    write_text(
        scan / "package-lock.json",
        "integrity sha512-aB3dE5fG7hI9jK1lM2nO4pQ6rS8tU0vW\n",
    )
    write_text(scan / "node_modules" / "ignored.js", "AKIAABCDEFGHIJKLMNOP\n")
    (scan / "binary.bin").write_bytes(b"\x00AKIA1234567890ABCDEF\n")
    return scan


def assert_equal(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: expected {expected!r}, got {actual!r}")


def test_json_scan(binary):
    with tempfile.TemporaryDirectory() as tmp:
        scan = make_fixture(Path(tmp))
        result = run([str(binary), "--json", str(scan)])
        assert_equal(result.returncode, 1, "json scan exit")
        payload = json.loads(result.stdout)
        findings = payload["findings"]
        rules = [item["rule"] for item in findings]
        assert_equal(rules.count("aws-access-key"), 1, "aws finding count")
        assert_equal(rules.count("stripe-live-key"), 1, "stripe finding count")
        # the stripe value sits in an api_key assignment: reported once, under
        # the specific rule, not duplicated by generic-assignment
        assert_equal(rules.count("generic-assignment"), 1, "generic finding count")
        assert_equal(rules.count("high-entropy-token"), 1, "entropy finding count")
        assert "example_placeholder_value" not in result.stdout
        assert "AKIA12\u2026CDEF" in result.stdout
        assert payload["stats"]["files_skipped"] >= 1
        assert payload["stats"]["findings_high"] == 2
        assert payload["stats"]["findings_medium"] == 1
        assert payload["stats"]["findings_low"] == 1


def test_no_entropy_and_quiet(binary):
    with tempfile.TemporaryDirectory() as tmp:
        scan = make_fixture(Path(tmp))
        result = run([str(binary), "--no-entropy", "--quiet", str(scan)])
        assert_equal(result.returncode, 1, "no entropy exit")
        assert "high-entropy-token" not in result.stdout
        assert "aws-access-key" not in result.stdout
        assert "Summary:" in result.stdout
        assert "LOW=0" in result.stdout


def test_clean_and_usage_exit_codes(binary):
    with tempfile.TemporaryDirectory() as tmp:
        clean = Path(tmp) / "clean.txt"
        write_text(clean, "hello world\n")
        ok = run([str(binary), str(clean)])
        assert_equal(ok.returncode, 0, "clean exit")

        missing = run([str(binary), str(Path(tmp) / "missing.txt")])
        assert_equal(missing.returncode, 2, "missing path exit")

        usage = run([str(binary)])
        assert_equal(usage.returncode, 2, "usage exit")


def test_max_size_skip(binary):
    with tempfile.TemporaryDirectory() as tmp:
        large = Path(tmp) / "large.txt"
        write_text(large, "AKIA1234567890ABCDEF\n")
        result = run([str(binary), "--json", "--max-size", "3", str(large)])
        assert_equal(result.returncode, 0, "max size skip exit")
        payload = json.loads(result.stdout)
        assert_equal(len(payload["findings"]), 0, "max size findings")
        assert_equal(payload["stats"]["files_skipped"], 1, "max size skipped")


def main():
    binary = build_binary()
    test_json_scan(binary)
    test_no_entropy_and_quiet(binary)
    test_clean_and_usage_exit_codes(binary)
    test_max_size_skip(binary)
    print("all tests passed")


if __name__ == "__main__":
    main()
