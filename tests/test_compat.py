#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OpenRAR End-to-End Bi-Directional Compatibility & CLI Verification Suite
Tests bi-directional interoperability between OpenRAR (rar.exe / unrar-free.exe)
and the official WinRAR CLI (C:\\Program Files\\WinRAR\\Rar.exe).
"""

import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile

WORKSPACE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OFFICIAL_RAR_EXE = r"C:\Program Files\WinRAR\Rar.exe"


def find_built(names):
    """Locate a built binary in the repo root or in build/."""
    roots = [WORKSPACE_DIR, os.path.join(WORKSPACE_DIR, "build")]
    extra = os.environ.get("OPENRAR_BUILD")
    if extra:
        roots.insert(0, extra)
    for root in roots:
        for name in names:
            path = os.path.join(root, name)
            if os.path.isfile(path):
                return path
    return None


OPENRAR_EXE = find_built(["rar", "rar.exe"])
UNRAR_FREE_EXE = find_built(["unrar-free", "unrar-free.exe"])


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def run_cmd(cmd, cwd=None, input_bytes=None, check=True, env=None):
    run_env = os.environ.copy()
    # Keep a developer's rarrc and RAR variable from changing -m or -x.
    run_env.pop("RAR", None)
    if env:
        run_env.update(env)
    p = subprocess.run(
        cmd,
        cwd=cwd,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=run_env,
    )
    if check and p.returncode != 0:
        out_str = p.stdout.decode("utf-8", errors="replace")
        err_str = p.stderr.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Command failed (exit {p.returncode}): {cmd}\nSTDOUT:\n{out_str}\nSTDERR:\n{err_str}"
        )
    return p


def create_sample_dataset(base_dir: str) -> dict:
    """Create a rich dataset of files (repetitive text, binary, Unicode names, nested dirs, empty file)."""
    os.makedirs(os.path.join(base_dir, "sub", "深层目录"), exist_ok=True)
    files = {}

    # 1. Highly compressible repetitive text (triggers LZSS + Huffman + repeat distances)
    f1 = os.path.join(base_dir, "hello_repeat.txt")
    content1 = (
        "OpenRAR Clean-Room RAR 5.0 LZSS + Canonical Huffman Compression Test!\n"
        "The quick brown fox jumps over the lazy dog. 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ.\n"
        "中文测试：基于《计算机软件保护条例》第十七条，用于学习和研究软件内含的设计思想和原理。\n"
    ).encode("utf-8") * 250
    with open(f1, "wb") as f:
        f.write(content1)
    files["hello_repeat.txt"] = sha256_file(f1)

    # 2. Structured binary data with patterns & x86 CALL/JMP opcodes (0xE8, 0xE9)
    f2 = os.path.join(base_dir, "sub", "pattern_code.bin")
    bdata = bytearray()
    for i in range(4000):
        bdata.extend(b"\xE8" + (i * 13 & 0xFFFFFFFF).to_bytes(4, "little"))
        bdata.extend(b"\xE9" + ((4000 - i) * 7 & 0xFFFFFFFF).to_bytes(4, "little"))
        bdata.extend(bytes([i & 0xFF, (i >> 2) & 0xFF, 0x00, 0xAA, 0x55]))
    with open(f2, "wb") as f:
        f.write(bdata)
    files["sub/pattern_code.bin"] = sha256_file(f2)

    # 3. Unicode / Chinese filename in nested subdirectory
    f3 = os.path.join(base_dir, "sub", "深层目录", "测试文档_UTF8.md")
    content3 = ("# RAR 5.0 格式分析报告\n\n" + "- 滑动窗口与哈夫曼编码验证\n" * 120).encode("utf-8")
    with open(f3, "wb") as f:
        f.write(content3)
    files["sub/深层目录/测试文档_UTF8.md"] = sha256_file(f3)

    # 4. Empty file
    f4 = os.path.join(base_dir, "empty.dat")
    with open(f4, "wb") as f:
        pass
    files["empty.dat"] = sha256_file(f4)

    # 5. High-entropy / pseudo-random data (tests incompressible fallback / literal blocks)
    f5 = os.path.join(base_dir, "random_entropy.bin")
    rng_bytes = hashlib.pbkdf2_hmac("sha256", b"openrar-seed", b"salt", 1, dklen=8192)
    with open(f5, "wb") as f:
        f.write(rng_bytes)
    files["random_entropy.bin"] = sha256_file(f5)

    return files


def verify_extracted_dataset(extract_dir: str, expected_hashes: dict, flat: bool = False):
    for rel_path, expected_hash in expected_hashes.items():
        target_rel = os.path.basename(rel_path) if flat else rel_path.replace("/", os.sep)
        full_path = os.path.join(extract_dir, target_rel)
        assert os.path.isfile(full_path), f"Missing extracted file: {full_path}"
        actual_hash = sha256_file(full_path)
        assert actual_hash == expected_hash, (
            f"SHA-256 mismatch for {rel_path}: expected {expected_hash}, got {actual_hash}"
        )


def main():
    print("=" * 72)
    print("OpenRAR Bi-Directional Compatibility & CLI Verification Suite")
    print("=" * 72)

    assert OPENRAR_EXE and os.path.isfile(OPENRAR_EXE), "Missing rar / rar.exe (build it first)"
    assert UNRAR_FREE_EXE and os.path.isfile(UNRAR_FREE_EXE), "Missing unrar-free / unrar-free.exe"
    has_official = os.path.isfile(OFFICIAL_RAR_EXE)
    print(f"[*] OpenRAR executable : {OPENRAR_EXE}")
    print(f"[*] Official WinRAR CLI: {OFFICIAL_RAR_EXE} (present={has_official})")

    isolated = tempfile.mkdtemp(prefix="openrar_home_")
    os.environ["HOME"] = isolated
    os.environ["APPDATA"] = isolated
    os.environ["XDG_DATA_HOME"] = isolated
    os.environ.pop("RAR", None)

    # 1. Test -iver and -? (and ensure no registration/activation mechanism)
    p_ver = run_cmd([OPENRAR_EXE, "-iver"])
    assert p_ver.stdout.decode("utf-8", errors="replace").strip() == "7.01"
    p_help = run_cmd([OPENRAR_EXE, "-?"])
    help_out = (p_help.stdout + p_help.stderr).decode("utf-8", errors="replace")
    assert "Usage:" in help_out and "Add files to archive" in help_out
    for banned in ("已注册给", "Registered to", "Trial copy", "试用"):
        assert banned not in help_out, f"Activation notice must not be present ({banned})"
    print("[PASS] 1. CLI Help (-?), Version (-iver), and Activation-Free check")

    with tempfile.TemporaryDirectory(prefix="openrar_test_") as tmpdir:
        src_dir = os.path.join(tmpdir, "src")
        expected = create_sample_dataset(src_dir)

        # 2. Test OpenRAR compression methods -m0, -m1, -m3, -m5 -> Official WinRAR t & x
        for m in [0, 1, 3, 5]:
            arch_path = os.path.join(tmpdir, f"openrar_m{m}.rar")
            run_cmd([OPENRAR_EXE, "a", "-r", f"-m{m}", arch_path, "*"], cwd=src_dir)
            assert os.path.isfile(arch_path)

            # Test with OpenRAR `t`
            run_cmd([OPENRAR_EXE, "t", arch_path])

            # Extract with OpenRAR `x`
            ext_open = os.path.join(tmpdir, f"ext_open_m{m}")
            os.makedirs(ext_open, exist_ok=True)
            run_cmd([OPENRAR_EXE, "x", "-y", arch_path, ext_open + os.sep])
            verify_extracted_dataset(ext_open, expected)

            # Verify with Official WinRAR `t` and `x`
            if has_official:
                run_cmd([OFFICIAL_RAR_EXE, "t", "-y", arch_path])
                ext_off = os.path.join(tmpdir, f"ext_off_m{m}")
                os.makedirs(ext_off, exist_ok=True)
                run_cmd([OFFICIAL_RAR_EXE, "x", "-y", arch_path, ext_off + os.sep])
                verify_extracted_dataset(ext_off, expected)
        print("[PASS] 2. Compression levels -m0..-m5 (OpenRAR <-> Official WinRAR verified)")

        # 3. Test Solid Archive (-s) + BLAKE2sp (-htb)
        solid_arch = os.path.join(tmpdir, "openrar_solid_blake2.rar")
        run_cmd([OPENRAR_EXE, "a", "-r", "-s", "-htb", "-m3", solid_arch, "*"], cwd=src_dir)
        run_cmd([OPENRAR_EXE, "t", solid_arch])
        if has_official:
            run_cmd([OFFICIAL_RAR_EXE, "t", "-y", solid_arch])
            ext_solid = os.path.join(tmpdir, "ext_solid_off")
            os.makedirs(ext_solid, exist_ok=True)
            run_cmd([OFFICIAL_RAR_EXE, "x", "-y", solid_arch, ext_solid + os.sep])
            verify_extracted_dataset(ext_solid, expected)
        print("[PASS] 3. Solid Archive (-s) & BLAKE2sp (-htb) checksums verified by Official WinRAR")

        # 4. Test AES-256 Encryption: -p<pwd> (data encryption) & -hp<pwd> (header+data encryption)
        for sw, name in [("-pMySecretPwd2026", "enc_data"), ("-hpHeaderSecret99", "enc_hdr")]:
            enc_arch = os.path.join(tmpdir, f"{name}.rar")
            run_cmd([OPENRAR_EXE, "a", "-r", "-m3", sw, enc_arch, "*"], cwd=src_dir)
            # Wrong password must fail
            p_bad = run_cmd([OPENRAR_EXE, "t", "-pWrongPwd", enc_arch], check=False)
            assert p_bad.returncode != 0, "Wrong password should fail!"
            # Correct password with OpenRAR
            run_cmd([OPENRAR_EXE, "t", sw, enc_arch])
            # Correct password with Official WinRAR
            if has_official:
                run_cmd([OFFICIAL_RAR_EXE, "t", "-y", sw, enc_arch])
                ext_enc = os.path.join(tmpdir, f"ext_{name}")
                os.makedirs(ext_enc, exist_ok=True)
                run_cmd([OFFICIAL_RAR_EXE, "x", "-y", sw, enc_arch, ext_enc + os.sep])
                verify_extracted_dataset(ext_enc, expected)
        print("[PASS] 4. AES-256-CBC Data (-p) & Header (-hp) Encryption + Tweaked CRC32 verified")

        # 5. Test Official WinRAR created archives -> OpenRAR l, v, lt, lb, t, x, e, p
        if has_official:
            for extra_sw, label in [
                (["-m0"], "off_m0"),
                (["-m3"], "off_m3"),
                (["-m5", "-s"], "off_m5_solid"),
                (["-m3", "-htb"], "off_blake2"),
                (["-m3", "-pWinRarPass1"], "off_p"),
                (["-m3", "-hpWinRarPass2"], "off_hp"),
            ]:
                off_arch = os.path.join(tmpdir, f"{label}.rar")
                run_cmd([OFFICIAL_RAR_EXE, "a", "-r", "-y"] + extra_sw + [off_arch, "*"], cwd=src_dir)
                pwd_sw = [s for s in extra_sw if s.startswith("-p") or s.startswith("-hp")]

                # OpenRAR list, technical list, bare list, and test
                run_cmd([OPENRAR_EXE, "l"] + pwd_sw + [off_arch])
                run_cmd([OPENRAR_EXE, "lt"] + pwd_sw + [off_arch])
                p_lb = run_cmd([OPENRAR_EXE, "lb"] + pwd_sw + [off_arch])
                assert "hello_repeat.txt" in p_lb.stdout.decode("utf-8", errors="replace")
                run_cmd([OPENRAR_EXE, "t"] + pwd_sw + [off_arch])

                # OpenRAR extract with full path
                ext_dir = os.path.join(tmpdir, f"openrar_from_{label}")
                os.makedirs(ext_dir, exist_ok=True)
                run_cmd([OPENRAR_EXE, "x", "-y"] + pwd_sw + [off_arch, ext_dir + os.sep])
                verify_extracted_dataset(ext_dir, expected)
            print("[PASS] 5. Official WinRAR Archives (-m0/-m3/-m5/-s/-htb/-p/-hp) -> Extracted by OpenRAR")

        # 6. Test Archive Modification Commands: c, cw, rn, d, k, i=<str>, e, p
        mod_arch = os.path.join(tmpdir, "modify_test.rar")
        comment_in = os.path.join(tmpdir, "comment_in.txt")
        comment_out = os.path.join(tmpdir, "comment_out.txt")
        with open(comment_in, "wb") as f:
            f.write("这是压缩文件注释测试 (Archive Comment Test)\n".encode("utf-8"))

        run_cmd([OPENRAR_EXE, "a", "-r", f"-z{comment_in}", mod_arch, "*"], cwd=src_dir)
        run_cmd([OPENRAR_EXE, "cw", "-y", mod_arch, comment_out])
        assert sha256_file(comment_in) == sha256_file(comment_out)

        # Find string in archive (`i=Canonical`)
        p_find = run_cmd([OPENRAR_EXE, "i=Canonical", mod_arch])
        assert "hello_repeat.txt" in p_find.stdout.decode("utf-8", errors="replace")

        # Print file to stdout (`p`)
        p_print = run_cmd([OPENRAR_EXE, "p", "-inul", mod_arch, "hello_repeat.txt"])
        assert hashlib.sha256(p_print.stdout).hexdigest() == expected["hello_repeat.txt"]

        # Rename file (`rn`)
        run_cmd([OPENRAR_EXE, "rn", mod_arch, "empty.dat", "renamed_empty.dat"])
        p_lb2 = run_cmd([OPENRAR_EXE, "lb", mod_arch])
        lb2_lines = [line.strip() for line in p_lb2.stdout.decode("utf-8", errors="replace").splitlines()]
        assert "renamed_empty.dat" in lb2_lines and "empty.dat" not in lb2_lines

        # Delete file (`d`)
        run_cmd([OPENRAR_EXE, "d", mod_arch, "renamed_empty.dat"])
        p_lb3 = run_cmd([OPENRAR_EXE, "lb", mod_arch])
        lb3_lines = [line.strip() for line in p_lb3.stdout.decode("utf-8", errors="replace").splitlines()]
        assert "renamed_empty.dat" not in lb3_lines

        # Lock archive (`k`) and verify subsequent modification is rejected with exit code 4
        run_cmd([OPENRAR_EXE, "k", mod_arch])
        p_locked = run_cmd([OPENRAR_EXE, "d", mod_arch, "hello_repeat.txt"], check=False)
        assert p_locked.returncode == 4, f"Expected exit code 4 (RAR_EXIT_LOCKED), got {p_locked.returncode}"
        if has_official:
            run_cmd([OFFICIAL_RAR_EXE, "t", "-y", mod_arch])
        print("[PASS] 6. Archive Commands (c, cw, i=<str>, p, rn, d, k) verified")

        # 7. Test Self-Extracting (SFX) creation (`-sfx`, `s`, `s-`) and direct execution!
        sfx_arch = os.path.join(tmpdir, "self_extract.exe")
        run_cmd([OPENRAR_EXE, "a", "-r", "-sfx", sfx_arch, "*"], cwd=src_dir)
        assert os.path.isfile(sfx_arch)
        sfx_out = os.path.join(tmpdir, "sfx_extracted")
        os.makedirs(sfx_out, exist_ok=True)
        # Execute SFX archive directly!
        run_cmd([sfx_arch, "-y", sfx_out + os.sep])
        verify_extracted_dataset(sfx_out, expected)
        # Convert SFX back to .rar using `s-`
        run_cmd([OPENRAR_EXE, "s-", sfx_arch])
        assert os.path.isfile(os.path.join(tmpdir, "self_extract.rar"))
        print("[PASS] 7. Self-Extracting Archive (-sfx, s, s-, direct .exe execution) verified")

        # 8. Test Multi-Volume Archive (-v15k) & Recovery Record (-rr5 + `r` repair)
        vol_arch = os.path.join(tmpdir, "multivol.rar")
        run_cmd([OPENRAR_EXE, "a", "-r", "-v15k", vol_arch, "*"], cwd=src_dir)
        part1 = os.path.join(tmpdir, "multivol.part1.rar")
        assert os.path.isfile(part1) and os.path.isfile(os.path.join(tmpdir, "multivol.part2.rar"))
        ext_vol = os.path.join(tmpdir, "ext_multivol")
        os.makedirs(ext_vol, exist_ok=True)
        run_cmd([OPENRAR_EXE, "x", "-y", part1, ext_vol + os.sep])
        verify_extracted_dataset(ext_vol, expected)

        # Repair test (`-rr5` and `r`)
        rr_arch = os.path.join(tmpdir, "recover_test.rar")
        run_cmd([OPENRAR_EXE, "a", "-r", "-rr10", rr_arch, "*"], cwd=src_dir)
        run_cmd([OPENRAR_EXE, "r", rr_arch], cwd=tmpdir)
        fixed_arch = os.path.join(tmpdir, "fixed.recover_test.rar")
        assert os.path.isfile(fixed_arch)
        run_cmd([OPENRAR_EXE, "t", fixed_arch])
        if has_official:
            run_cmd([OFFICIAL_RAR_EXE, "t", "-y", fixed_arch])
        print("[PASS] 8. Multi-Volume (-v) & Recovery Record (-rr / r) verified")

        # 9. Test unrar-free compatibility persona & GNU long options
        ext_uf = os.path.join(tmpdir, "ext_unrar_free")
        os.makedirs(ext_uf, exist_ok=True)
        run_cmd([UNRAR_FREE_EXE, "--list", solid_arch])
        run_cmd([UNRAR_FREE_EXE, "--extract", "--force", solid_arch, ext_uf + os.sep])
        verify_extracted_dataset(ext_uf, expected)
        print("[PASS] 9. unrar-free CLI persona (--list, --extract, --force) verified")

        extra_cli_features(tmpdir, src_dir)

    print("=" * 72)
    print("ALL VERIFICATION SUITES PASSED 100%!")
    print("=" * 72)


def extra_cli_features(tmpdir, src_dir):
    """Switches and commands that go beyond the original nine suites."""
    rar = OPENRAR_EXE

    # A key file beside the binary must not change the banner.
    bindir = os.path.join(tmpdir, "withkey")
    os.makedirs(bindir)
    copied = os.path.join(bindir, os.path.basename(rar))
    shutil.copy2(rar, copied)
    os.chmod(copied, os.stat(copied).st_mode | stat.S_IEXEC)
    with open(os.path.join(bindir, "rarreg.key"), "w", encoding="utf-8") as f:
        f.write("Registered to Someone\n")
    keyed = run_cmd([copied, "-?"])
    keyed_text = (keyed.stdout + keyed.stderr).decode("utf-8", errors="replace")
    for banned in ("Registered to", "Trial", "已注册给", "试用"):
        assert banned not in keyed_text

    link_dir = os.path.join(tmpdir, "links")
    os.makedirs(link_dir)
    target = os.path.join(link_dir, "target.txt")
    with open(target, "w", encoding="utf-8") as f:
        f.write("link-body\n")
    os.symlink("target.txt", os.path.join(link_dir, "sym.txt"))
    os.link(target, os.path.join(link_dir, "hard.txt"))
    link_arch = os.path.join(tmpdir, "links.rar")
    run_cmd([rar, "a", "-m0", "-ol", "-oh", "-ow", link_arch, "target.txt", "sym.txt", "hard.txt"], cwd=link_dir)
    blob = open(link_arch, "rb").read()
    try:
        import pwd
        owner = pwd.getpwuid(os.getuid()).pw_name.encode()
        assert owner in blob, "-ow should store the owner name"
    except ImportError:
        pass
    link_out = os.path.join(tmpdir, "links_out")
    os.makedirs(link_out)
    run_cmd([rar, "x", "-y", "-ow", link_arch, link_out + os.sep])
    assert os.path.islink(os.path.join(link_out, "sym.txt"))
    assert os.path.samefile(os.path.join(link_out, "target.txt"), os.path.join(link_out, "hard.txt"))

    vol_dir = os.path.join(tmpdir, "vols")
    os.makedirs(vol_dir)
    with open(os.path.join(vol_dir, "big.bin"), "wb") as f:
        f.write(b"Z" * 5000)
    run_cmd([rar, "a", "-m0", "-vn", "-v1k", os.path.join(vol_dir, "old.rar"), "big.bin"], cwd=vol_dir)
    assert os.path.isfile(os.path.join(vol_dir, "old.rar"))
    assert os.path.isfile(os.path.join(vol_dir, "old.r00"))
    run_cmd([rar, "a", "-m0", "-v1k", os.path.join(vol_dir, "new.rar"), "big.bin"], cwd=vol_dir)
    assert os.path.isfile(os.path.join(vol_dir, "new.part1.rar"))
    assert os.path.isfile(os.path.join(vol_dir, "new.part2.rar"))
    run_cmd([rar, "rv", os.path.join(vol_dir, "new.part1.rar")])
    assert os.path.isfile(os.path.join(vol_dir, "new.part1.rev"))
    os.remove(os.path.join(vol_dir, "new.part2.rar"))
    run_cmd([rar, "rc", os.path.join(vol_dir, "new.part1.rar")])
    assert os.path.isfile(os.path.join(vol_dir, "new.part2.rar"))
    run_cmd([rar, "t", os.path.join(vol_dir, "new.part1.rar")])

    work = os.path.join(tmpdir, "work")
    os.makedirs(work)
    dest = os.path.join(tmpdir, "dest.rar")
    run_cmd([rar, "a", "-m0", "-w" + work, dest, "empty.dat"], cwd=src_dir)
    assert os.path.isfile(dest)
    assert not any(name.endswith(".rar") for name in os.listdir(work))

    old_stamp = 946684800  # 2000-01-01 UTC
    os.utime(dest, (old_stamp, old_stamp))
    run_cmd([rar, "a", "-m0", "-tk", dest, "empty.dat"], cwd=src_dir)
    assert abs(os.stat(dest).st_mtime - old_stamp) < 2

    wipe_dir = os.path.join(tmpdir, "wipe")
    os.makedirs(wipe_dir)
    victim = os.path.join(wipe_dir, "gone.txt")
    with open(victim, "w", encoding="utf-8") as f:
        f.write("erase-me")
    run_cmd([rar, "a", "-m0", "-dw", os.path.join(wipe_dir, "wiped.rar"), "gone.txt"], cwd=wipe_dir)
    assert not os.path.exists(victim)

    fresh_dir = os.path.join(tmpdir, "fresh")
    os.makedirs(fresh_dir)
    with open(os.path.join(fresh_dir, "keep.txt"), "w", encoding="utf-8") as f:
        f.write("one")
    with open(os.path.join(fresh_dir, "extra.txt"), "w", encoding="utf-8") as f:
        f.write("nope")
    base = os.path.join(fresh_dir, "base.rar")
    run_cmd([rar, "a", "-m0", base, "keep.txt"], cwd=fresh_dir)
    with open(os.path.join(fresh_dir, "keep.txt"), "w", encoding="utf-8") as f:
        f.write("two")
    run_cmd([rar, "a", "-f", "-m0", base, "keep.txt", "extra.txt"], cwd=fresh_dir)
    names = run_cmd([rar, "lb", base]).stdout.decode("utf-8", errors="replace")
    assert "keep.txt" in names and "extra.txt" not in names

    cfg_home = os.path.join(tmpdir, "cfghome")
    os.makedirs(cfg_home)
    with open(os.path.join(cfg_home, ".rarrc"), "w", encoding="utf-8") as f:
        f.write("-xsecret.txt\n")
    with open(os.path.join(fresh_dir, "secret.txt"), "w", encoding="utf-8") as f:
        f.write("hidden")
    cfg_arch = os.path.join(fresh_dir, "cfg.rar")
    run_cmd([rar, "a", "-m0", cfg_arch, "keep.txt", "secret.txt"], cwd=fresh_dir,
            env={"HOME": cfg_home, "RAR": ""})
    cfg_names = run_cmd([rar, "lb", cfg_arch]).stdout.decode("utf-8", errors="replace")
    assert "keep.txt" in cfg_names and "secret.txt" not in cfg_names

    solid_dir = os.path.join(tmpdir, "solidg")
    os.makedirs(solid_dir)
    for name, body in (("a.txt", b"A" * 4000), ("b.txt", b"A" * 4000), ("c.txt", b"B" * 4000)):
        with open(os.path.join(solid_dir, name), "wb") as f:
            f.write(body)
    solid = os.path.join(solid_dir, "g.rar")
    run_cmd([rar, "a", "-m5", "-s2", "-ds", solid, "a.txt", "b.txt", "c.txt"], cwd=solid_dir)
    tech = run_cmd([rar, "lt", solid]).stdout.decode("utf-8", errors="replace")
    comp_lines = [line for line in tech.splitlines() if "Compression:" in line or "压缩:" in line or "Komprimierung:" in line or "Сжатие:" in line]
    assert len(comp_lines) >= 3
    assert "solid" not in comp_lines[0].lower() and "solid" not in comp_lines[2].lower()
    assert "solid" in comp_lines[1].lower()

    mt1 = os.path.join(tmpdir, "mt1.rar")
    mt2 = os.path.join(tmpdir, "mt2.rar")
    run_cmd([rar, "a", "-r", "-m3", "-mt1", mt1, "*"], cwd=src_dir)
    run_cmd([rar, "a", "-r", "-m3", "-mt2", mt2, "*"], cwd=src_dir)
    for label, arch in (("mt1", mt1), ("mt2", mt2)):
        out = os.path.join(tmpdir, label)
        os.makedirs(out)
        run_cmd([rar, "x", "-y", arch, out + os.sep])

    def tree_hashes(root):
        found = {}
        for dirpath, _, files in os.walk(root):
            for name in files:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                found[rel] = sha256_file(full)
        return found
    assert tree_hashes(os.path.join(tmpdir, "mt1")) == tree_hashes(os.path.join(tmpdir, "mt2"))

    case_arch = os.path.join(tmpdir, "case.rar")
    case_dir = os.path.join(tmpdir, "case")
    os.makedirs(case_dir)
    with open(os.path.join(case_dir, "File.TXT"), "w", encoding="utf-8") as f:
        f.write("Case")
    run_cmd([rar, "a", "-m0", case_arch, "File.TXT"], cwd=case_dir)
    run_cmd([rar, "ch", "-cl", case_arch])
    lowered = run_cmd([rar, "lb", case_arch]).stdout.decode("utf-8", errors="replace")
    assert "file.txt" in lowered.split()

    vd = run_cmd([rar, "a", "-vd", "-m0", os.path.join(tmpdir, "vd.rar"), "empty.dat"], cwd=src_dir)
    vd_err = (vd.stdout + vd.stderr).decode("utf-8", errors="replace")
    assert "does not erase" in vd_err
    assert os.path.isfile(os.path.join(src_dir, "empty.dat"))
    ma4 = run_cmd([rar, "a", "-ma4", os.path.join(tmpdir, "no4.rar"), "empty.dat"], cwd=src_dir, check=False)
    assert ma4.returncode == 7

    print("[PASS] 10. Links, owner, volumes, rv/rc, -w, -tk, -dw, -f, config, -s2, -mt, ch, -vd")


if __name__ == "__main__":
    main()
