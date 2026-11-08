#!/usr/bin/env python3
"""
Giao diện dòng lệnh (CLI) cho chương trình RSA.

Chạy không tham số -> menu tương tác:     python cli.py
Hoặc dùng lệnh con (tiện cho demo / script):
    python cli.py toy --preset lop                      # phiên bản thu nhỏ, in từng bước
    python cli.py toy --p 61 --q 53 --e 17 --m 65 --text HELLO
    python cli.py slide --name all                      # chạy lại các BTVD thuật toán nền trong slide
    python cli.py exercise --name all                   # chạy Bài tập luyện tập Chương 3, đối chiếu đáp án gợi ý
    python cli.py sign --p 13 --q 23 --e 17 --m 42      # chữ ký RSA: ký rồi kiểm chứng (thêm --s để kiểm một cặp cho trước)
    python cli.py inverse --a 173 --n 1024              # bảng nghịch đảo; tương tự: gcd, exgcd, modpow, prime
    python cli.py keygen --bits 2048 --out keys/key.json
    python cli.py encrypt --key keys/key.json --text "xin chào"
    python cli.py encrypt-file --key keys/key.json --in data/sample.png --out out/sample.png.enc
    python cli.py decrypt-file --key keys/key.json --in out/sample.png.enc --out out/sample.dec.png
    python cli.py test                                  # bộ kiểm thử + đối chiếu
    python cli.py bench                                 # đo thời gian
    python cli.py attack                                # minh họa tấn công

Toàn bộ thuật toán nằm trong gói `rsa/`; tệp này chỉ làm giao diện (nhập/xuất).
"""

import argparse
import os
import sys
import time

# In tiếng Việt ổn định trên Windows console
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rsa import toy, attacks, bench                       # noqa: E402
from rsa.keygen import generate_keypair, keypair_from_primes, PrivateKey, PublicKey   # noqa: E402
from rsa.codec import encrypt_bytes, decrypt_bytes          # noqa: E402
from rsa.fileio import (save_private_key, save_public_key, load_key,
                        encrypt_file, decrypt_file, files_identical)   # noqa: E402

KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "out")


# ======================================================================
# Các hành động (dùng chung cho menu và lệnh con)
# ======================================================================

def action_toy(preset=None, p=None, q=None, e=None, m=None, text=None, save=None):
    if preset:
        if preset not in toy.PRESETS:
            print(f"Không có preset '{preset}'. Có: {', '.join(toy.PRESETS)}")
            return
        cfg = toy.PRESETS[preset]
        p, q, e = cfg["p"], cfg["q"], cfg["e"]
        if m is None:
            m = cfg["m"]
        print(f"[preset {preset}] {cfg['desc']}")
    lines = []

    def out(s=""):
        print(s)
        lines.append(s)

    try:
        result = toy.run_toy(p, q, e, m, text, out)
    except ValueError as ex:
        print(f"LỖI: {ex}")
        return None
    if save:
        with open(save, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        print(f"Đã lưu toàn bộ bước trung gian vào {save}")
    return result


def action_slide(name):
    names = list(toy.SLIDE_EXAMPLES) if name == "all" else [name]
    for nm in names:
        if nm not in toy.SLIDE_EXAMPLES:
            print(f"Không có ví dụ '{nm}'. Có: all, {', '.join(toy.SLIDE_EXAMPLES)}")
            return
        toy.run_slide_example(nm)
        print()


def action_exercise(name):
    names = list(toy.EXERCISES) if name == "all" else [name]
    n_ok = 0
    for nm in names:
        if nm not in toy.EXERCISES:
            print(f"Không có bài '{nm}'. Có: all, {', '.join(toy.EXERCISES)}")
            return
        _, ok = toy.run_exercise(nm)
        n_ok += ok
        print()
    print(f"Khớp đáp án gợi ý: {n_ok}/{len(names)} bài")


def action_sign(p, q, e, m, s=None):
    key = keypair_from_primes(p, q, e)
    print(f"Khóa RSA: n = {key.n}, Φ(n) = {(p - 1) * (q - 1)}, e = {e} (công khai), d = {key.d} (bí mật)")
    if s is None:
        sig = toy.explain_sign(m, key)
        toy.explain_verify(m, sig, key)
    else:
        toy.explain_verify(m, s, key)


def action_algo(kind, **kw):
    """Chạy riêng một thuật toán nền với số liệu tự nhập."""
    if kind == "crt":
        toy.explain_crt(kw["res"], kw["mods"])
    elif kind == "phi":
        toy.explain_phi(kw["n"])
    elif kind == "gcd":
        toy.explain_gcd(kw["a"], kw["b"])
    elif kind == "exgcd":
        toy.explain_extended_gcd(kw["a"], kw["b"])
    elif kind == "inverse":
        toy.explain_inverse(kw["a"], kw["n"])
    elif kind == "modpow":
        toy.explain_mod_pow(kw["a"], kw["k"], kw["n"])
    elif kind == "prime":
        toy.explain_miller_rabin(kw["n"], bases=kw.get("bases"), max_bases=kw.get("max_bases", 3))


def action_keygen(bits, out_path=None, e=65537):
    t = time.perf_counter()
    key = generate_keypair(bits, e)
    dt = time.perf_counter() - t
    print(f"Đã sinh khóa RSA {key.bits} bit trong {dt:.3f} s")
    print(f"  p    = {key.p}")
    print(f"  q    = {key.q}")
    print(f"  n    = {key.n}")
    print(f"  e    = {key.e}")
    print(f"  d    = {key.d}")
    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        save_private_key(key, out_path)
        pub_path = os.path.splitext(out_path)[0] + ".pub.json"
        save_public_key(key.public, pub_path)
        print(f"  Đã lưu khóa bí mật: {out_path}")
        print(f"  Đã lưu khóa công khai: {pub_path}")
    return key


def action_encrypt_text(key, text, mode="pkcs1"):
    k = (key.n.bit_length() + 7) // 8
    if (mode == "pkcs1" and k < 12) or k < 2:
        # Khóa thu nhỏ: không đủ chỗ cho đệm PKCS#1 -> mã hóa từng ký tự như trên lớp
        print(f"Khóa chỉ có {key.n.bit_length()} bit (n = {key.n}): quá nhỏ để đệm PKCS#1 v1.5, "
              f"chuyển sang mã hóa từng ký tự (phiên bản thu nhỏ).")
        if isinstance(key, PrivateKey):
            return toy.explain_text(text, key)
        cs = [str(toy.encrypt_int(ord(ch), key)) for ch in text if ord(ch) < key.n]
        print("Bản mã (từng ký tự):", " ".join(cs))
        return cs
    data = text.encode("utf-8")
    t = time.perf_counter()
    ct = encrypt_bytes(data, key.public if isinstance(key, PrivateKey) else key, mode)
    te = time.perf_counter() - t
    print(f"Bản rõ   ({len(data)} byte UTF-8): {text}")
    print(f"Bản mã   ({len(ct)} byte, {len(ct) // ((key.n.bit_length() + 7) // 8)} khối, hex):")
    print(_wrap(ct.hex()))
    print(f"Thời gian mã hóa: {te * 1000:.2f} ms")
    if isinstance(key, PrivateKey):
        t = time.perf_counter()
        pt = decrypt_bytes(ct, key, mode)
        td = time.perf_counter() - t
        print(f"Giải mã  ({len(pt)} byte): {pt.decode('utf-8', errors='replace')}")
        print(f"Thời gian giải mã (CRT): {td * 1000:.2f} ms")
        print("Khớp bản rõ ban đầu:", "ĐÚNG" if pt == data else "SAI")
    return ct


def action_decrypt_hex(key, hex_ct, mode="pkcs1"):
    try:
        pt = decrypt_bytes(bytes.fromhex(hex_ct.strip()), key, mode)
    except Exception as ex:
        print(f"LỖI giải mã: {ex}")
        return None
    print(f"Bản rõ ({len(pt)} byte): {pt.decode('utf-8', errors='replace')}")
    return pt


def action_encrypt_file(key, in_path, out_path, mode="pkcs1"):
    pub = key.public if isinstance(key, PrivateKey) else key
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    t = time.perf_counter()
    n_in, n_out = encrypt_file(in_path, out_path, pub, mode)
    dt = time.perf_counter() - t
    print(f"Mã hóa tệp: {in_path} ({n_in} byte) -> {out_path} ({n_out} byte) trong {dt:.3f} s")


def action_decrypt_file(key, in_path, out_path, original=None, mode="pkcs1"):
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    t = time.perf_counter()
    n_in, n_out = decrypt_file(in_path, out_path, key, mode)
    dt = time.perf_counter() - t
    print(f"Giải mã tệp: {in_path} ({n_in} byte) -> {out_path} ({n_out} byte) trong {dt:.3f} s")
    if original and os.path.exists(original):
        same = files_identical(original, out_path)
        print(f"So sánh từng byte với tệp gốc {original}: {'GIỐNG HỆT' if same else 'KHÁC'}")


def action_file_roundtrip(key, in_path, mode="pkcs1"):
    base = os.path.basename(in_path)
    enc = os.path.join(OUT_DIR, base + ".enc")
    name, ext = os.path.splitext(base)
    dec = os.path.join(OUT_DIR, name + ".dec" + ext)
    action_encrypt_file(key, in_path, enc, mode)
    _preview_file(enc, "bản mã")
    action_decrypt_file(key, enc, dec, original=in_path, mode=mode)
    _preview_file(dec, "bản giải mã")


def action_test():
    import unittest
    tests_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tests")
    suite = unittest.defaultTestLoader.discover(tests_dir, top_level_dir=os.path.dirname(tests_dir))
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    print(f"\nTổng: {result.testsRun} ca; lỗi: {len(result.failures) + len(result.errors)}; "
          f"bỏ qua: {len(result.skipped)}")
    return result.wasSuccessful()


def action_bench(key_bits=1024):
    bench.bench_keygen()
    print()
    bench.bench_data(key_bits=key_bits)
    print()
    bench.bench_modpow()


def action_attack():
    attacks.run_all()


# ======================================================================
# Tiện ích hiển thị
# ======================================================================

def _wrap(s, width=96):
    return "\n".join(s[i:i + width] for i in range(0, len(s), width))


def _preview_file(path, label, nbytes=48):
    with open(path, "rb") as f:
        head = f.read(nbytes)
    try:
        txt = head.decode("utf-8")
        if all(ch.isprintable() or ch in "\r\n\t" for ch in txt):
            print(f"  {label}, {nbytes} byte đầu (văn bản): {txt!r}")
            return
    except UnicodeDecodeError:
        pass
    print(f"  {label}, {nbytes} byte đầu (hex): {head.hex()}")


def _ask(prompt, default=None, cast=str):
    while True:
        s = input(f"{prompt}" + (f" [{default}]" if default is not None else "") + ": ").strip()
        if not s and default is not None:
            return default
        try:
            return cast(s)
        except ValueError:
            print("  Giá trị không hợp lệ, nhập lại.")


def _show_key(key):
    if key is None:
        print("Chưa có khóa. Hãy sinh khóa (2) hoặc đọc khóa từ tệp (3).")
        return False
    kind = "bí mật" if isinstance(key, PrivateKey) else "công khai"
    print(f"Khóa hiện tại: {kind}, {key.n.bit_length()} bit, e = {key.e}")
    print(f"  n = {str(key.n)[:60]}{'...' if len(str(key.n)) > 60 else ''}")
    return True


# ======================================================================
# Menu tương tác
# ======================================================================

MENU = """
================= RSA - MENU =================
 1. Phiên bản thu nhỏ: chạy ví dụ trên lớp, in từng bước
 2. Sinh khóa RSA (phiên bản đầy đủ)
 3. Đọc khóa từ tệp JSON
 4. Lưu khóa hiện tại ra tệp
 5. Mã hóa văn bản nhập vào rồi giải mã lại
 6. Giải mã một bản mã (hex) bằng khóa hiện tại
 7. Mã hóa một tệp (văn bản / ảnh) rồi giải mã lại và so sánh
 8. Chạy bộ kiểm thử + đối chiếu với thư viện chuẩn / test vector
 9. Đo thời gian chạy theo kích thước dữ liệu
10. Minh họa tấn công
11. Chạy riêng từng thuật toán nền (BTVD trong slide hoặc tự nhập số)
12. Bài tập luyện tập Chương 3 (Euclid, nghịch đảo, bình phương và nhân, Ơle, CRT, RSA, chữ ký) + đối chiếu đáp án
 0. Thoát
"""


def menu():
    key = None
    while True:
        print(MENU)
        _show_key(key) if key else None
        choice = input("Chọn: ").strip()
        try:
            if choice == "1":
                print("Các ví dụ có sẵn:")
                for name, cfg in toy.PRESETS.items():
                    print(f"  {name:10s}: p={cfg['p']}, q={cfg['q']}, e={cfg['e']}, M={cfg['m']}  ({cfg['desc']})")
                print("  custom    : tự nhập p, q, e, M")
                sel = _ask("Chọn ví dụ", "lop")
                text = _ask("Chuỗi ký tự muốn mã hóa từng ký tự (Enter để bỏ qua)", "")
                if sel == "custom":
                    p = _ask("p", cast=int); q = _ask("q", cast=int)
                    e = _ask("e", cast=int); m = _ask("M (số nguyên < n)", cast=int)
                    res = action_toy(p=p, q=q, e=e, m=m, text=text or None)
                else:
                    m_in = _ask("M (Enter để dùng M của ví dụ)", "")
                    res = action_toy(preset=sel, m=int(m_in) if m_in else None, text=text or None)
                if res and _ask("Dùng khóa thu nhỏ này làm khóa hiện tại? (y/n)", "n") == "y":
                    key = res["key"]
            elif choice == "2":
                bits = _ask("Độ dài khóa (bit)", 2048, int)
                key = action_keygen(bits)
            elif choice == "3":
                path = _ask("Đường dẫn tệp khóa", os.path.join(KEY_DIR, "key.json"))
                key = load_key(path)
                _show_key(key)
            elif choice == "4":
                if _show_key(key):
                    path = _ask("Lưu vào", os.path.join(KEY_DIR, "key.json"))
                    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
                    if isinstance(key, PrivateKey):
                        save_private_key(key, path)
                        save_public_key(key.public, os.path.splitext(path)[0] + ".pub.json")
                    else:
                        save_public_key(key, path)
                    print("Đã lưu.")
            elif choice == "5":
                if _show_key(key):
                    text = _ask("Nhập bản rõ")
                    mode = _ask("Chế độ (pkcs1 = có đệm, raw = không đệm)", "pkcs1")
                    action_encrypt_text(key, text, mode)
            elif choice == "6":
                if _show_key(key):
                    if not isinstance(key, PrivateKey):
                        print("Cần khóa bí mật để giải mã.")
                    else:
                        hx = _ask("Dán bản mã (hex)")
                        mode = _ask("Chế độ (pkcs1 / raw)", "pkcs1")
                        action_decrypt_hex(key, hx, mode)
            elif choice == "7":
                if _show_key(key):
                    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "sample.png")
                    path = _ask("Tệp cần mã hóa", default)
                    mode = _ask("Chế độ (pkcs1 / raw)", "pkcs1")
                    if not os.path.exists(path):
                        print("Không tìm thấy tệp.")
                    elif not isinstance(key, PrivateKey):
                        enc = os.path.join(OUT_DIR, os.path.basename(path) + ".enc")
                        action_encrypt_file(key, path, enc, mode)
                    else:
                        action_file_roundtrip(key, path, mode)
            elif choice == "8":
                action_test()
            elif choice == "9":
                bits = _ask("Độ dài khóa dùng để đo (bit)", 1024, int)
                action_bench(bits)
            elif choice == "10":
                action_attack()
            elif choice == "11":
                print("Ví dụ trong slide:")
                for nm, ex in toy.SLIDE_EXAMPLES.items():
                    print(f"  {nm:8s}: {ex['desc']}")
                print("  all     : chạy tất cả ví dụ trên")
                print("Tự nhập: gcd | exgcd | inverse | modpow | prime | crt | phi | sign")
                sel = _ask("Chọn", "all")
                if sel in toy.SLIDE_EXAMPLES or sel == "all":
                    action_slide(sel)
                elif sel in ("gcd", "exgcd"):
                    action_algo(sel, a=_ask("a", cast=int), b=_ask("b", cast=int))
                elif sel == "inverse":
                    action_algo(sel, a=_ask("a", cast=int), n=_ask("n", cast=int))
                elif sel == "modpow":
                    action_algo(sel, a=_ask("a", cast=int), k=_ask("k (số mũ)", cast=int), n=_ask("n", cast=int))
                elif sel == "prime":
                    n = _ask("n", cast=int)
                    b = _ask("các cơ sở a, cách nhau bằng dấu phẩy (Enter = tự chọn)", "")
                    bases = [int(v) for v in b.split(",")] if b.strip() else None
                    action_algo(sel, n=n, bases=bases)
                elif sel == "crt":
                    res = [int(v) for v in _ask("các số dư a1,a2,... (cách nhau bằng dấu phẩy)").split(",")]
                    mods = [int(v) for v in _ask("các modulo m1,m2,...").split(",")]
                    action_algo(sel, res=res, mods=mods)
                elif sel == "phi":
                    action_algo(sel, n=_ask("n", cast=int))
                elif sel == "sign":
                    p_ = _ask("p", cast=int); q_ = _ask("q", cast=int); e_ = _ask("e", cast=int)
                    m_ = _ask("M", cast=int); s_ = _ask("S cần kiểm chứng (Enter = tự ký)", "")
                    action_sign(p_, q_, e_, m_, int(s_) if s_ else None)
                else:
                    print("Lựa chọn không hợp lệ.")
            elif choice == "12":
                print("Bài tập luyện tập Chương 3:")
                for nm, ex in toy.EXERCISES.items():
                    print(f"  {nm:7s}: {ex['desc']}")
                sel = _ask("Chọn bài (all = tất cả)", "all")
                action_exercise(sel)
            elif choice == "0":
                print("Tạm biệt.")
                return
            else:
                print("Lựa chọn không hợp lệ.")
        except (ValueError, OSError) as ex:
            print(f"LỖI: {ex}")
        except KeyboardInterrupt:
            print("\n(đã hủy)")


# ======================================================================
# Lệnh con
# ======================================================================

def build_parser():
    ap = argparse.ArgumentParser(description="RSA tự cài đặt - demo")
    sub = ap.add_subparsers(dest="cmd")

    s = sub.add_parser("toy", help="phiên bản thu nhỏ, in từng bước")
    s.add_argument("--preset", choices=list(toy.PRESETS), help="bộ ví dụ có sẵn")
    s.add_argument("--p", type=int); s.add_argument("--q", type=int)
    s.add_argument("--e", type=int); s.add_argument("--m", type=int)
    s.add_argument("--text", help="chuỗi mã hóa từng ký tự")
    s.add_argument("--save", help="lưu toàn bộ bước trung gian ra tệp văn bản")

    s = sub.add_parser("keygen", help="sinh khóa")
    s.add_argument("--bits", type=int, default=2048)
    s.add_argument("--e", type=int, default=65537)
    s.add_argument("--out", default=os.path.join(KEY_DIR, "key.json"))

    s = sub.add_parser("encrypt", help="mã hóa văn bản (và giải mã lại nếu là khóa bí mật)")
    s.add_argument("--key", required=True); s.add_argument("--text", required=True)
    s.add_argument("--mode", default="pkcs1", choices=["pkcs1", "raw"])

    s = sub.add_parser("decrypt", help="giải mã bản mã hex")
    s.add_argument("--key", required=True); s.add_argument("--hex", required=True)
    s.add_argument("--mode", default="pkcs1", choices=["pkcs1", "raw"])

    s = sub.add_parser("encrypt-file", help="mã hóa tệp")
    s.add_argument("--key", required=True); s.add_argument("--in", dest="inp", required=True)
    s.add_argument("--out", required=True); s.add_argument("--mode", default="pkcs1", choices=["pkcs1", "raw"])

    s = sub.add_parser("decrypt-file", help="giải mã tệp")
    s.add_argument("--key", required=True); s.add_argument("--in", dest="inp", required=True)
    s.add_argument("--out", required=True); s.add_argument("--original", help="tệp gốc để so sánh")
    s.add_argument("--mode", default="pkcs1", choices=["pkcs1", "raw"])

    s = sub.add_parser("roundtrip", help="mã hóa tệp rồi giải mã lại và so sánh (ra thư mục out/)")
    s.add_argument("--key", required=True); s.add_argument("--in", dest="inp", required=True)
    s.add_argument("--mode", default="pkcs1", choices=["pkcs1", "raw"])

    s = sub.add_parser("slide", help="chạy lại BTVD thuật toán nền trong slide")
    s.add_argument("--name", default="all", help="all | " + " | ".join(toy.SLIDE_EXAMPLES))
    s = sub.add_parser("gcd", help="Euclid tìm GCD(a, b), in từng dòng")
    s.add_argument("--a", type=int, required=True); s.add_argument("--b", type=int, required=True)
    s = sub.add_parser("exgcd", help="Euclid mở rộng, bảng như slide")
    s.add_argument("--a", type=int, required=True); s.add_argument("--b", type=int, required=True)
    s = sub.add_parser("inverse", help="a^-1 mod n, bảng như slide")
    s.add_argument("--a", type=int, required=True); s.add_argument("--n", type=int, required=True)
    s = sub.add_parser("modpow", help="a^k mod n bằng bình phương và nhân, bảng như slide")
    s.add_argument("--a", type=int, required=True); s.add_argument("--k", type=int, required=True)
    s.add_argument("--n", type=int, required=True)
    s = sub.add_parser("prime", help="kiểm tra Miller-Rabin, in từng bước")
    s.add_argument("--n", type=int, required=True)
    s.add_argument("--bases", help="các cơ sở a, cách nhau bằng dấu phẩy, ví dụ 2,3,5")
    s = sub.add_parser("crt", help="định lý phần dư Trung Hoa: --res 1,4,6 --mods 5,7,11")
    s.add_argument("--res", required=True); s.add_argument("--mods", required=True)
    s = sub.add_parser("phi", help="hàm Ơle Φ(n)")
    s.add_argument("--n", type=int, required=True)
    s = sub.add_parser("sign", help="chữ ký RSA thu nhỏ: ký M (hoặc kiểm chứng cặp M, S nếu có --s)")
    s.add_argument("--p", type=int, required=True); s.add_argument("--q", type=int, required=True)
    s.add_argument("--e", type=int, required=True); s.add_argument("--m", type=int, required=True)
    s.add_argument("--s", type=int)
    s = sub.add_parser("exercise", help="Bài tập luyện tập Chương 3, đối chiếu đáp án gợi ý")
    s.add_argument("--name", default="all", help="all | " + " | ".join(toy.EXERCISES))

    sub.add_parser("test", help="chạy bộ kiểm thử + đối chiếu")
    s = sub.add_parser("bench", help="đo thời gian")
    s.add_argument("--bits", type=int, default=1024)
    sub.add_parser("attack", help="minh họa tấn công")
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.cmd is None:
        menu()
        return 0
    if args.cmd == "toy":
        if not args.preset and None in (args.p, args.q, args.e):
            print("Cần --preset hoặc đủ --p --q --e (và --m / --text)")
            return 2
        action_toy(args.preset, args.p, args.q, args.e, args.m, args.text, args.save)
    elif args.cmd == "keygen":
        action_keygen(args.bits, args.out, args.e)
    elif args.cmd == "encrypt":
        action_encrypt_text(load_key(args.key), args.text, args.mode)
    elif args.cmd == "decrypt":
        action_decrypt_hex(load_key(args.key), args.hex, args.mode)
    elif args.cmd == "encrypt-file":
        action_encrypt_file(load_key(args.key), args.inp, args.out, args.mode)
    elif args.cmd == "decrypt-file":
        action_decrypt_file(load_key(args.key), args.inp, args.out, args.original, args.mode)
    elif args.cmd == "roundtrip":
        action_file_roundtrip(load_key(args.key), args.inp, args.mode)
    elif args.cmd == "slide":
        action_slide(args.name)
    elif args.cmd in ("gcd", "exgcd"):
        action_algo(args.cmd, a=args.a, b=args.b)
    elif args.cmd == "inverse":
        action_algo("inverse", a=args.a, n=args.n)
    elif args.cmd == "modpow":
        action_algo("modpow", a=args.a, k=args.k, n=args.n)
    elif args.cmd == "prime":
        bases = [int(v) for v in args.bases.split(",")] if args.bases else None
        action_algo("prime", n=args.n, bases=bases)
    elif args.cmd == "crt":
        action_algo("crt", res=[int(v) for v in args.res.split(",")], mods=[int(v) for v in args.mods.split(",")])
    elif args.cmd == "phi":
        action_algo("phi", n=args.n)
    elif args.cmd == "sign":
        action_sign(args.p, args.q, args.e, args.m, args.s)
    elif args.cmd == "exercise":
        action_exercise(args.name)
    elif args.cmd == "test":
        return 0 if action_test() else 1
    elif args.cmd == "bench":
        action_bench(args.bits)
    elif args.cmd == "attack":
        action_attack()
    return 0


if __name__ == "__main__":
    sys.exit(main())
