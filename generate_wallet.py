#!/usr/bin/env python3
"""
Offline BTC + SOL wallet generator from physical dice entropy.
Run ONLY on an air-gapped machine, after installing pinned/hash-verified
wheels via: pip install --no-index --find-links=./pkgs -r requirements-hashes.txt --require-hashes

Uses:
  - mnemonic  (BIP39 wordlist + checksum + PBKDF2 seed derivation)
  - ecdsa     (secp256k1 point math, for BIP32 Bitcoin derivation)
  - pynacl    (ed25519, for SLIP-0010 Solana derivation)
No network access is used or required anywhere in this script.
"""

import argparse, hashlib, hmac, getpass, os, random, re, subprocess, sys
from pathlib import Path
from importlib import metadata

ROOT = Path(__file__).resolve().parent
PKGS_DIR = ROOT / "pkgs"
REQ_HASHES = ROOT / "requirements-hashes.txt"


def _parse_requirements_hashes():
    expected = {}
    for raw in REQ_HASHES.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^([A-Za-z0-9_.-]+)==([^\s]+)\s+--hash=sha256:([0-9a-fA-F]{64})$", line)
        if not m:
            raise SystemExit(f"Bad requirements-hashes.txt line: {raw}")
        name, version, digest = m.groups()
        expected[name.lower().replace("_", "-")] = (version, digest.lower())
    return expected


def _verify_local_wheel_hashes(expected):
    if not PKGS_DIR.is_dir():
        raise SystemExit(f"Missing local package dir: {PKGS_DIR}")
    wheels = {p.name.lower(): p for p in PKGS_DIR.glob("*.whl")}
    for name, (version, digest) in expected.items():
        candidates = [p for fname, p in wheels.items() if fname.startswith(f"{name}-{version}".lower().replace("_", "-"))]
        if not candidates:
            raise SystemExit(f"Missing wheel in pkgs/: {name}=={version}")
        ok = False
        for whl in candidates:
            got = hashlib.sha256(whl.read_bytes()).hexdigest()
            if got == digest:
                ok = True
                break
        if not ok:
            raise SystemExit(f"Hash mismatch for pkgs/{candidates[0].name}; refusing to load dependencies")


def _installed_deps_match(expected):
    for name, (version, _digest) in expected.items():
        try:
            if metadata.version(name) != version:
                return False
        except metadata.PackageNotFoundError:
            return False
    return True


def enforce_local_verified_packages():
    expected = _parse_requirements_hashes()
    _verify_local_wheel_hashes(expected)
    cmd = [
        sys.executable, "-m", "pip", "install",
        "--no-index",
        f"--find-links={PKGS_DIR}",
        "--require-hashes",
        "--force-reinstall",
        "-r", str(REQ_HASHES),
    ]
    env = dict(os.environ)
    env["PIP_NO_INDEX"] = "1"
    env["PIP_FIND_LINKS"] = str(PKGS_DIR)
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    res = subprocess.run(cmd, cwd=str(ROOT), env=env, text=True, capture_output=True)
    if res.returncode != 0:
        raise SystemExit("Local hash-verified dependency install failed:\n" + res.stdout + res.stderr)
    if not _installed_deps_match(expected):
        raise SystemExit("Dependency versions still mismatch after local hash-verified install")


enforce_local_verified_packages()

from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
import nacl.signing
try:
    import pyfiglet
except ImportError:
    pyfiglet = None

COLOR_ENABLED = False
ANSI = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "red": "\033[31m",
    "cyan": "\033[36m",
    "dim": "\033[2m",
}


def colorize(text, color):
    if not COLOR_ENABLED:
        return text
    return ANSI[color] + text + ANSI["reset"]


def configure_color(mode):
    global COLOR_ENABLED
    COLOR_ENABLED = mode == "always" or (mode == "auto" and sys.stdout.isatty())

# ============================================================
# STEP 1: dice entropy collection with Von Neumann debiasing
# ============================================================
# Von Neumann extractor: roll the die TWICE per attempt.
#   if roll1 < roll2  -> emit bit 0
#   if roll1 > roll2  -> emit bit 1
#   if roll1 == roll2 -> discard, roll again
# This yields provably unbiased bits from ANY biased-but-independent die,
# because P(a,b) == P(b,a) for iid rolls regardless of the die's true
# per-face probabilities.

def analyze_roll_quality(rolls, pair_bits, target_bits):
    n = len(rolls)
    pair_bits = [] if pair_bits is None else pair_bits
    check_pair_yield = target_bits is not None
    ties = sum(1 for a, b in pair_bits if a == b)
    total_pairs = len(pair_bits)
    non_tie_pairs = total_pairs - ties
    face_counts = {i: 0 for i in range(1, 7)}
    for r in rolls:
        face_counts[r] += 1

    expected = n / 6 if n else 0
    chi2 = 0.0
    if expected:
        for v in face_counts.values():
            chi2 += (v - expected) ** 2 / expected

    streaks = []
    if rolls:
        cur = rolls[0]
        streak = 1
        for r in rolls[1:]:
            if r == cur:
                streak += 1
            else:
                streaks.append(streak)
                cur = r
                streak = 1
        streaks.append(streak)

    max_streak = max(streaks) if streaks else 0
    face_min = min(face_counts.values()) if face_counts else 0
    face_max = max(face_counts.values()) if face_counts else 0

    warnings = []
    if n < 24:
        warnings.append("low sample size (<24 rolls)")
    if ties > max(2, total_pairs * 0.35):
        warnings.append("high tie rate")
    if max_streak >= 5:
        warnings.append("long streak detected")
    if face_min == 0:
        warnings.append("one or more faces never appeared")
    if chi2 > 15.09:
        warnings.append("chi-square p<0.01 vs uniform")
    if check_pair_yield and non_tie_pairs < target_bits:
        warnings.append("insufficient unbiased bit yield")

    score = 100
    score -= min(30, max(0, 24 - n)) * 2
    score -= min(20, int(ties * 2))
    score -= min(20, max(0, max_streak - 3) * 4)
    score -= min(20, int(max(0, chi2 - 5)))
    score -= 15 if face_min == 0 else 0
    score -= 15 if check_pair_yield and non_tie_pairs < target_bits else 0
    score = max(0, min(100, score))

    if score >= 80 and not warnings:
        verdict = "GOOD"
    elif score >= 55:
        verdict = "OK"
    else:
        verdict = "SUSPECT"

    return {
        "roll_count": n,
        "pair_count": total_pairs,
        "tie_count": ties,
        "non_tie_pairs": non_tie_pairs,
        "face_counts": face_counts,
        "chi2": chi2,
        "max_streak": max_streak,
        "warnings": warnings,
        "score": score,
        "verdict": verdict,
    }


def print_quality_report(q):
    print("\n" + colorize("=== RANDOMNESS QUALITY REPORT ===", "bold"))
    verdict_color = "green" if q["verdict"] == "GOOD" else "yellow" if q["verdict"] == "OK" else "red"
    print("Verdict:       " + colorize(q["verdict"], verdict_color))
    print(f"Score:         {q['score']}/100")
    print(f"Rolls:         {q['roll_count']}")
    print(f"Pairs:         {q['pair_count']}")
    print(f"Ties:          {q['tie_count']}")
    print(f"Non-tie pairs: {q['non_tie_pairs']}")
    print(f"Chi-square:    {q['chi2']:.2f} (uniform expected)")
    print(f"Max streak:    {q['max_streak']}")
    print("Face counts:   " + ", ".join(f"{k}:{v}" for k, v in q['face_counts'].items()))
    if q['warnings']:
        print("Warnings:      " + colorize("; ".join(q['warnings']), "red"))
    else:
        print("Warnings:      none")
    if q["verdict"] != "GOOD":
        print(colorize("WARNING: RANDOMNESS QUALITY NOT GOOD. Possible bad die, non-random pattern, or dishonest/simulated rolls.", "red"))
        print(colorize("Do NOT fund wallets from this run unless you intentionally accept this risk.", "red"))
    print("NOTE: advisory only; generation continues.\n")


def mnemonic_gap_check(words):
    parts = words.split()
    if len(parts) not in (12, 24):
        print("\n=== MNEMONIC GAP CHECK ===")
        print("Unexpected word count; skipped.")
        return
    mnemo = Mnemonic('english')
    idxs = sorted(random.sample(range(len(parts)), k=min(5, len(parts))))
    print("\n=== MNEMONIC GAP CHECK ===")
    print("Fill the missing words:")
    answers = []
    for idx in idxs:
        prompt_words = parts.copy()
        prompt_words[idx] = '____'
        print(f"{idx+1:02d}: " + ' '.join(prompt_words))
        ans = input(f"Word #{idx+1}: ").strip().lower()
        answers.append((idx, ans))
    wrong = []
    for idx, ans in answers:
        if ans != parts[idx]:
            wrong.append((idx + 1, parts[idx]))
    if wrong:
        print("Mismatch:")
        for pos, correct in wrong:
            print(f"  {pos:02d} -> {correct}")
        print("WARNING: mnemonic recall check failed. Verify backup before closing.")
    else:
        print("Mnemonic recall check: PASS")


def collect_entropy_bits(num_bits):
    bits = []
    rolls = []
    pair_bits = []
    pair_count = 0
    pending = []
    max_rolls = max(48, num_bits * 8)
    print(f"\nNeed {num_bits} unbiased bits.")
    print("Enter 1 die roll at a time (1-6). App pairs in code. Type 'q' to abort.\n")
    while len(bits) < num_bits:
        if len(rolls) >= max_rolls:
            q = analyze_roll_quality(rolls, pair_bits, num_bits)
            q['warnings'].append(f"roll cap hit ({max_rolls})")
            q['verdict'] = 'SUSPECT'
            q['score'] = min(q['score'], 40)
            print_quality_report(q)
            raise SystemExit("Aborted: poor entropy quality / cap hit.")
        raw = input(f"[{len(bits)}/{num_bits} bits | pending={''.join(map(str, pending)) or '-'}] roll: ").strip()
        if raw.lower() == "q":
            raise SystemExit("Aborted.")
        try:
            r = int(raw)
            if r < 1 or r > 6:
                raise ValueError
        except ValueError:
            print("  -> invalid input, enter a single digit 1-6")
            continue
        rolls.append(r)
        pending.append(r)
        print(f"  -> stored: {raw}")
        if len(pending) < 2:
            continue
        a, b = pending
        pending.clear()
        pair_bits.append((a, b))
        pair_count += 1
        print(f"  -> pair #{pair_count}: {a} {b}")
        if a == b:
            print("  -> tie, discarded (this is expected sometimes)")
            continue
        bit = 0 if a < b else 1
        bits.append(bit)
        print(f"  -> bit: {bit}")
    q = analyze_roll_quality(rolls, pair_bits, num_bits)
    print_quality_report(q)
    print(f"Done. Used {pair_count} dice-pairs to extract {num_bits} unbiased bits.\n")
    return bits

def bits_to_bytes(bits):
    assert len(bits) % 8 == 0
    b = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        b.append(byte)
    return bytes(b)


def bytes_to_bits(data, num_bits=None):
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits[:num_bits] if num_bits is not None else bits


def hash_rolls_to_bits(rolls, num_bits):
    if not rolls:
        raise ValueError("at least one die roll is required")
    for r in rolls:
        if r < 1 or r > 6:
            raise ValueError("die rolls must be integers 1-6")
    transcript = "".join(str(r) for r in rolls).encode("ascii")
    digest = hashlib.sha256(transcript).digest()
    if num_bits <= 256:
        return bytes_to_bits(digest, num_bits)
    out = bytearray()
    counter = 0
    while len(out) * 8 < num_bits:
        out.extend(hashlib.sha256(transcript + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes_to_bits(bytes(out), num_bits)


def collect_hash_roll_entropy_bits(num_bits, roll_count=100):
    rolls = []
    print(f"\nNeed {roll_count} physical die rolls. App hashes exact transcript with SHA256.")
    print("Enter 1 die roll at a time (1-6). Type 'q' to abort.\n")
    while len(rolls) < roll_count:
        raw = input(f"[{len(rolls)}/{roll_count} rolls] roll: ").strip()
        if raw.lower() == "q":
            raise SystemExit("Aborted.")
        try:
            r = int(raw)
            if r < 1 or r > 6:
                raise ValueError
        except ValueError:
            print("  -> invalid input, enter a single digit 1-6")
            continue
        rolls.append(r)
        print(f"  -> stored: {raw}")
    q = analyze_roll_quality(rolls, None, None)
    print_quality_report(q)
    return hash_rolls_to_bits(rolls, num_bits)


def parse_args(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    argv = ["--help" if arg == "/help" or arg.replace("\\", "/").endswith("/help") else arg for arg in argv]
    parser = argparse.ArgumentParser(description="Offline BTC + SOL wallet generator from physical dice entropy.")
    parser.add_argument("--words", type=int, choices=(12, 24), default=24, help="BIP39 mnemonic length. Default: 24")
    parser.add_argument("--entropy-mode", choices=("hash-rolls", "von-neumann"), default="von-neumann", help="von-neumann extracts unbiased bits and usually needs hundreds of rolls; hash-rolls hashes a fixed roll transcript. Default: von-neumann")
    parser.add_argument("--roll-count", type=int, default=150, help="Physical die rolls for hash-rolls mode. Default: 150")
    parser.add_argument("--no-gap-check", dest="gap_check", action="store_false", help="Skip interactive mnemonic recall/gap check")
    parser.add_argument("--show-private-derivations", action="store_true", help="Also print private material for every listed derivation path")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="Colored terminal output. Default: auto")
    parser.add_argument("--no-color", dest="color", action="store_const", const="never", help="Disable colored terminal output")
    parser.add_argument("--bad-dice-report", action="store_true", help="Print synthetic bad/dishonest dice quality examples, then exit")
    parser.set_defaults(gap_check=True)
    return parser.parse_args(argv)

# ============================================================
# STEP 2: BIP32 secp256k1 derivation (Bitcoin) -- written explicitly,
# using `ecdsa` only for the underlying point multiplication.
# ============================================================
N = SECP256k1.order

def ser32(i): return i.to_bytes(4, "big")
def ser256(k): return k.to_bytes(32, "big")

def point_from_priv(k):
    sk = SigningKey.from_secret_exponent(k, curve=SECP256k1)
    return sk.get_verifying_key().pubkey.point

def compress_point(P):
    x, y = P.x(), P.y()
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, "big")

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def b58encode(b):
    n = int.from_bytes(b, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = ALPHABET[r] + out
    pad = 0
    for byte in b:
        if byte == 0: pad += 1
        else: break
    return "1" * pad + out

def b58check_encode(payload):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)

def ripemd160(b):
    try:
        h = hashlib.new("ripemd160")
        h.update(b)
        return h.digest()
    except ValueError:
        # Pure-Python fallback (compact RIPEMD-160 implementation)
        # Public-domain style implementation adapted for offline use.
        def _rol(x, n):
            return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

        def _f(j, x, y, z):
            if 0 <= j <= 15: return x ^ y ^ z
            if 16 <= j <= 31: return (x & y) | (~x & z)
            if 32 <= j <= 47: return (x | ~y) ^ z
            if 48 <= j <= 63: return (x & z) | (y & ~z)
            return x ^ (y | ~z)

        def _K(j):
            if 0 <= j <= 15: return 0x00000000
            if 16 <= j <= 31: return 0x5A827999
            if 32 <= j <= 47: return 0x6ED9EBA1
            if 48 <= j <= 63: return 0x8F1BBCDC
            return 0xA953FD4E

        def _Kp(j):
            if 0 <= j <= 15: return 0x50A28BE6
            if 16 <= j <= 31: return 0x5C4DD124
            if 32 <= j <= 47: return 0x6D703EF3
            if 48 <= j <= 63: return 0x7A6D76E9
            return 0x00000000

        r = [
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
        ]
        rp = [
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
        ]
        s = [
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
        ]
        sp = [
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
        ]
        msg = bytearray(b)
        ml = len(msg) * 8
        msg.append(0x80)
        while (len(msg) % 64) != 56:
            msg.append(0)
        msg += ml.to_bytes(8, 'little')

        h0, h1, h2, h3, h4 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0
        for off in range(0, len(msg), 64):
            X = [int.from_bytes(msg[off+i:off+i+4], 'little') for i in range(0, 64, 4)]
            A1, B1, C1, D1, E1 = h0, h1, h2, h3, h4
            A2, B2, C2, D2, E2 = h0, h1, h2, h3, h4
            for j in range(80):
                T = (_rol((A1 + _f(j, B1, C1, D1) + X[r[j]] + _K(j)) & 0xFFFFFFFF, s[j]) + E1) & 0xFFFFFFFF
                A1, E1, D1, C1, B1 = E1, D1, _rol(C1, 10), B1, T
                T = (_rol((A2 + _f(79-j, B2, C2, D2) + X[rp[j]] + _Kp(j)) & 0xFFFFFFFF, sp[j]) + E2) & 0xFFFFFFFF
                A2, E2, D2, C2, B2 = E2, D2, _rol(C2, 10), B2, T
            T = (h1 + C1 + D2) & 0xFFFFFFFF
            h1 = (h2 + D1 + E2) & 0xFFFFFFFF
            h2 = (h3 + E1 + A2) & 0xFFFFFFFF
            h3 = (h4 + A1 + B2) & 0xFFFFFFFF
            h4 = (h0 + B1 + C2) & 0xFFFFFFFF
            h0 = T
        return b''.join(x.to_bytes(4, 'little') for x in (h0, h1, h2, h3, h4))

def bip32_master(seed):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]

def bip32_ckd_priv(k_par, c_par, index):
    hardened = index >= 0x80000000
    if hardened:
        data = b'\x00' + ser256(int.from_bytes(k_par, "big")) + ser32(index)
    else:
        P = point_from_priv(int.from_bytes(k_par, "big"))
        data = compress_point(P) + ser32(index)
    I = hmac.new(c_par, data, hashlib.sha512).digest()
    IL, IR = I[:32], I[32:]
    il_int = int.from_bytes(IL, "big")
    if il_int >= N:
        raise ValueError("Invalid BIP32 child key material (IL >= N)")
    k_i = (il_int + int.from_bytes(k_par, "big")) % N
    if k_i == 0:
        raise ValueError("Invalid BIP32 child key material (child key = 0)")
    return ser256(k_i), IR

def H(i): return 0x80000000 + i

def btc_from_seed(seed, path=(H(44), H(0), H(0), 0, 0)):
    k, c = bip32_master(seed)
    for level in path:
        k, c = bip32_ckd_priv(k, c, level)
    kint = int.from_bytes(k, "big")
    P = point_from_priv(kint)
    pub = compress_point(P)
    h160 = ripemd160(hashlib.sha256(pub).digest())
    address = b58check_encode(b'\x00' + h160)
    wif = b58check_encode(b'\x80' + k + b'\x01')
    return address, wif

# ============================================================
# STEP 3: SLIP-0010 ed25519 derivation (Solana) -- explicit,
# using `pynacl` only for the final ed25519 keypair from the derived seed.
# ============================================================
def slip10_ed25519_master(seed):
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]

def slip10_ed25519_ckd(k_par, c_par, index):
    index = index | 0x80000000  # SLIP-10 ed25519: every level is hardened
    data = b'\x00' + k_par + ser32(index)
    I = hmac.new(c_par, data, hashlib.sha512).digest()
    return I[:32], I[32:]

def sol_from_seed(seed, path=(44, 501, 0, 0, 0)):
    k, c = slip10_ed25519_master(seed)
    for level in path:
        k, c = slip10_ed25519_ckd(k, c, level)
    sk = nacl.signing.SigningKey(k)
    pub = sk.verify_key.encode()
    address = b58encode(pub)
    return address, k


def default_derivation_profiles():
    return [
        {"chain": "BTC", "label": "BTC legacy P2PKH m/44'/0'/0'/0/0", "path": "m/44'/0'/0'/0/0", "kind": "btc", "path_tuple": (H(44), H(0), H(0), 0, 0)},
        {"chain": "BTC", "label": "BTC legacy P2PKH account 1 m/44'/0'/1'/0/0", "path": "m/44'/0'/1'/0/0", "kind": "btc", "path_tuple": (H(44), H(0), H(1), 0, 0)},
        {"chain": "SOL", "label": "SOL Phantom/Solflare m/44'/501'/0'/0'", "path": "m/44'/501'/0'/0'", "kind": "sol", "path_tuple": (44, 501, 0, 0)},
        {"chain": "SOL", "label": "SOL legacy/deep m/44'/501'/0'/0'/0'", "path": "m/44'/501'/0'/0'/0'", "kind": "sol", "path_tuple": (44, 501, 0, 0, 0)},
        {"chain": "SOL", "label": "SOL account 1 m/44'/501'/1'/0'", "path": "m/44'/501'/1'/0'", "kind": "sol", "path_tuple": (44, 501, 1, 0)},
    ]


def derive_wallet_profiles(seed):
    rows = []
    for profile in default_derivation_profiles():
        if profile["kind"] == "btc":
            address, secret = btc_from_seed(seed, profile["path_tuple"])
            secret_name = "wif"
        else:
            address, secret_bytes = sol_from_seed(seed, profile["path_tuple"])
            secret = secret_bytes.hex()
            secret_name = "seed_hex"
        rows.append({
            "chain": profile["chain"],
            "label": profile["label"],
            "path": profile["path"],
            "address": address,
            secret_name: secret,
        })
    return rows


def print_derivation_profiles(rows, include_private=False):
    print("\n" + colorize("--- Common wallet derivation conventions ---", "bold"))
    print(colorize("Same 24 words can produce different addresses depending on wallet/path.", "dim"))
    for row in rows:
        print("\n" + colorize(f"[{row['chain']}] {row['label']}", "cyan"))
        print("Path:   ", colorize(row["path"], "yellow"))
        print("Address:", colorize(row["address"], "green"))
        if include_private:
            if "wif" in row:
                print("WIF:    ", row["wif"])
            if "seed_hex" in row:
                print("Seed hex:", row["seed_hex"])

def print_bad_dice_report():
    cases = [
        ("all ones / fake stuck die", [1] * 40, [(1, 1)] * 20, 16),
        ("scripted alternating 1,2", [1, 2] * 20, [(1, 2)] * 20, 16),
        ("missing faces 1,2,3 only", [1, 2, 3] * 14, [(1, 2), (2, 3), (3, 1)] * 7, 16),
    ]
    print("\n=== BAD / DISHONEST DICE REPORT ===")
    print("Synthetic examples. Use to show how non-random or lied-about rolls get flagged.\n")
    for label, rolls, pairs, target in cases:
        print(colorize(f"--- {label} ---", "bold"))
        print_quality_report(analyze_roll_quality(rolls, pairs, target))


# ============================================================
# MAIN
# ============================================================
def main(argv=None):
    args = parse_args(argv)
    configure_color(args.color)
    if args.bad_dice_report:
        print_bad_dice_report()
        return
    if pyfiglet:
        print(colorize(pyfiglet.figlet_format("Wallet Dice"), "cyan"))
    else:
        print(colorize("Wallet Dice", "cyan"))
    print(colorize("=== Offline dice-based BTC + SOL wallet generator ===", "bold"))
    entropy_bits = 128 if args.words == 12 else 256

    if args.entropy_mode == "von-neumann":
        bits = collect_entropy_bits(entropy_bits)
    else:
        bits = collect_hash_roll_entropy_bits(entropy_bits, args.roll_count)
    entropy = bits_to_bytes(bits)

    mnemo = Mnemonic("english")
    words = mnemo.to_mnemonic(entropy)

    print("\n" + colorize("=" * 60, "yellow"))
    print(colorize("MNEMONIC (write this down on paper/steel; this terminal cannot securely erase secrets):", "yellow"))
    print(colorize(words, "green"))
    print(colorize("WARNING: mnemonic/passphrase/seed may remain in terminal scrollback, RAM, swap/hibernation, crash dumps, malware logs, or firmware capture.", "red"))
    print(colorize("=" * 60, "yellow"))

    use_pass = getpass.getpass("\nAdd an optional BIP39 passphrase? (leave blank for none): ")
    if use_pass:
        confirm = getpass.getpass("Confirm passphrase: ")
        if confirm != use_pass:
            raise SystemExit("Passphrase mismatch.")
    seed = mnemo.to_seed(words, use_pass)

    rows = derive_wallet_profiles(seed)
    print_derivation_profiles(rows, include_private=args.show_private_derivations)

    if not args.show_private_derivations:
        print("\nPrivate material hidden for alternate paths. Use --show-private-derivations only on airgap if needed.")

    if args.gap_check:
        mnemonic_gap_check(words)

    print("\nVerify these addresses independently in Electrum/Sparrow (BTC) and")
    print("Phantom/Solflare (SOL) by importing the mnemonic BEFORE sending any funds.")

if __name__ == "__main__":
    main()
