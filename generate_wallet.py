#!/usr/bin/env python3
"""
Offline Solana wallet generator from physical dice entropy.

Run ONLY on an air-gapped machine, after setup_env.bat installs pinned/hash-verified
wheels from local pkgs/ using --no-index and --require-hashes.

Wallet generation performs zero package installation.
"""

import argparse, getpass, hashlib, hmac, random, re, sys
from pathlib import Path
from importlib import metadata

ROOT = Path(__file__).resolve().parent
PKGS_DIR = ROOT / "pkgs"
REQ_HASHES = ROOT / "requirements-hashes.txt"
MIN_HASH_ROLLS_24 = 150
MIN_HASH_ROLLS_12 = 75


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
        if not any(hashlib.sha256(p.read_bytes()).hexdigest() == digest for p in candidates):
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
    if not _installed_deps_match(expected):
        raise SystemExit("Dependency versions mismatch or missing. Run setup_env.bat first; wallet generation performs zero package installation.")


enforce_local_verified_packages()

from mnemonic import Mnemonic
import nacl.signing

COLOR_ENABLED = False
ANSI = {"reset":"\033[0m","bold":"\033[1m","green":"\033[32m","yellow":"\033[33m","red":"\033[31m","cyan":"\033[36m","dim":"\033[2m"}
ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def colorize(text, color):
    return ANSI[color] + text + ANSI["reset"] if COLOR_ENABLED else text


def configure_color(mode):
    global COLOR_ENABLED
    COLOR_ENABLED = mode == "always" or (mode == "auto" and sys.stdout.isatty())


def ser32(i): return i.to_bytes(4, "big")


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


def bytes_to_bits(data, num_bits=None):
    bits = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits[:num_bits] if num_bits is not None else bits


def bits_to_bytes(bits):
    assert len(bits) % 8 == 0
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        out.append(byte)
    return bytes(out)


def analyze_roll_quality(rolls, pair_bits=None, target_bits=None):
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
    chi2 = sum((v - expected) ** 2 / expected for v in face_counts.values()) if expected else 0.0
    max_streak = 0
    if rolls:
        cur = rolls[0]; streak = 1; max_streak = 1
        for r in rolls[1:]:
            if r == cur:
                streak += 1
            else:
                max_streak = max(max_streak, streak)
                cur = r; streak = 1
        max_streak = max(max_streak, streak)
    face_min = min(face_counts.values()) if face_counts else 0
    warnings = []
    if n < 24: warnings.append("low sample size (<24 rolls)")
    if total_pairs and ties > max(2, total_pairs * 0.35): warnings.append("high tie rate")
    if max_streak >= 5: warnings.append("long streak detected")
    if face_min == 0: warnings.append("one or more faces never appeared")
    if chi2 > 15.09: warnings.append("chi-square p<0.01 vs uniform")
    if check_pair_yield and non_tie_pairs < target_bits: warnings.append("insufficient unbiased bit yield")
    score = 100
    score -= min(30, max(0, 24 - n)) * 2
    score -= min(20, int(ties * 2))
    score -= min(20, max(0, max_streak - 3) * 4)
    score -= min(20, int(max(0, chi2 - 5)))
    score -= 15 if face_min == 0 else 0
    score -= 15 if check_pair_yield and non_tie_pairs < target_bits else 0
    score = max(0, min(100, score))
    verdict = "GOOD" if score >= 80 and not warnings else "OK" if score >= 55 else "SUSPECT"
    return {"roll_count":n,"pair_count":total_pairs,"tie_count":ties,"non_tie_pairs":non_tie_pairs,"face_counts":face_counts,"chi2":chi2,"max_streak":max_streak,"warnings":warnings,"score":score,"verdict":verdict}


def print_quality_report(q):
    print("\n" + colorize("=== RANDOMNESS QUALITY REPORT ===", "bold"))
    verdict_color = "green" if q["verdict"] == "GOOD" else "yellow" if q["verdict"] == "OK" else "red"
    print("Verdict:       " + colorize(q["verdict"], verdict_color))
    print(f"Score:         {q['score']}/100")
    print(f"Rolls:         {q['roll_count']}")
    print(f"Pairs:         {q['pair_count']}")
    print(f"Ties:          {q['tie_count']}")
    print(f"Non-tie pairs: {q['non_tie_pairs']}")
    print(f"Chi-square:    {q['chi2']:.2f}")
    print(f"Max streak:    {q['max_streak']}")
    print("Face counts:   " + ", ".join(f"{k}:{v}" for k, v in q['face_counts'].items()))
    print("Warnings:      " + (colorize("; ".join(q['warnings']), "red") if q['warnings'] else "none"))


def abort_if_not_good(q):
    if q["verdict"] != "GOOD" or q["warnings"]:
        raise SystemExit("Aborted: randomness quality is not GOOD. Do not generate/fund a wallet from suspect entropy.")


def hash_rolls_to_bits(rolls, num_bits):
    if not rolls: raise ValueError("at least one die roll is required")
    for r in rolls:
        if r < 1 or r > 6: raise ValueError("die rolls must be integers 1-6")
    return bytes_to_bits(hashlib.sha256("".join(str(r) for r in rolls).encode("ascii")).digest(), num_bits)


def collect_hash_roll_entropy_bits(num_bits, roll_count):
    min_rolls = MIN_HASH_ROLLS_24 if num_bits == 256 else MIN_HASH_ROLLS_12
    if roll_count < min_rolls:
        raise SystemExit(f"--roll-count too low for {num_bits}-bit entropy. Minimum: {min_rolls}")
    rolls = []
    print(f"\nNeed {roll_count} physical die rolls. App hashes exact transcript with SHA256.")
    print(colorize("Treat the complete dice-roll transcript as secret key material.", "yellow"))
    print("Enter 1 die roll at a time (1-6). Input is not echoed back. Type 'q' to abort.\n")
    while len(rolls) < roll_count:
        raw = input(f"[{len(rolls)}/{roll_count} rolls] roll: ").strip()
        if raw.lower() == "q": raise SystemExit("Aborted.")
        try:
            r = int(raw)
            if r < 1 or r > 6: raise ValueError
        except ValueError:
            print("  -> invalid input, enter a single digit 1-6")
            continue
        rolls.append(r)
        print("  -> stored")
    q = analyze_roll_quality(rolls)
    print_quality_report(q)
    abort_if_not_good(q)
    return hash_rolls_to_bits(rolls, num_bits)


def collect_entropy_bits(num_bits):
    bits, rolls, pair_bits, pending = [], [], [], []
    max_rolls = max(48, num_bits * 8)
    print(f"\nNeed {num_bits} unbiased bits.")
    print("Enter 1 die roll at a time (1-6). Input/pairs/bits are not echoed. Type 'q' to abort.\n")
    while len(bits) < num_bits:
        if len(rolls) >= max_rolls:
            q = analyze_roll_quality(rolls, pair_bits, num_bits)
            q['warnings'].append(f"roll cap hit ({max_rolls})")
            q['verdict'] = 'SUSPECT'
            print_quality_report(q)
            abort_if_not_good(q)
        raw = input(f"[{len(bits)}/{num_bits} bits] roll: ").strip()
        if raw.lower() == "q": raise SystemExit("Aborted.")
        try:
            r = int(raw)
            if r < 1 or r > 6: raise ValueError
        except ValueError:
            print("  -> invalid input, enter a single digit 1-6")
            continue
        rolls.append(r); pending.append(r)
        print("  -> stored")
        if len(pending) < 2: continue
        a, b = pending; pending.clear(); pair_bits.append((a, b))
        if a == b: continue
        bits.append(0 if a < b else 1)
    q = analyze_roll_quality(rolls, pair_bits, num_bits)
    print_quality_report(q)
    abort_if_not_good(q)
    print(f"Done. Extracted {num_bits} unbiased bits.\n")
    return bits


def mnemonic_gap_check(words):
    parts = words.split()
    if len(parts) not in (12, 24): return
    idxs = sorted(random.sample(range(len(parts)), k=min(5, len(parts))))
    print("\n=== MNEMONIC GAP CHECK ===")
    print("Mnemonic is not reprinted here. Answers are hidden.")
    wrong = []
    for idx in idxs:
        ans = getpass.getpass(f"Enter word #{idx+1}: ").strip().lower()
        if ans != parts[idx]: wrong.append(idx + 1)
    if wrong:
        print("Mnemonic recall check failed at positions: " + ", ".join(f"#{i}" for i in wrong))
        raise SystemExit("Aborted: mnemonic recall check failed. Verify backup before funding.")
    print("Mnemonic recall check: PASS")


def slip10_ed25519_master(seed):
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]


def slip10_ed25519_ckd(k_par, c_par, index):
    index |= 0x80000000
    I = hmac.new(c_par, b'\x00' + k_par + ser32(index), hashlib.sha512).digest()
    return I[:32], I[32:]


def sol_from_seed(seed, path):
    k, c = slip10_ed25519_master(seed)
    for level in path:
        k, c = slip10_ed25519_ckd(k, c, level)
    sk = nacl.signing.SigningKey(k)
    return b58encode(sk.verify_key.encode()), k


def default_derivation_profiles():
    return [
        {"chain":"SOL","label":"SOL Phantom/Solflare m/44'/501'/0'/0'","path":"m/44'/501'/0'/0'","path_tuple":(44,501,0,0)},
        {"chain":"SOL","label":"SOL account 1 m/44'/501'/1'/0'","path":"m/44'/501'/1'/0'","path_tuple":(44,501,1,0)},
    ]


def derive_wallet_profiles(seed):
    rows = []
    for profile in default_derivation_profiles():
        address, secret_bytes = sol_from_seed(seed, profile["path_tuple"])
        rows.append({"chain":profile["chain"],"label":profile["label"],"path":profile["path"],"address":address,"seed_hex":secret_bytes.hex()})
    return rows


def print_derivation_profiles(rows, include_private=False):
    print("\n" + colorize("--- Solana derivation conventions ---", "bold"))
    for row in rows:
        print("\n" + colorize(f"[{row['chain']}] {row['label']}", "cyan"))
        print("Path:   ", colorize(row["path"], "yellow"))
        print("Address:", colorize(row["address"], "green"))
        if include_private:
            print("Seed hex:", row["seed_hex"])


def print_bad_dice_report():
    cases = [("all ones", [1]*40, [(1,1)]*20, 16), ("scripted alternating 1,2", [1,2]*20, [(1,2)]*20, 16)]
    print("\n=== BAD / DISHONEST DICE REPORT ===")
    for label, rolls, pairs, target in cases:
        print(colorize(f"--- {label} ---", "bold"))
        print_quality_report(analyze_roll_quality(rolls, pairs, target))


def parse_args(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    argv = ["--help" if arg == "/help" or arg.replace("\\", "/").endswith("/help") else arg for arg in argv]
    parser = argparse.ArgumentParser(description="Offline Solana wallet generator from physical dice entropy.")
    parser.add_argument("--words", type=int, choices=(12, 24), default=24, help="BIP39 mnemonic length. Default: 24")
    parser.add_argument("--entropy-mode", choices=("hash-rolls", "von-neumann"), default="von-neumann", help="Default: von-neumann")
    parser.add_argument("--roll-count", type=int, default=150, help="Physical die rolls for hash-rolls mode. Minimum/default: 150 for 24 words")
    parser.add_argument("--no-gap-check", dest="gap_check", action="store_false", help="Skip interactive mnemonic recall/gap check")
    parser.add_argument("--show-private-derivations", action="store_true", help="Also print private material for every listed derivation path")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--no-color", dest="color", action="store_const", const="never")
    parser.add_argument("--bad-dice-report", action="store_true", help="Print synthetic bad/dishonest dice quality examples, then exit")
    parser.set_defaults(gap_check=True)
    args = parser.parse_args(argv)
    min_rolls = MIN_HASH_ROLLS_24 if args.words == 24 else MIN_HASH_ROLLS_12
    if args.entropy_mode == "hash-rolls" and args.roll_count < min_rolls:
        parser.error(f"--roll-count must be >= {min_rolls} for {args.words} words")
    return args


def main(argv=None):
    args = parse_args(argv)
    configure_color(args.color)
    if args.bad_dice_report:
        print_bad_dice_report(); return
    print(colorize("Wallet Dice", "cyan"))
    print(colorize("=== Offline dice-based Solana wallet generator ===", "bold"))
    entropy_bits = 128 if args.words == 12 else 256
    bits = collect_entropy_bits(entropy_bits) if args.entropy_mode == "von-neumann" else collect_hash_roll_entropy_bits(entropy_bits, args.roll_count)
    words = Mnemonic("english").to_mnemonic(bits_to_bytes(bits))
    print("\n" + colorize("=" * 60, "yellow"))
    print(colorize("MNEMONIC (write this down on paper/steel):", "yellow"))
    print(colorize(words, "green"))
    print(colorize("=" * 60, "yellow"))
    passphrase = getpass.getpass("\nOptional BIP39 passphrase (leave blank for none): ")
    if passphrase and getpass.getpass("Confirm passphrase: ") != passphrase:
        raise SystemExit("Passphrase mismatch.")
    seed = Mnemonic("english").to_seed(words, passphrase)
    print_derivation_profiles(derive_wallet_profiles(seed), include_private=args.show_private_derivations)
    if not args.show_private_derivations:
        print("\nPrivate material hidden. Use --show-private-derivations only on a trusted airgap if needed.")
    if args.gap_check:
        mnemonic_gap_check(words)
    print("\nVerify these addresses independently in Phantom/Solflare before sending funds.")


if __name__ == "__main__":
    main()
