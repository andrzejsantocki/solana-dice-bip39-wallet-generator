# Solana Dice BIP39 Wallet Generator

[![tests](https://github.com/andrzejsantocki/solana-dice-bip39-wallet-generator/actions/workflows/tests.yml/badge.svg)](https://github.com/andrzejsantocki/solana-dice-bip39-wallet-generator/actions/workflows/tests.yml)

![Offline Solana Wallet Generator cover](assets/cover.png)

Offline Solana wallet generator from physical dice entropy.

![CLI screenshot](assets/screenshot.svg)

## Security model

Helps with:

- Local Solana key generation without browser wallet-provider keygen.
- Physical dice entropy.
- Von Neumann debiasing by default, assuming one independently rolled physical d6 or no fixed first/second roles across different dice.
- Pinned local wheel dependencies.
- Local-only operation with pinned dependency artifacts.

Does not solve:

- Compromised OS/firmware/peripherals.
- RAM/swap/hibernation/crash-dump leakage.
- Bad/fake dice.
- Human backup mistakes.
- Secure zeroization of Python strings.

The complete dice-roll transcript is secret key material, especially in hash-rolls mode. Never photograph, save, print, log, or retain it.

## Defaults

- 24-word BIP39 mnemonic.
- Conservative entropy mode: `von-neumann`.
- Hash-rolls mode minimum/default: 150 physical d6 rolls for 24 words.
- Generation aborts if the dice anomaly screen detects a statistical anomaly. This screen is a sanity check, not an entropy proof.
- Von Neumann mode gates structural anomalies only (streaks, missing faces, pair yield): the </> extractor debiases any single IID die, so fair-die face uniformity is not required. Hash-rolls mode also gates fair-die uniformity (chi-square, tie rate) because hashing cannot create entropy the die did not produce.
- BIP39 passphrase default: none, matching common Phantom/Solflare mnemonic-only recovery.
- BIP39 passphrase is advanced opt-in via `--bip39-passphrase`; only use it after proving your restore wallet supports mnemonic + passphrase.
- Solana paths only:
  - `m/44'/501'/0'/0'`
  - `m/44'/501'/1'/0'`

## Setup and run

On the air-gapped Windows machine:

```bat
setup_env.bat
.venv\Scripts\python.exe -I generate_wallet.py
```

Hash-rolls mode:

```bat
.venv\Scripts\python.exe -I generate_wallet.py --entropy-mode hash-rolls --roll-count 150
```

Bad dice report:

```bat
.venv\Scripts\python.exe -I generate_wallet.py --bad-dice-report --color always
```

## BIP39 passphrase compatibility

By default, this tool uses no BIP39 passphrase. That matches common Phantom/Solflare recovery flows that ask for only the 12/24 words.

A BIP39 passphrase changes the seed completely. The same words with a passphrase produce different Solana addresses. This wallet requires BOTH the mnemonic and the exact BIP39 passphrase for recovery. A wallet that does not support BIP39 passphrase entry will derive different addresses. Do not fund a passphrase-derived wallet unless you have independently restored the same address in software that explicitly supports BIP39 passphrase + the same derivation path.

Use passphrase mode only if you have tested the full restore path:

```bat
.venv\Scripts\python.exe -I generate_wallet.py --bip39-passphrase
```

## Dependency enforcement

Setup is separate from wallet generation:

1. `setup_env.bat` requires 64-bit CPython 3.10 because bundled wheels target cp310/win_amd64.
2. `setup_env.bat` refuses missing `pkgs/` and installs only with:
   - `--no-index`
   - `--find-links=./pkgs`
   - `--require-hashes`
3. `generate_wallet.py` performs zero package installation; wallet generation performs zero package installation.
4. At wallet-generation startup, it verifies:
   - `requirements-hashes.txt`
   - local wheel SHA256 hashes
   - exact `pkgs/*.whl` allowlist
   - installed package versions

## Verification

Run the built-in self-test before any wallet ceremony:

```bat
.venv\Scripts\python.exe -I generate_wallet.py --self-test
```

The self-test and CI test suite check BIP39 official entropy/seed vectors, SLIP-0010 ed25519 master/child vectors, Base58 leading-zero encoding, Solana golden addresses for `m/44'/501'/0'/0'`, `m/44'/501'/1'/0'`, and the BIP39 `TREZOR` passphrase case, plus wheel allowlist regressions. CI runs these tests on every push/PR.

Developer test run:

```bash
python -m unittest discover -v -s . -p 'test*.py'
```

## Memory hygiene limits

Python cannot securely zeroize all mnemonic/passphrase/seed material. Secrets can remain in interpreter objects, terminal scrollback, RAM, swap, hibernation files, crash dumps, malware logs, and peripheral/firmware capture. For serious key ceremonies:

- use a fresh offline machine/session
- disable swap/pagefile and hibernation before the ceremony
- avoid screenshots, clipboard, terminal logging, shell history, and networked printers
- power off after use if you cannot trust RAM persistence assumptions
- prefer paper/steel backup only

This tool avoids intentionally saving secrets and uses hidden input for dice/passphrase/check prompts, but OS-level memory hygiene remains the user's responsibility.

## Wheel reproducibility / supply-chain notes

Bundled wheels are installed only with `--no-index --find-links=./pkgs --require-hashes`. The runtime also verifies `requirements-hashes.txt`, local wheel SHA256 hashes, exact `pkgs/*.whl` allowlist, installed versions, and import locations.

For higher assurance, compare the committed wheel hashes against independently downloaded PyPI artifacts on a separate trusted machine, or publish the expected hashes in an independently signed release note/tag. A repository compromise could otherwise update both `pkgs/*.whl` and `requirements-hashes.txt` together.

## Recommended ceremony

1. Fresh offline machine.
2. Install only from local `pkgs/` via `setup_env.bat`.
3. Roll one physical d6 yourself, independently for every entry. If using multiple dice, do not assign permanent first/second pair roles to different dice.
4. Do not retain dice transcript.
5. Write mnemonic/passphrase on paper or steel only.
6. Record derivation path and first address.
7. Restore independently in Phantom/Solflare before funding.
8. Send tiny test deposit first.

## License

MIT. See `LICENSE`.
