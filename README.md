# Wallet Local Dice Generator

Offline BTC + Solana wallet generator from physical dice entropy.

This project is for air-gapped local wallet generation and deterministic verification. It avoids browser wallet-provider keygen risk by deriving keys locally from dice rolls, with pinned local wheel dependencies and published cryptographic test vectors.

![CLI screenshot](assets/screenshot.svg)

## Security model

What this helps with:

- Avoiding online/web wallet provider key generation.
- Avoiding live package downloads during execution.
- Generating BIP39 mnemonic entropy from physical dice.
- Verifying BIP39, BIP32, SLIP-0010, Base58Check, RIPEMD-160 behavior against independent vectors.
- Showing multiple common BTC/SOL derivation paths so restored wallets can be checked.

What this does not solve:

- Compromised OS, firmware, keyboard, monitor, printer, camera, terminal, RAM, swap, hibernation files, crash dumps, or malware.
- Human transcription errors.
- Bad/fake dice entropy.
- Dice-roll transcript leakage. In hash-rolls mode, the complete dice transcript is secret key material; anyone with all rolls can reproduce the wallet.
- Wrong derivation path during restore.
- Secure zeroization of Python strings or terminal scrollback.
- Any claim of “100% unbreakable” security.

Use tiny test deposits and independent restore checks before sending meaningful funds.

## Defaults

- 24-word BIP39 mnemonic.
- Conservative entropy mode: `von-neumann`.
- Hash-rolls mode default: 150 physical d6 rolls.
- Private material for alternate paths hidden unless explicitly requested.
- Dependencies are installed only by `setup_env.bat` from local `pkgs/` with `--require-hashes`.
- Wallet generation performs zero package installation at runtime.

## Install / run offline

On online prep machine, download wheels matching `requirements-hashes.txt` into `pkgs/`.

On the air-gapped machine:

```bash
python generate_wallet.py
```

Hash-rolls mode:

```bash
python generate_wallet.py --entropy-mode hash-rolls --roll-count 150
```

Bad/dishonest dice report:

```bash
python generate_wallet.py --bad-dice-report --color always
```

Skip mnemonic gap check:

```bash
python generate_wallet.py --no-gap-check
```

Show private material for listed derivation paths only on a trusted airgap:

```bash
python generate_wallet.py --show-private-derivations
```

## Dependency enforcement

Setup is separate from wallet generation:

1. `setup_env.bat` requires 64-bit CPython 3.10 because bundled wheels target cp310/win_amd64.
2. `setup_env.bat` refuses missing `pkgs/` and installs only with:
   - `--no-index`
   - `--find-links=./pkgs`
   - `--require-hashes`
3. `generate_wallet.py` performs zero package installation.
4. At wallet-generation startup, it only verifies:
   - `requirements-hashes.txt`
   - local wheel SHA256 hashes
   - installed package versions
5. It refuses to continue on missing/mismatched dependencies.

## Verification

Run:

```bash
python -m unittest discover -v -s . -p 'test*.py'
```

Current tests cover:

- BIP39 official mnemonic + seed vector.
- BIP32 official vector 1 for secp256k1 master and child keys.
- SLIP-0010 official ed25519 vector 1 master and child keys.
- Base58Check known vector.
- RIPEMD-160 known vector and fallback implementation.
- Hash-rolls randomness reporting bug regression.

## Derivation paths printed

BTC:

- `m/44'/0'/0'/0/0` legacy P2PKH
- `m/44'/0'/1'/0/0` account 1 legacy P2PKH

Solana:

- `m/44'/501'/0'/0'` Phantom/Solflare common
- `m/44'/501'/0'/0'/0'` legacy/deep
- `m/44'/501'/1'/0'` account 1

Same mnemonic plus different path means different address. Record the path and first receiving address.

## Recommended ceremony

1. Use a fresh offline machine.
2. Install only from local `pkgs/`.
3. Roll physical dice yourself.
4. Treat the complete dice-roll transcript as secret key material: never photograph, save, print, log, or retain it.
5. Write mnemonic/passphrase on paper or steel only.
6. Record derivation path and first address.
7. Restore independently in Sparrow/Electrum and Phantom/Solflare before funding.
8. Send tiny test deposit first.
9. Only then send meaningful funds.

## License

MIT. See `LICENSE`.
