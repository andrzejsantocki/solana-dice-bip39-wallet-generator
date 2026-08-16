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
- Wrong derivation path during restore.
- Secure zeroization of Python strings or terminal scrollback.
- Any claim of “100% unbreakable” security.

Use tiny test deposits and independent restore checks before sending meaningful funds.

## Defaults

- 24-word BIP39 mnemonic.
- Conservative entropy mode: `von-neumann`.
- Hash-rolls mode default: 150 physical d6 rolls.
- Private material for alternate paths hidden unless explicitly requested.
- Runtime dependency install is forced from local `pkgs/` only, with `--require-hashes`.

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

At startup, before importing wallet dependencies, the script:

1. reads `requirements-hashes.txt`
2. verifies local wheel hashes in `pkgs/`
3. runs pip with:
   - `--no-index`
   - `--find-links=./pkgs`
   - `--require-hashes`
   - `--force-reinstall`
4. refuses to continue on missing/mismatched wheels

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
4. Write mnemonic/passphrase on paper or steel only.
5. Record derivation path and first address.
6. Restore independently in Sparrow/Electrum and Phantom/Solflare before funding.
7. Send tiny test deposit first.
8. Only then send meaningful funds.

## License

MIT. See `LICENSE`.
