# HashCrack

A **dependency-free** hash identifier and dictionary/rule-based password cracker
in pure Python.

HashCrack identifies common hash types by format, then runs offline wordlist
attacks — with optional rule-based mangling (capitalization, appended
digits/symbols, leetspeak, reversal) — against the `hashlib` algorithm family.

No `pip install`, no third-party packages. Python 3.7+ and you're set.

> ⚠️ **Authorized use only.** This is an educational tool for CTFs, lab
> exercises, and auditing the strength of *your own* password hashes. Only run
> it against hashes you have explicit permission to test.

```
$ python -m hashcrack crack 6b1628b016dff46e6fa35684be6acc96 -w wordlists/common.txt
Auto-detected hash type: md5
HashCrack 1.0.0 — attacking md5 hash...

  [+] CRACKED: summer
      21 attempts in 0.0s (108,741/s)
```

## Why I built it

Understanding how dictionary and rule-based attacks work — and how fast a weak
password falls — is core to both offensive testing and defensive password
policy. I built the whole pipeline (identify → generate candidates → hash →
compare) so I can explain exactly why "Summer2026!" is not a strong password.

## Features

- **Hash identification** by format/length: MD5, SHA-1, SHA-224, SHA-256,
  SHA-384, SHA-512, plus recognition (identify-only) of NTLM, bcrypt, and
  `md5crypt`/`sha256crypt`/`sha512crypt`
- **Dictionary attacks** over any wordlist
- **Rule-based mangling** (`--rules`): case variants, appended digits/symbols,
  leetspeak substitutions, and reversal — one base word becomes ~100 candidates
- **Auto type detection**, or force it with `--type`
- **Live progress** with attempts/sec
- **Non-zero exit code** when a hash isn't cracked (handy for scripting)
- **Zero dependencies** + a unit test suite

## Usage

```bash
# Identify a hash
python -m hashcrack identify 5f4dcc3b5aa765d61d8327deb882cf99

# Dictionary attack (auto-detects the type)
python -m hashcrack crack <hash> --wordlist wordlists/common.txt

# Add rule-based mangling to widen coverage
python -m hashcrack crack <hash> -w wordlists/common.txt --rules

# Force a hash type and silence progress
python -m hashcrack crack <hash> -w big.txt --type sha256 --quiet
```

### Supported crack types
`md5`, `sha1`, `sha224`, `sha256`, `sha384`, `sha512`

bcrypt and the `crypt`-style hashes are *identified* but not cracked (they need
per-hash salts and dedicated KDFs outside the stdlib hashlib digests).

## Try it

```bash
bash demo.sh
```

Generates a few hashes and shows identification, a plain dictionary hit, and a
rule-based crack.

## Running the tests

```bash
python -m unittest discover tests -v
```

## Project layout

```
hashcrack/
├── hashcrack/
│   ├── __main__.py   # CLI (identify / crack)
│   ├── identify.py   # hash type detection
│   ├── rules.py      # candidate mangling rules
│   └── cracker.py    # the cracking engine
├── wordlists/
│   └── common.txt    # small demo wordlist
└── tests/            # unittest suite
```

## Roadmap

- Salted hash support (`hash:salt` formats)
- Brute-force / mask mode for short keyspaces
- Multiprocessing for large wordlists
- More mangling rules (toggle case, combinator attacks)

## License

MIT — see [LICENSE](LICENSE).
