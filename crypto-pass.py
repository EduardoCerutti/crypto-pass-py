#!/usr/bin/env python3
"""Crypto Pass for the terminal. Generates the same passwords as the app.

Needs Argon2 bindings: `sudo apt install python3-argon2` on Debian,
or `pip install argon2-cffi` elsewhere.

Usage: crypto-pass.py [--fast] [site] [counter]
The passphrase and password are always asked for without echo, so they never
end up in the shell history or the process list.
"""

import argparse
import base64
import getpass
import hashlib
import json
import re
import sys
import unicodedata

from argon2.exceptions import HashingError
from argon2.low_level import Type, hash_secret_raw

# Must match src/utils/crypto/encrypt.ts, or the passwords will differ
PASSES = 3
PARALLELISM = 4
TAG_LENGTH = 32
MEMORY_KIB = {"v2-fast": 256 * 1024, "v2": 512 * 1024}

# The characters JavaScript's \s matches. Python's \s differs slightly.
JS_WHITESPACE = re.compile(
    "[\t\n\v\f\r    -     　﻿]+"
)


def nfc(text):
    return unicodedata.normalize("NFC", text)


def normalize_site(site):
    return JS_WHITESPACE.sub("", nfc(site)).lower()


def generate(password, phrase, site, counter, version):
    # Same bytes as JSON.stringify in the app
    fields = json.dumps(
        ["crypto-pass-v2", phrase, normalize_site(site), counter],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    salt = hashlib.sha256(nfc(fields).encode("utf-8")).digest()
    tag = hash_secret_raw(
        secret=nfc(password).encode("utf-8"),
        salt=salt,
        time_cost=PASSES,
        memory_cost=MEMORY_KIB[version],
        parallelism=PARALLELISM,
        hash_len=TAG_LENGTH,
        type=Type.ID,
    )
    return base64.b64encode(tag).decode("ascii")


def parse_counter(value):
    if not re.fullmatch(r"[1-9]\d{0,5}", value):
        raise argparse.ArgumentTypeError("counter must be a number from 1 to 999999")
    return int(value)


def main():
    parser = argparse.ArgumentParser(description="Generate a Crypto Pass password.")
    parser.add_argument("site", nargs="?", help="site name, e.g. gmail")
    parser.add_argument("counter", nargs="?", type=parse_counter, default=1)
    parser.add_argument(
        "--fast", action="store_true", help="use v2 fast instead of v2"
    )
    args = parser.parse_args()

    site = args.site if args.site is not None else input("Site name: ")
    if not normalize_site(site):
        parser.error("site name is empty")

    phrase = getpass.getpass("Passphrase: ")
    password = getpass.getpass("Password: ")
    if not phrase or not password:
        parser.error("passphrase and password are required")

    version = "v2-fast" if args.fast else "v2"
    try:
        print(generate(password, phrase, site, args.counter, version))
    except HashingError as error:
        # Usually a failed memory allocation: v2 needs 512 MiB free, v2 fast 256 MiB
        sys.exit("Could not generate the password (%s). Try --fast or free some memory." % error)


if __name__ == "__main__":
    main()
