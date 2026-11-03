"""Versioned authenticated project container. SPDX-License-Identifier: LGPL-3.0-or-later."""

import base64
import hashlib
import json
import os
import struct
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"PMEECP\x01\n"
MAX_PLAINTEXT = 64 * 1024 * 1024
MAX_HEADER = 64 * 1024
MAX_FACTORS = 8
MAX_FILE = len(MAGIC) + 4 + MAX_HEADER + 12 + MAX_PLAINTEXT + 16
CONTEXT = b"MoleditPy Encrypted Project Pro v1"


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def encode(value):
    return base64.b64encode(value).decode("ascii")


def decode(value, length=None):
    if not isinstance(value, str) or len(value) > MAX_HEADER:
        raise ValueError("Invalid encoded field.")
    result = base64.b64decode(value, validate=True)
    if length is not None and len(result) != length:
        raise ValueError("Invalid field length.")
    return result


def read_bounded(path, limit):
    with open(path, "rb") as handle:
        value = handle.read(limit + 1)
    if len(value) > limit:
        raise ValueError("File exceeds the size limit.")
    return value


def atomic_write(path, value):
    target = Path(path).absolute()
    fd, temporary = tempfile.mkstemp(prefix=".pmeecp-", dir=target.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def create_key_file(path):
    # Exclusive creation avoids destroying a key already used by other files.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(os.urandom(32))


def oaep():
    return padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=CONTEXT
    )


def public_bytes(key):
    return key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def key_id(key):
    return hashlib.sha256(public_bytes(key)).hexdigest()


def derive(secret, salt, aad):
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=CONTEXT + aad
    ).derive(secret)


class Password:
    kind = "password"

    def __init__(self, value):
        if not isinstance(value, str) or not value:
            raise ValueError("Password cannot be empty.")
        self.value = value.encode("utf-8")

    def key(self, salt):
        return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(self.value)

    def wrap(self, secret, aad):
        salt, nonce = os.urandom(16), os.urandom(12)
        return {
            "kind": self.kind,
            "salt": encode(salt),
            "nonce": encode(nonce),
            "wrapped": encode(AESGCM(self.key(salt)).encrypt(nonce, secret, aad)),
        }

    def unwrap(self, record, aad):
        return AESGCM(self.key(decode(record["salt"], 16))).decrypt(
            decode(record["nonce"], 12), decode(record["wrapped"], 48), aad
        )


class KeyFile(Password):
    kind = "key-file"

    def __init__(self, value):
        if len(value) != 32:
            raise ValueError(
                "Key files must contain exactly 32 random bytes. Use Generate key file."
            )
        self.value = value

    def key(self, salt):
        return derive(self.value, salt, b"key-file")


class PublicKey:
    kind = "public-key"

    def __init__(self, key):
        self.public = key
        if isinstance(key, rsa.RSAPublicKey):
            if key.key_size < 2048 or key.key_size > 4096:
                raise ValueError("RSA keys must have 2048–4096 bits.")
        elif not isinstance(key, x25519.X25519PublicKey) and not (
            isinstance(key, ec.EllipticCurvePublicKey)
            and isinstance(key.curve, ec.SECP256R1)
        ):
            raise ValueError(
                "Supported public keys: RSA 2048–4096, X25519, ECDH P-256."
            )

    def wrap(self, secret, aad):
        result = {"kind": self.kind, "key_id": key_id(self.public)}
        if isinstance(self.public, rsa.RSAPublicKey):
            result.update(
                algorithm="RSA-OAEP-SHA256",
                wrapped=encode(self.public.encrypt(secret, oaep())),
            )
            return result
        if isinstance(self.public, x25519.X25519PublicKey):
            ephemeral = x25519.X25519PrivateKey.generate()
            shared = ephemeral.exchange(self.public)
            algorithm = "X25519-HKDF-SHA256"
        else:
            ephemeral = ec.generate_private_key(ec.SECP256R1())
            shared = ephemeral.exchange(ec.ECDH(), self.public)
            algorithm = "ECDH-P256-HKDF-SHA256"
        salt, nonce = os.urandom(16), os.urandom(12)
        result.update(
            algorithm=algorithm,
            ephemeral=encode(public_bytes(ephemeral.public_key())),
            salt=encode(salt),
            nonce=encode(nonce),
            wrapped=encode(
                AESGCM(derive(shared, salt, aad)).encrypt(nonce, secret, aad)
            ),
        )
        return result


class PrivateKey:
    kind = "public-key"

    def __init__(self, key):
        self.private = key
        self.public = PublicKey(key.public_key()).public

    def unwrap(self, record, aad):
        if record["key_id"] != key_id(self.public):
            raise ValueError("The selected private key does not match this recipient.")
        if record["algorithm"] == "RSA-OAEP-SHA256" and isinstance(
            self.private, rsa.RSAPrivateKey
        ):
            return self.private.decrypt(
                decode(record["wrapped"], self.private.key_size // 8), oaep()
            )
        ephemeral = serialization.load_der_public_key(decode(record["ephemeral"]))
        if (
            record["algorithm"] == "X25519-HKDF-SHA256"
            and isinstance(self.private, x25519.X25519PrivateKey)
            and isinstance(ephemeral, x25519.X25519PublicKey)
        ):
            shared = self.private.exchange(ephemeral)
        elif (
            record["algorithm"] == "ECDH-P256-HKDF-SHA256"
            and isinstance(self.private, ec.EllipticCurvePrivateKey)
            and isinstance(ephemeral, ec.EllipticCurvePublicKey)
            and isinstance(ephemeral.curve, ec.SECP256R1)
        ):
            shared = self.private.exchange(ec.ECDH(), ephemeral)
        else:
            raise ValueError("Unsupported key agreement.")
        return AESGCM(derive(shared, decode(record["salt"], 16), aad)).decrypt(
            decode(record["nonce"], 12), decode(record["wrapped"], 48), aad
        )


def _xor(values):
    result = bytearray(32)
    for value in values:
        if len(value) != 32:
            raise ValueError("Invalid key share.")
        for index, byte in enumerate(value):
            result[index] ^= byte
    return bytes(result)


def factor_aad(header, index):
    return CONTEXT + canonical(
        {"id": header["id"], "policy": header["policy"], "index": index}
    )


def encrypt(data, factors, policy="any"):
    if not isinstance(data, bytes) or len(data) > MAX_PLAINTEXT:
        raise ValueError("Project exceeds 64 MiB.")
    if policy not in {"any", "all"} or not 1 <= len(factors) <= MAX_FACTORS:
        raise ValueError("Choose Any or All and one to eight factors.")
    header = {"version": 1, "id": encode(os.urandom(16)), "policy": policy}
    dek = os.urandom(32)
    if policy == "all":
        shares = [os.urandom(32) for _ in factors[1:]]
        shares.append(_xor([dek, *shares]))
    else:
        shares = [dek] * len(factors)
    header["factors"] = [
        factor.wrap(share, factor_aad(header, index))
        for index, (factor, share) in enumerate(zip(factors, shares, strict=True))
    ]
    encoded = canonical(header)
    if len(encoded) > MAX_HEADER:
        raise ValueError("Too many recipient details.")
    nonce = os.urandom(12)
    prefix = MAGIC + struct.pack(">I", len(encoded)) + encoded
    return prefix + nonce + AESGCM(dek).encrypt(nonce, data, prefix)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate header field.")
        result[key] = value
    return result


def inspect_container(blob):
    if (
        not isinstance(blob, bytes)
        or len(blob) > MAX_FILE
        or not blob.startswith(MAGIC)
    ):
        raise ValueError("Not a supported .pmeecp file.")
    offset = len(MAGIC)
    if len(blob) < offset + 4:
        raise ValueError("Truncated container.")
    size = struct.unpack(">I", blob[offset : offset + 4])[0]
    end = offset + 4 + size
    if not 1 <= size <= MAX_HEADER or len(blob) < end + 28:
        raise ValueError("Invalid header size or truncated payload.")
    header = json.loads(blob[offset + 4 : end], object_pairs_hook=_object)
    if (
        not isinstance(header, dict)
        or set(header) != {"version", "id", "policy", "factors"}
        or header["version"] != 1
        or type(header["version"]) is not int
    ):
        raise ValueError("Unsupported container version.")
    decode(header["id"], 16)
    if (
        header["policy"] not in {"any", "all"}
        or not isinstance(header["factors"], list)
        or not 1 <= len(header["factors"]) <= MAX_FACTORS
    ):
        raise ValueError("Invalid unlock policy.")
    for record in header["factors"]:
        if not isinstance(record, dict) or record.get("kind") not in {
            "password",
            "key-file",
            "public-key",
            "yubikey",
        }:
            raise ValueError("Unsupported factor.")
        if record["kind"] in {"password", "key-file"}:
            decode(record["salt"], 16)
            decode(record["nonce"], 12)
            decode(record["wrapped"], 48)
        else:
            if not isinstance(record.get("key_id"), str) or len(record["key_id"]) != 64:
                raise ValueError("Invalid public-key identifier.")
            if record.get("algorithm") not in {
                "RSA-OAEP-SHA256",
                "X25519-HKDF-SHA256",
                "ECDH-P256-HKDF-SHA256",
            }:
                raise ValueError("Unsupported public-key algorithm.")
            decode(record["wrapped"])
    return header, end


def decrypt(blob, credentials):
    """credentials maps header factor indexes to credential objects."""
    header, end = inspect_container(blob)
    shares = []
    if not isinstance(credentials, dict) or not credentials:
        raise ValueError("No credentials supplied.")
    if header["policy"] == "all" and set(credentials) != set(
        range(len(header["factors"]))
    ):
        raise ValueError("Every factor is required by this file.")
    for index, credential in credentials.items():
        if type(index) is not int or not 0 <= index < len(header["factors"]):
            raise ValueError("Invalid factor index.")
        record = header["factors"][index]
        if credential.kind != record["kind"]:
            raise ValueError("Credential type does not match.")
        share = credential.unwrap(record, factor_aad(header, index))
        if len(share) != 32:
            raise ValueError("Invalid key share.")
        if header["policy"] == "any":
            return AESGCM(share).decrypt(
                blob[end : end + 12], blob[end + 12 :], blob[:end]
            )
        shares.append(share)
    return AESGCM(_xor(shares)).decrypt(
        blob[end : end + 12], blob[end + 12 :], blob[:end]
    )
