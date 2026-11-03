"""Read-only PIV integration. Never provisions, resets, or writes device keys."""

from contextlib import contextmanager

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import PublicKey, decode, derive, key_id, oaep


@contextmanager
def connect(serial):
    try:
        from ykman.device import list_all_devices
        from yubikit.core.smartcard import SmartCardConnection
        from yubikit.piv import PivSession
    except ImportError as error:
        raise ValueError(
            "YubiKey support requires the optional yubikey-manager package."
        ) from error
    devices = [
        (device, info)
        for device, info in list_all_devices()
        if serial is None or info.serial == serial
    ]
    if len(devices) != 1:
        raise ValueError("Connect exactly one matching PIV-capable YubiKey.")
    device, info = devices[0]
    with device.open_connection(SmartCardConnection) as connection:
        yield PivSession(connection), info.serial


def slot_value(slot):
    from yubikit.piv import SLOT

    if type(slot) is not int or (slot != 0x9D and not 0x82 <= slot <= 0x95):
        raise ValueError(
            "Use PIV key-management slot 9d or a retired key-management slot 82–95."
        )
    return SLOT(slot)


def checked_public(session, slot):
    from yubikit.piv import PIN_POLICY, TOUCH_POLICY

    metadata = session.get_slot_metadata(slot)
    if (
        metadata.pin_policy not in {PIN_POLICY.ONCE, PIN_POLICY.ALWAYS}
        or metadata.touch_policy != TOUCH_POLICY.ALWAYS
    ):
        raise ValueError(
            "Configure the PIV key with PIN Once/Always and Touch Always before use."
        )
    if not metadata.generated:
        raise ValueError("Use a private key generated inside the YubiKey.")
    public = session.get_certificate(slot).public_key()
    if key_id(public) != key_id(metadata.public_key):
        raise ValueError("PIV certificate and slot key do not match.")
    return public


class YubiKeyRecipient:
    kind = "yubikey"

    def __init__(self, serial=None, slot=0x9D):
        self.serial, self.slot = serial, slot

    def wrap(self, secret, aad):
        with connect(self.serial) as (session, serial):
            key = checked_public(session, slot_value(self.slot))
            if not isinstance(key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
                raise ValueError("PIV requires an RSA or P-256 encryption key.")
            result = PublicKey(key).wrap(secret, aad)
            result.update(kind=self.kind, serial=serial, slot=self.slot)
            return result


class YubiKeyCredential:
    kind = "yubikey"

    def __init__(self, pin):
        if not pin:
            raise ValueError("PIV PIN is required.")
        self.pin = pin

    def unwrap(self, record, aad):
        # Validate routing fields before accessing a device or consuming a PIN retry.
        if type(record.get("serial")) is not int or record["serial"] <= 0:
            raise ValueError("Invalid YubiKey serial.")
        slot = slot_value(record["slot"])
        with connect(record["serial"]) as (session, _serial):
            public = checked_public(session, slot)
            if key_id(public) != record["key_id"]:
                raise ValueError(
                    "YubiKey certificate does not match the encrypted file."
                )
            if record["algorithm"] == "RSA-OAEP-SHA256" and isinstance(
                public, rsa.RSAPublicKey
            ):
                ciphertext = decode(record["wrapped"], public.key_size // 8)
                session.verify_pin(self.pin)
                return session.decrypt(slot, ciphertext, oaep())
            if (
                record["algorithm"] != "ECDH-P256-HKDF-SHA256"
                or not isinstance(public, ec.EllipticCurvePublicKey)
                or not isinstance(public.curve, ec.SECP256R1)
            ):
                raise ValueError("Unsupported PIV key agreement.")
            peer = serialization.load_der_public_key(decode(record["ephemeral"]))
            if not isinstance(peer, ec.EllipticCurvePublicKey) or not isinstance(
                peer.curve, ec.SECP256R1
            ):
                raise ValueError("Invalid PIV peer key.")
            salt, nonce, wrapped = (
                decode(record["salt"], 16),
                decode(record["nonce"], 12),
                decode(record["wrapped"], 48),
            )
            session.verify_pin(self.pin)
            shared = session.calculate_secret(slot, peer)
            return AESGCM(derive(shared, salt, aad)).decrypt(nonce, wrapped, aad)
