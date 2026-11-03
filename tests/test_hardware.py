"""Real cryptography and SDK interfaces; no hardware access in automated tests."""

from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from encrypted_project_pro import crypto, hardware

piv = pytest.importorskip("yubikit.piv")


@pytest.fixture(params=["rsa", "p256"])
def device(monkeypatch, request):
    private = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if request.param == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
    )
    session = MagicMock(spec=piv.PivSession)
    session.get_certificate.return_value.public_key.return_value = private.public_key()
    session.get_slot_metadata.return_value = SimpleNamespace(
        pin_policy=piv.PIN_POLICY.ALWAYS,
        touch_policy=piv.TOUCH_POLICY.ALWAYS,
        generated=True,
        public_key=private.public_key(),
    )
    session.decrypt.side_effect = lambda slot, ciphertext, padding: private.decrypt(
        ciphertext, padding
    )
    session.calculate_secret.side_effect = lambda slot, public: private.exchange(
        ec.ECDH(), public
    )

    @contextmanager
    def connect(serial):
        assert serial in [None, 12345]
        yield session, 12345

    monkeypatch.setattr(hardware, "connect", connect)
    return session


@pytest.mark.parametrize("policy", ["any", "all"])
def test_real_sdk_contract_and_crypto(device, policy):
    key = crypto.KeyFile(b"a" * 32)
    blob = crypto.encrypt(
        b"private project", [key, hardware.YubiKeyRecipient()], policy
    )
    assert not device.verify_pin.called
    credentials = {1: hardware.YubiKeyCredential("123456")}
    if policy == "all":
        credentials[0] = key
    assert crypto.decrypt(blob, credentials) == b"private project"
    device.verify_pin.assert_called_once_with("123456")


def test_pin_failure_never_retries(device):
    blob = crypto.encrypt(b"project", [hardware.YubiKeyRecipient()])
    device.verify_pin.side_effect = ValueError("wrong PIN")
    with pytest.raises(ValueError):
        crypto.decrypt(blob, {0: hardware.YubiKeyCredential("wrong")})
    device.verify_pin.assert_called_once()
    device.decrypt.assert_not_called()
    device.calculate_secret.assert_not_called()


def test_wrong_key_rejected_before_pin(device):
    blob = crypto.encrypt(b"project", [hardware.YubiKeyRecipient()])
    replacement = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    ).public_key()
    device.get_certificate.return_value.public_key.return_value = replacement
    device.get_slot_metadata.return_value.public_key = replacement
    with pytest.raises(ValueError, match="does not match"):
        crypto.decrypt(blob, {0: hardware.YubiKeyCredential("123456")})
    device.verify_pin.assert_not_called()


@pytest.mark.parametrize("unsafe", ["pin", "touch", "imported"])
def test_unsafe_device_policy_rejected(device, unsafe):
    metadata = device.get_slot_metadata.return_value
    if unsafe == "pin":
        metadata.pin_policy = piv.PIN_POLICY.NEVER
    elif unsafe == "touch":
        metadata.touch_policy = piv.TOUCH_POLICY.NEVER
    else:
        metadata.generated = False
    with pytest.raises(ValueError):
        crypto.encrypt(b"project", [hardware.YubiKeyRecipient()])
    device.verify_pin.assert_not_called()
