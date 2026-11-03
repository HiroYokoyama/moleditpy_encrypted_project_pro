import json
import struct

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import ec, rsa, x25519

from encrypted_project_pro import crypto as c


@pytest.fixture(scope='module')
def keys():
    return [rsa.generate_private_key(public_exponent=65537, key_size=2048),
            x25519.X25519PrivateKey.generate(), ec.generate_private_key(ec.SECP256R1())]


@pytest.mark.parametrize('index', range(3))
@pytest.mark.parametrize('policy', ['any', 'all'])
def test_real_public_key_roundtrip(keys, index, policy):
    key = keys[index]
    value = c.encrypt(b'{"molecule":"benzene"}', [c.PublicKey(key.public_key())], policy)
    assert c.decrypt(value, {0: c.PrivateKey(key)}) == b'{"molecule":"benzene"}'


def test_password_unicode_and_wrong_password():
    blob = c.encrypt(b'project', [c.Password('long passphrase \u03bb')])
    assert c.decrypt(blob, {0: c.Password('long passphrase \u03bb')}) == b'project'
    with pytest.raises(InvalidTag):
        c.decrypt(blob, {0: c.Password('wrong')})


@pytest.mark.parametrize('policy', ['any', 'all'])
def test_multi_factor_policy(keys, policy):
    key = c.KeyFile(bytes(range(32)))
    private = keys[1]
    blob = c.encrypt(b'secret', [key, c.PublicKey(private.public_key())], policy)
    if policy == 'any':
        assert c.decrypt(blob, {0: key}) == b'secret'
        assert c.decrypt(blob, {1: c.PrivateKey(private)}) == b'secret'
    else:
        for credentials in [{0: key}, {1: c.PrivateKey(private)}]:
            with pytest.raises(ValueError, match='Every factor'):
                c.decrypt(blob, credentials)
        assert c.decrypt(blob, {0: key, 1: c.PrivateKey(private)}) == b'secret'
        with pytest.raises(InvalidTag):
            c.decrypt(blob, {0: c.KeyFile(b'x'*32), 1: c.PrivateKey(private)})


@pytest.mark.parametrize('where', ['payload', 'nonce', 'policy', 'id', 'factor', 'reorder'])
def test_tamper_detection(where):
    first, second = c.KeyFile(b'a'*32), c.KeyFile(b'b'*32)
    blob = c.encrypt(b'secret', [first, second])
    header, end = c.inspect_container(blob)
    if where in ['payload', 'nonce']:
        data = bytearray(blob)
        data[-1 if where == 'payload' else end] ^= 1
        changed = bytes(data)
    else:
        if where == 'policy':
            header['policy'] = 'all'
        elif where == 'id':
            header['id'] = c.encode(b'c'*16)
        elif where == 'factor':
            header['factors'][1]['salt'] = c.encode(b'c'*16)
        else:
            header['factors'].reverse()
        encoded = c.canonical(header)
        changed = c.MAGIC + struct.pack('>I',len(encoded)) + encoded + blob[end:]
    with pytest.raises((ValueError, InvalidTag)):
        c.decrypt(changed, {0: first})


def test_fresh_keys_and_no_plaintext():
    key = c.KeyFile(b'a'*32)
    first, second = [c.encrypt(b'private molecular structure', [key]) for _ in range(2)]
    assert first != second and b'private molecular structure' not in first
    assert b'a'*32 not in first


@pytest.mark.parametrize('blob', [b'', b'PMEECP', c.MAGIC, c.MAGIC+b'\xff'*4, c.MAGIC+b'\x00'*4])
def test_bad_inputs(blob):
    with pytest.raises(ValueError):
        c.inspect_container(blob)


def test_duplicate_header_fields_rejected():
    encoded = b'{"version":1,"version":1}'
    with pytest.raises(ValueError, match='Duplicate'):
        c.inspect_container(c.MAGIC+struct.pack('>I', len(encoded))+encoded+b'x'*28)


def test_key_file_exclusive_and_size(tmp_path):
    path = tmp_path/'private.key'
    c.create_key_file(path)
    assert len(path.read_bytes()) == 32
    with pytest.raises(FileExistsError):
        c.create_key_file(path)
    for length in [0, 31, 33]:
        with pytest.raises(ValueError):
            c.KeyFile(b'x'*length)


def test_atomic_failure_preserves_existing_file(tmp_path, monkeypatch):
    path = tmp_path/'project.pmeecp'
    path.write_bytes(b'previous')
    def fail(*args):
        raise OSError('failure')
    monkeypatch.setattr(c.os, 'replace', fail)
    with pytest.raises(OSError):
        c.atomic_write(path, b'new encrypted file')
    assert path.read_bytes() == b'previous'
    assert list(tmp_path.iterdir()) == [path]


def test_size_and_factor_limits(monkeypatch):
    monkeypatch.setattr(c, 'MAX_PLAINTEXT', 2)
    with pytest.raises(ValueError):
        c.encrypt(b'big', [c.KeyFile(b'a'*32)])
    for factors, policy in [([], 'any'), ([c.KeyFile(b'a'*32)]*9, 'all'), ([c.KeyFile(b'a'*32)], 'bad')]:
        with pytest.raises(ValueError):
            c.encrypt(b'ok', factors, policy)


def test_invalid_record_rejected_before_kdf():
    blob = c.encrypt(b'ok', [c.KeyFile(b'a'*32)])
    header, end = c.inspect_container(blob)
    header['factors'][0]['salt'] = c.encode(b'bad')
    encoded = json.dumps(header).encode()
    with pytest.raises(ValueError):
        c.inspect_container(c.MAGIC+struct.pack('>I',len(encoded))+encoded+blob[end:])
