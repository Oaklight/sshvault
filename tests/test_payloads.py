"""Payload encoding must stay byte-compatible with existing vault items."""

from __future__ import annotations

import base64

import pytest

from sshvault.payloads import decode_config, decode_keys, encode_config, encode_keys


def test_encode_keys_is_compact_json_with_public_first():
    notes = encode_keys(b"ssh-ed25519 AAAA pub\n", b"-----BEGIN priv\n")
    decoded = base64.b64decode(notes)
    # The items already in the vault use compact JSON; default separators would
    # make every push look dirty and silently rewrite stored bytes.
    assert b'": ' not in decoded
    assert b'", ' not in decoded
    assert decoded.startswith(b'[{"name":"public_key"')
    assert decoded.index(b"public_key") < decoded.index(b"private_key")


def test_encode_keys_matches_the_inherited_layout():
    notes = encode_keys(b"PUB", b"PRIV")
    assert base64.b64decode(notes) == (
        b'[{"name":"public_key","value":"PUB"},{"name":"private_key","value":"PRIV"}]'
    )


def test_keys_round_trip_preserves_trailing_newline():
    public = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test@host\n"
    private = (
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    fields = decode_keys(encode_keys(public, private).decode())
    assert fields["public_key"].encode() == public
    assert fields["private_key"].encode() == private


def test_encode_keys_rejects_binary():
    with pytest.raises(UnicodeDecodeError):
        encode_keys(b"\xff\xfe", b"\xff")


def test_config_round_trip_handles_binary_and_newlines():
    content = b"Host x\n  User y\n\n\x00\xff"
    assert decode_config(encode_config(content).decode()) == content


def test_decode_rejects_invalid_base64():
    with pytest.raises(ValueError):
        decode_config("not base64!!")
