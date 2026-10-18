"""Vault payload encoding.

Two payload shapes are supported, and both are inherited from the tools
sshvault replaced. They are kept byte-for-byte compatible so existing vault
items keep working; changing either would make every item look modified.

Keys, stored under ``SSHKeys__<name>``::

    base64(compact JSON [{"name": "public_key", "value": ...},
                         {"name": "private_key", "value": ...}])

Config files, stored under ``SSHConfig__<path>``::

    base64(raw file content)
"""

from __future__ import annotations

import base64
import json


def encode_keys(public_key: bytes, private_key: bytes) -> bytes:
    """Build the vault ``notes`` payload for a keypair.

    Compact separators are mandatory. ``json.dumps`` defaults to ``", "`` and
    ``": "``; the items already in the vault use the compact form, so the
    default would make every push look dirty and silently rewrite stored bytes.
    """
    values = [
        {"name": "public_key", "value": public_key.decode("utf-8")},
        {"name": "private_key", "value": private_key.decode("utf-8")},
    ]
    payload = json.dumps(values, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(payload)


def decode_keys(notes: str) -> dict[str, str]:
    raw = base64.b64decode(notes, validate=True)
    values = json.loads(raw)
    return {field["name"]: field["value"] for field in values}


def encode_config(content: bytes) -> bytes:
    return base64.b64encode(content)


def decode_config(notes: str) -> bytes:
    return base64.b64decode(notes, validate=True)
