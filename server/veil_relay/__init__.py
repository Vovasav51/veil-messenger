"""Veil relay: minimal zero-knowledge ciphertext relay for the Veil iOS MVP.

The relay stores opaque Signal ciphertexts and public key bundles only. It does
not implement or replace any part of the Signal protocol.
"""

from __future__ import annotations

__all__ = ["__version__", "SERVER_VERSION"]

__version__ = "0.1.0"
# Version reported by GET /health (the API contract version, not the app build).
SERVER_VERSION = "0.1.0"
