"""Identifier generation shared by stores and the firewall pipeline."""

from __future__ import annotations

import uuid


def new_id(prefix: str) -> str:
    """Short, readable, collision-safe identifier (e.g. ``rev_1a2b3c4d5e6f``)."""
    return f"{prefix}_{uuid.uuid4().hex[:12]}"
