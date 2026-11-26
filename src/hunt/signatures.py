"""Signature scanning: the marker, and candidate AES key material."""

from __future__ import annotations

# A 32-byte buffer cannot have more than log2(32) = 5 bits/byte of Shannon
# entropy, so an entropy threshold is the wrong test for a key-sized blob.
# Random bytes show ~30 distinct values out of 32; repeated or structured data
# does not.
MIN_DISTINCT_BYTES = 24


def find_all(haystack: bytes, needle: bytes) -> list[int]:
    """All offsets of needle, allowing overlaps. Empty needle yields []."""
    if not needle:
        return []
    hits: list[int] = []
    start = 0
    while True:
        index = haystack.find(needle, start)
        if index < 0:
            return hits
        hits.append(index)
        start = index + 1


def marker_hits(data: bytes, marker: bytes) -> list[int]:
    return find_all(data, marker)


def looks_like_key(block: bytes) -> bool:
    """A 32-byte random blob, by shape rather than by entropy."""
    if len(block) != 32:
        return False
    if block == b"\x00" * 32:
        return False
    if len(set(block)) < MIN_DISTINCT_BYTES:
        return False
    # Random data essentially never contains a run of eight identical bytes.
    return all(block[i : i + 8] != block[i] * 8 for i in range(len(block) - 7))
