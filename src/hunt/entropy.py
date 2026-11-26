"""Shannon entropy helpers.

The detector does not care that a region is high entropy. Plenty of normal
regions are: .NET heaps, JPEGs, zipped resources. It cares that a *stable*
region got more random while the process was idle. That is why the delta
functions exist and are the ones the rules use.
"""

from __future__ import annotations

import math
from collections import Counter

DEFAULT_BLOCK = 4096


def shannon(data: bytes) -> float:
    """Bits per byte, 0.0..8.0. Empty input is defined as 0.0."""
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    result = 0.0
    for count in counts.values():
        p = count / total
        result -= p * math.log2(p)
    return result


def block_entropies(data: bytes, block_size: int = DEFAULT_BLOCK) -> list[float]:
    """Per-block entropy, ignoring a trailing partial block."""
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    full = len(data) // block_size
    return [shannon(data[i * block_size : (i + 1) * block_size]) for i in range(full)]


def mean_block_entropy(data: bytes, block_size: int = DEFAULT_BLOCK) -> float:
    """Mean entropy over full blocks. Falls back to whole-buffer entropy."""
    blocks = block_entropies(data, block_size)
    if not blocks:
        return shannon(data)
    return sum(blocks) / len(blocks)


def entropy_delta(baseline: float | None, current: float | None) -> float | None:
    if baseline is None or current is None:
        return None
    return current - baseline
