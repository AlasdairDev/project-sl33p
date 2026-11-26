"""Region bookkeeping: diffing snapshots, choosing what is worth reading."""

from __future__ import annotations

from models import Region, RegionChange

# Do not try to read an entire 2 GB reserved region because someone asked.
PER_REGION_CAP = 1 << 17  # 128 KiB of each region is plenty for entropy + marker
MIN_INTERESTING = 4096
MAX_REGION_FOR_READ = 1 << 22  # 4 MiB
SMALL_REGION = 1 << 17  # re-read unchanged private regions up to 128 KiB


def index_by_base(regions: list[Region]) -> dict[int, Region]:
    return {region.base: region for region in regions}


def diff(before: list[Region], after: list[Region]) -> list[RegionChange]:
    """Protection changes for regions present in both snapshots with equal size."""
    previous = index_by_base(before)
    changes: list[RegionChange] = []
    for region in after:
        old = previous.get(region.base)
        if old is None or old.size != region.size:
            continue
        if old.protect != region.protect:
            changes.append(
                RegionChange(
                    base=region.base,
                    size=region.size,
                    before=old.protect,
                    after=region.protect,
                )
            )
    return changes


def worth_reading(region: Region) -> bool:
    return (
        region.committed
        and region.readable
        and region.private
        and MIN_INTERESTING <= region.size <= MAX_REGION_FOR_READ
    )


def read_length(region: Region) -> int:
    return min(region.size, PER_REGION_CAP)


def interesting_bases(
    baseline: list[Region], current: list[Region], changes: list[RegionChange]
) -> set[int]:
    """Everything worth (re)reading on a tick.

    The whole private working set is cheaper than it sounds on a 64 KiB lab
    payload, but this keeps the hunter usable against a real console app too.
    """
    bases = set()
    baseline_protect = {region.base: region.protect for region in baseline}
    changed = {change.base for change in changes}

    for region in current:
        if not worth_reading(region):
            continue
        if region.base in changed:
            bases.add(region.base)
        elif baseline_protect.get(region.base) is None:
            bases.add(region.base)
        elif region.size <= SMALL_REGION:
            bases.add(region.base)
    return bases
