from pathlib import Path


def find_asset_path(start: Path, *relative_parts: str) -> Path:
    """Search upward from a module location until the requested asset exists."""
    start = start.resolve()
    search_roots = [start.parent, *start.parents]

    for root in search_roots:
        candidate = root.joinpath(*relative_parts)
        if candidate.exists():
            return candidate

    searched = ", ".join(str(root.joinpath(*relative_parts)) for root in search_roots)
    raise FileNotFoundError(
        f"Unable to locate asset {'/'.join(relative_parts)}. Searched: {searched}"
    )


def maybe_find_asset_path(start: Path, *relative_parts: str) -> Path | None:
    try:
        return find_asset_path(start, *relative_parts)
    except FileNotFoundError:
        return None


def find_asset_dir(start: Path, *relative_parts: str) -> Path:
    path = find_asset_path(start, *relative_parts)
    if not path.is_dir():
        raise NotADirectoryError(f"Expected directory but found file: {path}")
    return path
