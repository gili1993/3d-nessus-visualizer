def sev_to_size(sev_int: int) -> int:
    """
    Convert severity integer (0..4) to a marker size for Plotly.
    This is a simple baseline mapping (used as a fallback).
    """
    return {0: 5, 1: 7, 2: 9, 3: 11, 4: 13}.get(sev_int, 7)
