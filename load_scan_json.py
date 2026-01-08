import json
import os
from typing import Iterable, Tuple, Any


def load_scan_json(path_candidates: Iterable[str]) -> Tuple[str, Any]:
    """
    Try a list of JSON file paths and return (chosen_path, parsed_json).

    Why:
    - Nice UX: you can pass multiple candidates and load the first that exists.
    - Supports CLI override in visualize_3d_nessus.py
    """
    for p in path_candidates:
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8") as f:
                return p, json.load(f)

    raise FileNotFoundError(f"Could not find any of: {', '.join(path_candidates)}")
