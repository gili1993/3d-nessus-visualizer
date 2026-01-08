# Maps common Nessus-like severity labels into a numeric scale: 0..4
SEV_ORDER = {
    "Informational": 0,
    "Info": 0,
    "Low": 1,
    "Medium": 2,
    "High": 3,
    "Critical": 4,
}


def sev_to_int(sev: str | int | None) -> int:
    """
    Convert severity value into an integer in range 0..4.

    Supports:
    - None -> defaults to Low (1)
    - "0".."4" strings or int values (Nessus sometimes uses numeric)
    - common string labels: Info/Low/Medium/High/Critical
    """
    if sev is None:
        return 1

    # If severity is already numeric (int), clamp to 0..4
    if isinstance(sev, int):
        return max(0, min(4, sev))

    sev_str = str(sev).strip()

    # If severity is numeric in a string form
    if sev_str.isdigit():
        return max(0, min(4, int(sev_str)))

    return SEV_ORDER.get(sev_str, 1)  # default to Low (1)
