def sev_to_symbol(kind: str) -> str:
    """
    Map node type ("kind") to a Plotly marker symbol.
    """
    return {
        "subnet": "diamond",
        "host": "circle",
        "service": "square",
        "finding": "x",
    }.get(kind, "circle")
