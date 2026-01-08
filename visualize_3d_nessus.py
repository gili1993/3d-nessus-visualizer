import sys
from plot_3d import plot_3d
from normalize import normalize
from load_scan_json import load_scan_json
from build_graph import build_graph


def main():
    """
    Entry point:
    - Load JSON (default: nessus.json, or CLI arg)
    - Normalize to stable schema
    - Build graph
    - Plot in 3D
    """
    candidates = [
        "nessus.json",
        "nesus_large.json",  # note: your generator uses 'nesus_large.json' (typo kept for compatibility)
    ]

    # Allow command-line argument to override file path:
    # python visualize_3d_nessus.py nesus_large.json
    if len(sys.argv) > 1:
        candidates.insert(0, sys.argv[1])

    chosen, raw = load_scan_json(candidates)
    scan = normalize(raw)

    print(f"[+] Loaded: {chosen}")
    print(f"[+] Hosts: {len(scan.get('hosts', []))}")

    G = build_graph(scan, host_top_n_findings=10)
    print(f"[+] Graph nodes: {G.number_of_nodes()}, edges: {G.number_of_edges()}")

    plot_3d(G)


if __name__ == "__main__":
    main()
