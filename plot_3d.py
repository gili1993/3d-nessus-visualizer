import math  # used to set layout spacing
import networkx as nx  # builds the graph (nodes + edges)
import plotly.graph_objects as go  # draws the 3D interactive plot
from sev_to_symbol import sev_to_symbol


def risk_to_size(kind: str, risk_score: float, severity_int: int) -> float:
    """
    Map risk_score to marker size.

    Why:
    - Visual priority should be driven by risk, not only severity.
    - Hosts should generally appear larger than services/findings.

    This is intentionally simple (MVP). Later we can add log scaling.
    """
    risk_score = float(risk_score or 0.0)

    if kind == "finding":
        # Findings: base size + scaled risk
        # Example: risk 0..20 -> size ~6..18
        return 6 + (risk_score * 0.6)

    if kind == "host":
        # Hosts: make them bigger; risk 0..80 -> size ~10..26
        return 10 + (risk_score * 0.2)

    if kind == "subnet":
        return 16

    # Services / other
    return 8


def plot_3d(G: nx.Graph):
    """
    Render the graph as an interactive 3D Plotly chart.

    Nodes are grouped by 'kind' to create a clean legend and different symbols.
    """
    # 3D force-directed layout (spring) with spacing scaled by node count
    pos = nx.spring_layout(G, dim=3, seed=7, k=1 / math.sqrt(max(G.number_of_nodes(), 1)))

    # ---------- Edges ----------
    ex, ey, ez = [], [], []
    for u, v in G.edges():
        x0, y0, z0 = pos[u]
        x1, y1, z1 = pos[v]
        ex += [x0, x1, None]
        ey += [y0, y1, None]
        ez += [z0, z1, None]

    edge_trace = go.Scatter3d(
        x=ex,
        y=ey,
        z=ez,
        mode="lines",
        line=dict(width=2),
        hoverinfo="none",
        name="links",
    )

    # ---------- Nodes by kind ----------
    kinds = sorted({G.nodes[n].get("kind", "other") for n in G.nodes()})
    traces = [edge_trace]

    for kind in kinds:
        xs, ys, zs, texts, sizes = [], [], [], [], []

        for n in G.nodes():
            if G.nodes[n].get("kind") != kind:
                continue

            x, y, z = pos[n]
            xs.append(x)
            ys.append(y)
            zs.append(z)

            node = G.nodes[n]
            texts.append(node.get("label", n))

            sev_i = int(node.get("severity", 1) or 1)
            risk = node.get("risk_score", 0.0)

            sizes.append(risk_to_size(kind, risk, sev_i))

        traces.append(
            go.Scatter3d(
                x=xs,
                y=ys,
                z=zs,
                mode="markers",
                marker=dict(
                    size=sizes,
                    symbol=sev_to_symbol(kind),
                    opacity=0.9,
                ),
                text=texts,
                hoverinfo="text",
                name=kind,
            )
        )

    fig = go.Figure(data=traces)
    fig.update_layout(
        title="3D Nessus-style Scan Visualization (Risk-driven)",
        margin=dict(l=0, r=0, b=0, t=45),
        showlegend=True,
    )
    fig.show()
