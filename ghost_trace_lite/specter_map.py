"""Build observed entity relationships and render a Mermaid diagram."""


def observed_relationships(auth, flows):
    edges = set()
    for event in auth:
        edges.add(("user", event.user, "login target", "host", event.host))
        edges.add(("ip", event.src_ip, "login source", "host", event.host))
        edges.add(("host", event.host, "reported address", "ip", event.host_ip))
    for flow in flows:
        edges.add(("ip", flow.src_ip, "connected to", "ip", flow.dst_ip))
        if flow.dst_domain:
            edges.add(("ip", flow.dst_ip, "observed destination", "domain", flow.dst_domain))
    return [
        {"source": {"type": left, "value": source}, "relation": relation,
         "target": {"type": right, "value": target}}
        for left, source, relation, right, target in sorted(edges)
    ]


def mermaid_label(value):
    # Mermaid decimal entities protect labels from syntax and HTML interpretation.
    return "".join(
        char if char.isascii() and (char.isalnum() or char in " ._@:-") else f"#{ord(char)};"
        for char in value
    )


def render_mermaid(relationships):
    lines = ["flowchart TD"]
    nodes = {}

    def node_id(entity):
        key = entity["type"], entity["value"]
        if key not in nodes:
            nodes[key] = f"n{len(nodes) + 1}"
            label = mermaid_label(f"{key[0]}: {key[1]}")
            lines.append(f'    {nodes[key]}["{label}"]')
        return nodes[key]

    for edge in relationships:
        source = node_id(edge["source"])
        target = node_id(edge["target"])
        lines.append(f"    {source} -->|{mermaid_label(edge['relation'])}| {target}")
    if not relationships:
        lines.append('    n1["No observed relationships"]')
    return "\n".join(lines) + "\n"
