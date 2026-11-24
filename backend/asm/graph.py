"""An in-memory asset graph derived from the scan's tables at request time.

No new storage: the graph is rebuilt from assets, findings, dns_records and the asn findings whenever it's needed.
Its nodes are hosts, IPs, netblocks, certificates, technologies, findings and lookalike domains; its edges are the
relationships between them (resolves-to, in-netblock, presents-cert, runs-tech, has-finding, cname-to, impersonated-by).

It exists mainly to answer "what else is affected" questions — blast radius, shared certificates, co-hosting — and to
feed the attack-path simulation, which walks these edges. Everything is computed from data already collected; nothing
here sends traffic.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field

from .db import DB
from .surface import classify_host, dedup_tech, is_agent_surface

NODE_KINDS = ("host", "ip", "netblock", "cert", "tech", "finding", "lookalike")


@dataclass
class Node:
    id: str                       # "<kind>:<key>"
    kind: str
    label: str
    attrs: dict = field(default_factory=dict)


@dataclass
class Edge:
    src: str
    dst: str
    rel: str                      # resolves_to | in_netblock | presents | runs | has_finding | cname_to | impersonated_by


@dataclass
class Graph:
    nodes: dict[str, Node]
    edges: list[Edge]
    _out: dict[str, list[Edge]]
    _in: dict[str, list[Edge]]

    def neighbours(self, node_id: str, rel: str | None = None, incoming: bool = False) -> list[Node]:
        edges = self._in.get(node_id, []) if incoming else self._out.get(node_id, [])
        out = []
        for e in edges:
            if rel and e.rel != rel:
                continue
            other = e.src if incoming else e.dst
            if other in self.nodes:
                out.append(self.nodes[other])
        return out

    def of_kind(self, kind: str) -> list[Node]:
        return [n for n in self.nodes.values() if n.kind == kind]


def build_graph(db: DB, sid: str) -> Graph:
    nodes: dict[str, Node] = {}
    edges: list[Edge] = []

    def node(kind: str, key: str, label: str | None = None, **attrs) -> str:
        nid = f"{kind}:{key}"
        if nid not in nodes:
            nodes[nid] = Node(nid, kind, label or key, attrs)
        else:
            nodes[nid].attrs.update({k: v for k, v in attrs.items() if v is not None})
        return nid

    def edge(src: str, dst: str, rel: str) -> None:
        edges.append(Edge(src, dst, rel))

    # netblocks from the asn findings
    netblocks: list[tuple[object, str]] = []
    for r in db.all("SELECT host, title FROM findings WHERE scan_id = ? AND source_tool = 'asn'", sid):
        try:
            net = ipaddress.ip_network(r["host"], strict=False)
        except ValueError:
            continue
        kind = "own" if "org-owned" in r["title"] else "shared"
        label = r["title"].split("(", 1)[-1].rstrip(")") if "(" in r["title"] else str(net)
        nid = node("netblock", str(net), label, net_kind=kind)
        netblocks.append((net, nid))

    def is_pub(ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
            return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast)
        except ValueError:
            return False

    assets = db.all("SELECT host, ips, tech, tls, cdn, third_party, is_live, http_status, ports, ports_confirmed "
                    "FROM assets WHERE scan_id = ?", sid)
    for a in assets:
        tags = classify_host(a["host"])
        h = node("host", a["host"], a["host"], live=bool(a["is_live"]), http_status=a["http_status"],
                 cdn=bool(a["cdn"]), third_party=bool(a["third_party"]), tags=tags, agent=is_agent_surface(a["host"]),
                 ports=json.loads(a["ports"] or "[]"),
                 ports_confirmed=json.loads(a["ports_confirmed"]) if a["ports_confirmed"] is not None else None)
        for ip in json.loads(a["ips"] or "[]"):
            if not is_pub(ip):
                continue
            ipn = node("ip", ip, ip, shared=bool(a["cdn"]) or bool(a["third_party"]))
            edge(h, ipn, "resolves_to")
            for net, nid in netblocks:
                if ipaddress.ip_address(ip) in net:
                    edge(ipn, nid, "in_netblock")
        for t in dedup_tech(json.loads(a["tech"] or "[]")):
            edge(h, node("tech", t.split(" ")[0].lower(), t.split(" ")[0], version=(t.split(" ", 1)[1] if " " in t else None)), "runs")
        tls = json.loads(a["tls"] or "{}")
        cn = tls.get("subject_cn")
        if cn:
            # a cert is identified softly by its subject CN + expiry; a wildcard CN shared across hosts is a shared cert
            cid = node("cert", f"{cn}|{tls.get('not_after') or ''}", cn, not_after=tls.get("not_after"),
                       wildcard=cn.startswith("*."), flags=[k for k in ("expired", "self_signed", "mismatched") if tls.get(k)])
            edge(h, cid, "presents")

    # CNAME edges (host -> external target) from the DNS snapshot
    for r in db.all("SELECT host, value FROM dns_records WHERE scan_id = ? AND rtype = 'CNAME'", sid):
        src = f"host:{r['host']}"
        if src in nodes:
            tgt = node("host", r["value"], r["value"], external=True) if f"host:{r['value']}" not in nodes else f"host:{r['value']}"
            edge(src, tgt, "cname_to")

    # findings attached to their host
    for r in db.all("SELECT id, area, severity, title, host, source_tool FROM findings WHERE scan_id = ? "
                    "AND status != 'false_positive'", sid):
        fid = node("finding", str(r["id"]), r["title"][:120], severity=r["severity"], area=r["area"], tool=r["source_tool"])
        if r["host"] and f"host:{r['host']}" in nodes:
            edge(f"host:{r['host']}", fid, "has_finding")
        if r["area"] == "brand":           # lookalike domains
            m = r["title"].rsplit(": ", 1)
            if len(m) == 2 and "." in m[1]:
                edge(f"host:{r['host']}" if f"host:{r['host']}" in nodes else node("host", r["host"] or "root", r["host"] or "root"),
                     node("lookalike", m[1], m[1]), "impersonated_by")

    out_idx: dict[str, list[Edge]] = {}
    in_idx: dict[str, list[Edge]] = {}
    for e in edges:
        out_idx.setdefault(e.src, []).append(e)
        in_idx.setdefault(e.dst, []).append(e)
    return Graph(nodes, edges, out_idx, in_idx)


# ---- canned questions -------------------------------------------------------------------

def blast_radius(g: Graph, ip: str) -> dict:
    """What a single IP carries: the hosts on it, their findings and certs — the blast radius if it's compromised."""
    ipn = f"ip:{ip}"
    if ipn not in g.nodes:
        return {"ip": ip, "hosts": []}
    hosts = g.neighbours(ipn, "resolves_to", incoming=True)
    out = []
    for h in hosts:
        findings = g.neighbours(h.id, "has_finding")
        out.append({"host": h.label, "agent": h.attrs.get("agent"),
                    "findings": sorted((f.attrs.get("severity"), f.label) for f in findings)})
    return {"ip": ip, "host_count": len(hosts), "hosts": out,
            "netblock": next((n.label for n in g.neighbours(ipn, "in_netblock")), None)}


def shared_certs(g: Graph) -> list[dict]:
    """Certificates presented by more than one host — if the private key leaks, every host is exposed at once."""
    out = []
    for c in g.of_kind("cert"):
        hosts = g.neighbours(c.id, "presents", incoming=True)
        if len(hosts) > 1:
            out.append({"cert": c.label, "wildcard": c.attrs.get("wildcard"), "not_after": c.attrs.get("not_after"),
                        "hosts": sorted(h.label for h in hosts), "host_count": len(hosts)})
    return sorted(out, key=lambda x: -x["host_count"])


def co_hosting(g: Graph) -> list[dict]:
    """IPs that carry more than one host (a single box's compromise reaches several names)."""
    out = []
    for ipn in g.of_kind("ip"):
        hosts = g.neighbours(ipn.id, "resolves_to", incoming=True)
        if len(hosts) > 1 and not ipn.attrs.get("shared"):
            out.append({"ip": ipn.label, "host_count": len(hosts), "hosts": sorted(h.label for h in hosts),
                        "agent_hosts": sorted(h.label for h in hosts if h.attrs.get("agent"))})
    return sorted(out, key=lambda x: -x["host_count"])


def graph_summary(g: Graph) -> dict:
    counts = {k: len(g.of_kind(k)) for k in NODE_KINDS}
    return {"nodes": counts, "edges": len(g.edges),
            "shared_certs": shared_certs(g)[:20], "co_hosting": co_hosting(g)[:20]}


def to_payload(g: Graph, max_nodes: int = 1500) -> dict:
    """A trimmed node/edge list for a visualisation: drop tech/finding leaves if the graph is very large."""
    keep = set(g.nodes)
    if len(g.nodes) > max_nodes:
        drop_kinds = ("tech", "finding")
        keep = {nid for nid, n in g.nodes.items() if n.kind not in drop_kinds}
    nodes = [{"id": n.id, "kind": n.kind, "label": n.label, **n.attrs} for nid, n in g.nodes.items() if nid in keep]
    edges = [{"src": e.src, "dst": e.dst, "rel": e.rel} for e in g.edges if e.src in keep and e.dst in keep]
    return {"nodes": nodes, "edges": edges, "truncated": len(g.nodes) > max_nodes}
