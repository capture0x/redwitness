"""
Knowledge Graph & Coverage Mapper (exploration and reporting; it does NOT generate attacks).

A library case of `type: knowledge_map` holds a TREE of questions the operator wrote (`nodes`). The engine asks them, one fresh conversation per node,
and builds the "knowledge tree" from the target's replies with plain string matching in code:

  * terms            words/phrases the operator expects a knowledgeable target to mention -> the node is `covered` when at least one appears
  * protected_terms  values the target must never reveal -> any occurrence is a deterministic violation (then replayed like every finding)
  * expand           `if_covered` (default): a child question is asked only when its parent was covered; `always`: every node is asked

No model writes anything here: questions, terms and the tree's shape come from the hashed library; the code only classifies the replies.
The result is a coverage map (what the target knows, per topic) and an exposure list (which protected values leaked), stored per run.
"""
import re
from dataclasses import dataclass

MAX_NODES, MAX_DEPTH, MAX_TERMS = 40, 4, 12
ID = re.compile(r"[A-Za-z0-9_.-]{1,40}")


class KnowledgeError(ValueError):
    pass


@dataclass(frozen=True)
class KNode:
    id: str
    parent: str | None
    topic: str
    question: str
    terms: tuple[str, ...] = ()
    protected: tuple[str, ...] = ()


def _terms(raw, key: str, nid: str) -> tuple[str, ...]:
    if raw in (None, []):
        return ()
    if not isinstance(raw, list) or len(raw) > MAX_TERMS or not all(isinstance(x, str) and 2 <= len(x.strip()) <= 100 and "\x00" not in x for x in raw):
        raise KnowledgeError(f"node {nid!r}: '{key}' must be a list of at most {MAX_TERMS} texts of 2-100 characters")
    return tuple(dict.fromkeys(x.strip() for x in raw))


def parse_nodes(raw) -> tuple[KNode, ...]:
    if not isinstance(raw, list) or not 2 <= len(raw) <= MAX_NODES:
        raise KnowledgeError(f"'nodes' must be a list of 2-{MAX_NODES} nodes")
    out: dict[str, KNode] = {}
    depth: dict[str, int] = {}
    for n in raw:
        if not isinstance(n, dict) or set(n) - {"id", "parent", "topic", "question", "terms", "protected_terms"}:
            raise KnowledgeError("every node must be an object with id, parent, topic, question, terms, protected_terms")
        nid, parent = n.get("id"), n.get("parent")
        if not isinstance(nid, str) or not ID.fullmatch(nid) or nid in out:
            raise KnowledgeError("node ids must be unique, 1-40 characters of letters, digits, _ . -")
        if parent not in (None, "") and parent not in out:
            raise KnowledgeError(f"node {nid!r}: the parent {parent!r} must be defined before the node")
        topic, q = n.get("topic", ""), n.get("question")
        if not isinstance(topic, str) or len(topic) > 80:
            raise KnowledgeError(f"node {nid!r}: topic must be text of at most 80 characters")
        if not isinstance(q, str) or not q.strip() or len(q) > 2000 or "\x00" in q:
            raise KnowledgeError(f"node {nid!r}: 'question' must be 1-2000 characters")
        terms, prot = _terms(n.get("terms"), "terms", nid), _terms(n.get("protected_terms"), "protected_terms", nid)
        d = (depth[parent] + 1) if parent else 1
        if d > MAX_DEPTH:
            raise KnowledgeError(f"node {nid!r}: the tree is deeper than {MAX_DEPTH} levels")
        depth[nid] = d
        out[nid] = KNode(nid, parent or None, topic.strip() or nid, q.strip(), terms, prot)
    if not any(k.parent is None for k in out.values()):
        raise KnowledgeError("the tree needs at least one root node (parent: null)")
    return tuple(out.values())


def _has(text: str, term: str) -> bool:
    return " ".join(term.split()).casefold() in " ".join(text.split()).casefold()


def classify(node: KNode, reply: str, *, error: bool = False) -> dict:
    """Code-only classification of one reply. status: covered | uncovered | exposed | empty | error."""
    if error:
        return {"status": "error", "found": [], "missing": list(node.terms), "exposed": []}
    found = [t for t in node.terms if _has(reply, t)]
    exposed = [t for t in node.protected if _has(reply, t)]
    if exposed:
        status = "exposed"
    elif not reply.strip():
        status = "empty"
    elif found or not node.terms:
        status = "covered"
    else:
        status = "uncovered"
    return {"status": status, "found": found, "missing": [t for t in node.terms if t not in found], "exposed": exposed}


def traversal(nodes: tuple[KNode, ...]) -> list[KNode]:
    """Breadth-first order (roots first), the order the engine asks them in."""
    kids: dict[str | None, list[KNode]] = {}
    for n in nodes:
        kids.setdefault(n.parent, []).append(n)
    order, queue = [], list(kids.get(None, []))
    while queue:
        n = queue.pop(0)
        order.append(n)
        queue += kids.get(n.id, [])
    return order


def build_tree(nodes: tuple[KNode, ...], results: dict[str, dict]) -> dict:
    """The knowledge tree + coverage numbers. `results`: node id -> {status, found, missing, exposed, excerpt}. Nodes never asked are `skipped`."""
    def node_view(n: KNode) -> dict:
        r = results.get(n.id)
        base = {"id": n.id, "topic": n.topic, "question": n.question, "terms": len(n.terms), "protected": len(n.protected)}
        if r is None:
            return base | {"status": "skipped", "found": [], "missing": list(n.terms), "exposed": [], "excerpt": "", "children": []}
        return base | {k: r.get(k, v) for k, v in (("status", "error"), ("found", []), ("missing", []), ("exposed", []), ("excerpt", ""))} | {"children": []}
    views = {n.id: node_view(n) for n in nodes}
    roots = []
    for n in nodes:
        (views[n.parent]["children"] if n.parent else roots).append(views[n.id])
    asked = [v for v in views.values() if v["status"] != "skipped"]
    total_terms = sum(len(n.terms) for n in nodes)
    found_terms = sum(len(v["found"]) for v in views.values())
    topics: dict[str, dict] = {}
    for n in nodes:
        t = topics.setdefault(n.topic, {"topic": n.topic, "nodes": 0, "asked": 0, "covered": 0, "terms": 0, "found": 0, "exposed": 0})
        v = views[n.id]
        t["nodes"] += 1
        t["asked"] += v["status"] != "skipped"
        t["covered"] += v["status"] == "covered"
        t["terms"] += len(n.terms)
        t["found"] += len(v["found"])
        t["exposed"] += len(v["exposed"])
    return {"roots": roots, "topics": list(topics.values()),
            "summary": {"nodes": len(nodes), "asked": len(asked), "skipped": len(nodes) - len(asked),
                        "covered": sum(v["status"] == "covered" for v in views.values()),
                        "uncovered": sum(v["status"] == "uncovered" for v in views.values()),
                        "exposed_nodes": sum(v["status"] == "exposed" for v in views.values()),
                        "exposed_terms": sum(len(v["exposed"]) for v in views.values()),
                        "terms_total": total_terms, "terms_found": found_terms,
                        "coverage": round(found_terms / total_terms, 4) if total_terms else None},
            "note": "Exploration and reporting only. Questions and terms come from the library; classification is plain string matching in code."}
