"""
KernelGraph: Core graph data model for the Linux kernel call graph.

Wraps NetworkX MultiDiGraph with kernel-specific node/edge semantics,
serialization, and subsystem classification.
"""

import json
import os
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

import networkx as nx

from config import (
    SYSCALL_PREFIXES, LSM_HOOKS, VALIDATION_FUNCTIONS,
    ALLOC_FUNCTIONS, FREE_FUNCTIONS, PRIV_CHECKS,
    LOCK_FUNCTIONS, SUBSYSTEMS,
)


class NodeType(str, Enum):
    FUNCTION = "function"
    FILE = "file"
    SUBSYSTEM = "subsystem"


class EdgeType(str, Enum):
    CALLS = "calls"              # direct function call
    INDIRECT_CALL = "indirect"   # function pointer / vtable call
    INCLUDES = "includes"        # header include
    CONTAINS = "contains"        # file contains function


class SecurityRole(str, Enum):
    """Security-relevant classification for a function node."""
    SYSCALL_ENTRY = "syscall_entry"
    LSM_HOOK = "lsm_hook"
    VALIDATION = "validation"
    ALLOC_SINK = "alloc_sink"
    FREE_SINK = "free_sink"
    PRIV_CHECK = "priv_check"
    LOCK_OP = "lock_op"
    NONE = "none"


@dataclass
class FunctionNode:
    """Metadata for a function node in the kernel graph."""
    name: str
    file_path: str
    subsystem: str = ""
    line_start: int = 0
    line_end: int = 0
    security_role: str = "none"
    is_exported: bool = False          # EXPORT_SYMBOL
    is_static: bool = False
    signature: str = ""                # function signature for type-based indirect call resolution
    # Populated by analysis
    betweenness: float = 0.0
    pagerank: float = 0.0
    eigenvector: float = 0.0
    fiedler_value: float = 0.0
    community_id: int = -1
    unchecked_path_count: int = 0      # paths from syscall to this node without validation


def classify_security_role(func_name: str) -> SecurityRole:
    """Classify a function's security role based on its name."""
    for prefix in SYSCALL_PREFIXES:
        if func_name.startswith(prefix):
            return SecurityRole.SYSCALL_ENTRY
    if func_name in LSM_HOOKS:
        return SecurityRole.LSM_HOOK
    if func_name in VALIDATION_FUNCTIONS:
        return SecurityRole.VALIDATION
    if func_name in ALLOC_FUNCTIONS:
        return SecurityRole.ALLOC_SINK
    if func_name in FREE_FUNCTIONS:
        return SecurityRole.FREE_SINK
    if func_name in PRIV_CHECKS:
        return SecurityRole.PRIV_CHECK
    if func_name in LOCK_FUNCTIONS:
        return SecurityRole.LOCK_OP
    return SecurityRole.NONE


def classify_subsystem(file_path: str) -> str:
    """Determine which kernel subsystem a file belongs to."""
    for name, info in SUBSYSTEMS.items():
        if file_path.startswith(info["path"]):
            return name
    return "other"


class KernelGraph:
    """
    Core graph representation of the Linux kernel.
    
    Wraps a NetworkX MultiDiGraph with:
    - Typed nodes (function, file, subsystem)
    - Typed edges (calls, indirect_call, includes, contains)
    - Security role classification
    - Subsystem membership
    - Serialization to/from JSON
    """

    def __init__(self):
        self.graph = nx.MultiDiGraph()
        self._func_index: dict[str, list[str]] = {}  # name -> [node_ids] (handles duplicates)

    @property
    def num_nodes(self) -> int:
        return self.graph.number_of_nodes()

    @property
    def num_edges(self) -> int:
        return self.graph.number_of_edges()

    def add_function(
        self,
        name: str,
        file_path: str,
        line_start: int = 0,
        line_end: int = 0,
        signature: str = "",
        is_exported: bool = False,
        is_static: bool = False,
    ) -> str:
        """
        Add a function node. Returns the node ID.
        Node ID is file_path::func_name to handle duplicate names across files.
        """
        node_id = f"{file_path}::{name}"
        subsystem = classify_subsystem(file_path)
        security_role = classify_security_role(name)

        self.graph.add_node(
            node_id,
            node_type=NodeType.FUNCTION.value,
            name=name,
            file_path=file_path,
            subsystem=subsystem,
            line_start=line_start,
            line_end=line_end,
            security_role=security_role.value,
            is_exported=is_exported,
            is_static=is_static,
            signature=signature,
            # Analysis fields - populated later
            betweenness=0.0,
            pagerank=0.0,
            eigenvector=0.0,
            fiedler_value=0.0,
            community_id=-1,
            unchecked_path_count=0,
        )

        # Index by function name for lookup
        if name not in self._func_index:
            self._func_index[name] = []
        self._func_index[name].append(node_id)

        return node_id

    def add_call_edge(
        self,
        caller_id: str,
        callee_id: str,
        edge_type: EdgeType = EdgeType.CALLS,
        call_site_line: int = 0,
    ) -> None:
        """Add a call edge between two function nodes."""
        is_cross_subsystem = False
        if caller_id in self.graph and callee_id in self.graph:
            caller_sub = self.graph.nodes[caller_id].get("subsystem", "")
            callee_sub = self.graph.nodes[callee_id].get("subsystem", "")
            is_cross_subsystem = caller_sub != callee_sub and caller_sub and callee_sub

        self.graph.add_edge(
            caller_id,
            callee_id,
            edge_type=edge_type.value,
            call_site_line=call_site_line,
            is_cross_subsystem=is_cross_subsystem,
        )

    def lookup_function(self, name: str) -> list[str]:
        """Look up node IDs by function name. Returns all matches (may be in multiple files)."""
        return self._func_index.get(name, [])

    def get_node(self, node_id: str) -> Optional[dict]:
        """Get node attributes."""
        if node_id in self.graph:
            return dict(self.graph.nodes[node_id])
        return None

    def get_callers(self, node_id: str, hops: int = 1) -> set[str]:
        """Get all callers up to N hops back."""
        callers = set()
        frontier = {node_id}
        for _ in range(hops):
            next_frontier = set()
            for n in frontier:
                preds = set(self.graph.predecessors(n))
                next_frontier |= preds - callers - {node_id}
            callers |= next_frontier
            frontier = next_frontier
        return callers

    def get_callees(self, node_id: str, hops: int = 1) -> set[str]:
        """Get all callees up to N hops forward."""
        callees = set()
        frontier = {node_id}
        for _ in range(hops):
            next_frontier = set()
            for n in frontier:
                succs = set(self.graph.successors(n))
                next_frontier |= succs - callees - {node_id}
            callees |= next_frontier
            frontier = next_frontier
        return callees

    def get_syscall_nodes(self) -> list[str]:
        """Get all syscall entry point nodes."""
        return [
            n for n, d in self.graph.nodes(data=True)
            if d.get("security_role") == SecurityRole.SYSCALL_ENTRY.value
        ]

    def get_nodes_by_role(self, role: SecurityRole) -> list[str]:
        """Get all nodes with a specific security role."""
        return [
            n for n, d in self.graph.nodes(data=True)
            if d.get("security_role") == role.value
        ]

    def get_cross_subsystem_edges(self) -> list[tuple[str, str, dict]]:
        """Get all edges that cross subsystem boundaries."""
        return [
            (u, v, d) for u, v, _, d in self.graph.edges(data=True, keys=True)
            if d.get("is_cross_subsystem", False)
        ]

    def get_subsystem_subgraph(self, subsystem: str) -> "KernelGraph":
        """Extract subgraph for a single subsystem."""
        nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("subsystem") == subsystem
        ]
        sub = KernelGraph()
        sub.graph = self.graph.subgraph(nodes).copy()
        # Rebuild index
        for n, d in sub.graph.nodes(data=True):
            name = d.get("name", "")
            if name not in sub._func_index:
                sub._func_index[name] = []
            sub._func_index[name].append(n)
        return sub

    def to_simple_graph(self) -> nx.DiGraph:
        """
        Convert MultiDiGraph to simple DiGraph for algorithms that
        don't support multigraphs (most centrality metrics).
        """
        return nx.DiGraph(self.graph)

    def save(self, path: str) -> None:
        """Serialize graph to JSON."""
        data = nx.node_link_data(self.graph)
        data["_func_index"] = self._func_index
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "KernelGraph":
        """Deserialize graph from JSON."""
        with open(path) as f:
            data = json.load(f)
        kg = cls()
        kg._func_index = data.pop("_func_index", {})
        kg.graph = nx.node_link_graph(data, directed=True, multigraph=True)
        return kg

    def summary(self) -> dict:
        """Quick stats about the graph."""
        roles = {}
        subsystems = {}
        for _, d in self.graph.nodes(data=True):
            role = d.get("security_role", "none")
            roles[role] = roles.get(role, 0) + 1
            sub = d.get("subsystem", "other")
            subsystems[sub] = subsystems.get(sub, 0) + 1

        cross_sub_edges = len(self.get_cross_subsystem_edges())

        return {
            "nodes": self.num_nodes,
            "edges": self.num_edges,
            "security_roles": roles,
            "subsystems": subsystems,
            "cross_subsystem_edges": cross_sub_edges,
        }
