"""
Configuration for KernelGraph vulnerability discovery system.
Defines CVE taxonomy patterns, security-relevant kernel functions,
and analysis parameters.
"""

# ============================================================================
# CVE TAXONOMY - 7 vulnerability patterns for guided detection
# Each pattern has a structural signature in the call graph
# ============================================================================

CVE_TAXONOMY = {
    "stack_buffer_overflow": {
        "id": "P1",
        "description": "Unbounded copy into stack buffer",
        "sink_functions": [
            "strcpy", "strcat", "sprintf", "vsprintf",
            "gets", "memcpy",  # when dst is stack-allocated
        ],
        "missing_checks": ["strlcpy", "strscpy", "snprintf", "ksize"],
        "graph_signature": "High in-degree from userspace paths, no validation node on path",
    },
    "heap_buffer_overflow": {
        "id": "P2",
        "description": "Integer overflow in size calculation before allocation",
        "sink_functions": [
            "kmalloc", "kzalloc", "kvmalloc", "__kmalloc",
            "kmem_cache_alloc", "vmalloc", "krealloc",
        ],
        "related_functions": [
            "array_size", "struct_size",  # safe alternatives
            "check_mul_overflow", "check_add_overflow",
        ],
        "graph_signature": "Arithmetic op on user-controlled value feeds into allocation size",
    },
    "off_by_one": {
        "id": "P3",
        "description": "Off-by-one in boundary/loop checks",
        "indicators": ["<= instead of <", "< n instead of < n-1"],
        "common_contexts": ["array indexing", "buffer length", "page boundary"],
        "graph_signature": "Boundary check node with edge to array/buffer access",
    },
    "missing_bounds_check": {
        "id": "P4",
        "description": "Missing bounds check on cross-subsystem call",
        "validation_functions": [
            "copy_from_user", "copy_to_user", "get_user", "put_user",
            "access_ok", "check_object_size",
        ],
        "graph_signature": "Cross-subsystem edge without validation node on path",
    },
    "toctou_race": {
        "id": "P5",
        "description": "Time-of-check-to-time-of-use race on shared buffer",
        "check_functions": ["access_ok", "inode_permission", "may_open"],
        "use_functions": ["vfs_read", "vfs_write", "do_mmap"],
        "lock_functions": [
            "mutex_lock", "spin_lock", "down_read", "down_write",
            "rcu_read_lock",
        ],
        "graph_signature": "Check and use on same object without lock held on both paths",
    },
    "type_confusion": {
        "id": "P6",
        "description": "Type confusion in union or unsafe cast",
        "indicators": ["container_of", "void* cast", "union access"],
        "graph_signature": "Multiple callers pass different concrete types to same polymorphic function",
    },
    "use_after_free": {
        "id": "P7",
        "description": "Use-after-free on async callback or deferred work path",
        "free_functions": ["kfree", "kmem_cache_free", "vfree", "put_page"],
        "async_mechanisms": [
            "schedule_work", "queue_work", "tasklet_schedule",
            "call_rcu", "timer_setup", "mod_timer",
        ],
        "refcount_functions": ["kref_get", "kref_put", "refcount_inc", "refcount_dec_and_test"],
        "graph_signature": "Free node reachable before async callback completes",
    },
}

# ============================================================================
# SECURITY-RELEVANT FUNCTIONS
# Used to label nodes in the call graph
# ============================================================================

# Syscall entry points - the attack surface
SYSCALL_PREFIXES = [
    "sys_", "__x64_sys_", "__arm64_sys_", "__ia32_sys_",
    "ksys_", "SYSCALL_DEFINE",
]

# LSM (Linux Security Module) hooks - security checkpoints
LSM_HOOKS = [
    "security_file_permission", "security_inode_permission",
    "security_socket_connect", "security_socket_sendmsg",
    "security_bprm_check", "security_task_kill",
    "security_capable", "security_ptrace_access_check",
    "security_mmap_file", "security_mmap_addr",
    "security_file_open", "security_path_mkdir",
    "security_sk_alloc", "security_socket_create",
]

# Validation / sanitization functions
VALIDATION_FUNCTIONS = [
    "copy_from_user", "copy_to_user",
    "get_user", "put_user",
    "access_ok", "check_object_size",
    "strlcpy", "strscpy", "strncpy_from_user",
    "check_mul_overflow", "check_add_overflow",
    "array_size", "struct_size",
    "ksize",
]

# Memory allocation sinks
ALLOC_FUNCTIONS = [
    "kmalloc", "kzalloc", "kvmalloc", "kvzalloc",
    "__kmalloc", "kmem_cache_alloc", "kmem_cache_zalloc",
    "vmalloc", "vzalloc", "krealloc",
    "__get_free_pages", "alloc_pages",
    "dma_alloc_coherent",
]

# Memory free functions
FREE_FUNCTIONS = [
    "kfree", "kvfree", "vfree",
    "kmem_cache_free", "free_pages",
    "dma_free_coherent", "put_page",
]

# Privilege / capability checks
PRIV_CHECKS = [
    "capable", "ns_capable", "has_capability",
    "uid_eq", "gid_eq",
    "inode_owner_or_capable",
]

# Locking primitives
LOCK_FUNCTIONS = [
    "mutex_lock", "mutex_unlock", "mutex_trylock",
    "spin_lock", "spin_unlock", "spin_lock_irqsave",
    "down_read", "up_read", "down_write", "up_write",
    "rcu_read_lock", "rcu_read_unlock",
    "read_lock", "write_lock",
]

# Kernel subsystems and their directory mappings
SUBSYSTEMS = {
    "kernel": {"path": "kernel/", "description": "Core kernel (scheduling, signals, fork)"},
    "mm": {"path": "mm/", "description": "Memory management"},
    "fs": {"path": "fs/", "description": "Virtual filesystem and filesystems"},
    "net": {"path": "net/", "description": "Networking stack"},
    "drivers": {"path": "drivers/", "description": "Device drivers"},
    "security": {"path": "security/", "description": "LSM framework"},
    "crypto": {"path": "crypto/", "description": "Cryptographic API"},
    "ipc": {"path": "ipc/", "description": "Inter-process communication"},
    "block": {"path": "block/", "description": "Block layer"},
    "sound": {"path": "sound/", "description": "Sound subsystem"},
    "arch": {"path": "arch/", "description": "Architecture-specific code"},
    "lib": {"path": "lib/", "description": "Kernel library routines"},
}

# ============================================================================
# ANALYSIS PARAMETERS
# ============================================================================

ANALYSIS_CONFIG = {
    # Centrality thresholds (top N% flagged as interesting)
    "betweenness_percentile": 95,
    "pagerank_percentile": 95,
    "eigenvector_percentile": 95,

    # Path analysis
    "max_path_length": 10,          # max hops for path queries
    "max_paths_per_query": 100,     # limit path enumeration

    # Community detection
    "community_resolution": 1.0,    # Louvain resolution parameter

    # Fiedler vector
    "fiedler_boundary_threshold": 0.1,  # nodes within this of zero are boundary nodes

    # Context assembly
    "context_hops": 2,              # how many hops of callers/callees to include
    "max_context_tokens": 4000,     # rough token budget per candidate

    # Agent loop
    "max_iterations": 10,           # max feedback iterations per candidate
    "batch_size": 5,                # candidates to analyze per batch
}
