# [INFORMATIONAL] Use After Free in nft_expr_init (CWE-416)

**Generated:** 2026-03-06T04:04:22.193324+00:00  
**Report ID:** `nft_expr_init_8a24d253`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nf_tables_api.c` |
| Function | `nft_expr_init` |
| Line | 2672 |
| Subsystem | net |

## Source Code

```c
 2672 | static struct nft_expr *nft_expr_init(const struct nft_ctx *ctx,
 2673 | 				      const struct nlattr *nla)
 2674 | {
 2675 | 	struct nft_expr_info info;
 2676 | 	struct nft_expr *expr;
 2677 | 	struct module *owner;
 2678 | 	int err;
 2679 | 
 2680 | 	err = nf_tables_expr_parse(ctx, nla, &info);
 2681 | 	if (err < 0)
 2682 | 		goto err1;
 2683 | 
 2684 | 	err = -ENOMEM;
 2685 | 	expr = kzalloc(info.ops->size, GFP_KERNEL);
 2686 | 	if (expr == NULL)
 2687 | 		goto err2;
 2688 | 
 2689 | 	err = nf_tables_newexpr(ctx, &info, expr);
 2690 | 	if (err < 0)
 2691 | 		goto err3;
 2692 | 
 2693 | 	return expr;
 2694 | err3:
 2695 | 	kfree(expr);
 2696 | err2:
 2697 | 	owner = info.ops->type->owner;
 2698 | 	if (info.ops->type->release_ops)
 2699 | 		info.ops->type->release_ops(info.ops);
 2700 | 
 2701 | 	module_put(owner);
 2702 | err1:
 2703 | 	return ERR_PTR(err);
 2704 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | CWE-416 |
| Type | use_after_free |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | NONE |

## Description

In `nft_expr_init` (net/netfilter/nf_tables_api.c), the error path contains a Use-After-Free vulnerability centered on the `release_ops` callback pattern used by `nft_compat`-style expression types. The critical sequence is:

1. Line 2685: `expr = kzalloc(info.ops->size, GFP_KERNEL_ACCOUNT)` — allocates expression using size from ops.
2. Line 2649 (within nf_tables_newexpr called from nft_expr_init): `expr->ops = ops` is written into the allocated expr.
3. If `ops->init()` fails, control jumps to `err3`.
4. Line 2695: `kfree(expr)` — expr memory is freed.
5. Line 2699: `info.ops->type->release_ops(info.ops)` — for `nft_compat`, this frees the dynamically-allocated `ops` struct itself.
6. Line 2701: `module_put(owner)` — owner was cached from `info.ops->type->owner` at line 2697, so this specific access is safe.

The UAF occurs because:
- For `nft_compat` expression types, `select_ops` dynamically allocates a new `nft_expr_ops` struct per rule (containing iptables match/target info). This ops pointer is written into `expr->ops`.
- In the error path, `kfree(expr)` is called FIRST, then `release_ops(info.ops)` is called to free the dynamically-allocated ops struct.
- Any concurrent reader that obtained a pointer to `expr` before the free (e.g., via RCU read-side critical section in a set element lookup path `nft_set_elem_expr_alloc`) can dereference `expr->ops` after `expr` has been freed — classic UAF.
- Additionally, since `nft_set_elem_expr_alloc` is confirmed to hold NO LOCK when calling into this path, there is no mutual exclusion preventing concurrent access to the partially-torn-down expr.

Secondary vulnerability: The allocation size `info.ops->size` is derived from the user-controlled `nft_expr_ops` registered via `nft_compat`. If a crafted netlink message causes `select_ops` to return an ops struct with `size` smaller than what `ops->init()` writes, a heap buffer overflow occurs during the init call at line 2693.

Reachability: The path is `nfnetlink_rcv_msg -> nf_tables_newrule/nf_tables_newsetelem -> nft_expr_init -> nf_tables_expr_parse (which calls select_ops) -> ops->init()`. The `nft_set_elem_expr_alloc` caller is confirmed reachable with no locking, making the race window exploitable from userspace with `CAP_NET_ADMIN` (or in a user namespace with netfilter access).

## Impact

No exploitable vulnerability exists. The error path correctly frees locally-held allocations that have no external references. No concurrent reader can access the not-yet-published expr object.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

The UAF scenario fails at Step 1 of the verification: the expr pointer is a local allocation that is never made visible to concurrent readers before the error path executes. kfree(expr) at line 2695 followed by release_ops at line 2699 is correct cleanup order — both objects are locally owned. The nft.commit_mutex (confirmed via lockdep_assert_held in nft_dynset_init caller) serializes the mutation path. No RCU-visible insertion of expr occurs before the error path. The primary agent incorrectly assumes nft_set_elem_expr_alloc exposes expr to concurrent readers during initialization, but the caller only publishes expr after nft_expr_init returns successfully.

**False-positive reason:** The alleged UAF requires concurrent readers to access an expression object that has never been published to any shared data structure. In the error path, expr is a locally-allocated object that fails initialization before being inserted into any set, rule, or table. No other thread can hold a reference to this object. The kfree(expr) followed by release_ops(info.ops) is a correct sequential cleanup of local allocations. The nft.commit_mutex serializes table mutations, and nft_set_elem_expr_alloc itself has not yet completed successfully (expr is being returned as ERR_PTR). The primary agent conflates the error path cleanup with a published-object UAF scenario, which is logically impossible here. The secondary buffer overflow claim is also unfounded because ops->size is determined by in-kernel nft_compat code, not directly from user-controlled netlink attributes.

## Remediation

No remediation required. The code is correct as written.

---
*Graph vulnerability score: 12.71 | Betweenness: 0.0000 | PageRank: 0.000358*
