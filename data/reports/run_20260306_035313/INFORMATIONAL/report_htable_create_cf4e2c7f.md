# [INFORMATIONAL] Use After Free in htable_create (CWE-362)

**Generated:** 2026-03-06T04:06:02.114492+00:00  
**Report ID:** `htable_create_cf4e2c7f`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/xt_hashlimit.c` |
| Function | `htable_create` |
| Line | 275 |
| Subsystem | net |

## Source Code

```c
  275 | static int htable_create(struct net *net, struct hashlimit_cfg3 *cfg,
  276 | 			 const char *name, u_int8_t family,
  277 | 			 struct xt_hashlimit_htable **out_hinfo,
  278 | 			 int revision)
  279 | {
  280 | 	struct hashlimit_net *hashlimit_net = hashlimit_pernet(net);
  281 | 	struct xt_hashlimit_htable *hinfo;
  282 | 	const struct seq_operations *ops;
  283 | 	unsigned int size, i;
  284 | 	unsigned long nr_pages = totalram_pages();
  285 | 	int ret;
  286 | 
  287 | 	if (cfg->size) {
  288 | 		size = cfg->size;
  289 | 	} else {
  290 | 		size = (nr_pages << PAGE_SHIFT) / 16384 /
  291 | 		       sizeof(struct hlist_head);
  292 | 		if (nr_pages > 1024 * 1024 * 1024 / PAGE_SIZE)
  293 | 			size = 8192;
  294 | 		if (size < 16)
  295 | 			size = 16;
  296 | 	}
  297 | 	/* FIXME: don't use vmalloc() here or anywhere else -HW */
  298 | 	hinfo = vmalloc(struct_size(hinfo, hash, size));
  299 | 	if (hinfo == NULL)
  300 | 		return -ENOMEM;
  301 | 	*out_hinfo = hinfo;
  302 | 
  303 | 	/* copy match config into hashtable config */
  304 | 	ret = cfg_copy(&hinfo->cfg, (void *)cfg, 3);
  305 | 	if (ret) {
  306 | 		vfree(hinfo);
  307 | 		return ret;
  308 | 	}
  309 | 
  310 | 	hinfo->cfg.size = size;
  311 | 	if (hinfo->cfg.max == 0)
  312 | 		hinfo->cfg.max = 8 * hinfo->cfg.size;
  313 | 	else if (hinfo->cfg.max < hinfo->cfg.size)
  314 | 		hinfo->cfg.max = hinfo->cfg.size;
  315 | 
  316 | 	for (i = 0; i < hinfo->cfg.size; i++)
  317 | 		INIT_HLIST_HEAD(&hinfo->hash[i]);
  318 | 
  319 | 	refcount_set(&hinfo->use, 1);
  320 | 	hinfo->count = 0;
  321 | 	hinfo->family = family;
  322 | 	hinfo->rnd_initialized = false;
  323 | 	hinfo->name = kstrdup(name, GFP_KERNEL);
  324 | 	if (!hinfo->name) {
  325 | 		vfree(hinfo);
  326 | 		return -ENOMEM;
  327 | 	}
  328 | 	spin_lock_init(&hinfo->lock);
  329 | 
  330 | 	switch (revision) {
  331 | 	case 1:
  332 | 		ops = &dl_seq_ops_v1;
  333 | 		break;
  334 | 	case 2:
  335 | 		ops = &dl_seq_ops_v2;
  336 | 		break;
  337 | 	default:
  338 | 		ops = &dl_seq_ops;
  339 | 	}
  340 | 
  341 | 	hinfo->pde = proc_create_seq_data(name, 0,
  342 | 		(family == NFPROTO_IPV4) ?
  343 | 		hashlimit_net->ipt_hashlimit : hashlimit_net->ip6t_hashlimit,
  344 | 		ops, hinfo);
  345 | 	if (hinfo->pde == NULL) {
  346 | 		kfree(hinfo->name);
  347 | 		vfree(hinfo);
  348 | 		return -ENOMEM;
  349 | 	}
  350 | 	hinfo->net = net;
  351 | 
  352 | 	INIT_DEFERRABLE_WORK(&hinfo->gc_work, htable_gc);
  353 | 	queue_delayed_work(system_power_efficient_wq, &hinfo->gc_work,
  354 | 			   msecs_to_jiffies(hinfo->cfg.gc_interval));
  355 | 
  356 | 	hlist_add_head(&hinfo->node, &hashlimit_net->htables);
  357 | 
  358 | 	return 0;
  359 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | CWE-362 |
| Type | use_after_free |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | LOW |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

There is a Use-After-Free (UAF) vulnerability enabled by a deferred work / garbage-collection race in htable_create. At line 352-354 the function schedules a deferrable work item (`htable_gc`) on `system_power_efficient_wq` that holds a raw pointer back into `hinfo`. The `hinfo` object is then added to the per-net htables list at line 356. No reference count is taken before the work is queued. If the caller's error path (or a concurrent netns teardown via `hashlimit_net_exit`) calls `htable_destroy()` / `htable_put()` and drops the last reference while the gc work is still pending or executing, the gc callback (`htable_gc`) will dereference a freed `hinfo` structure. The vulnerability has two concrete sub-cases:

1. **GC callback UAF (P7)**: `queue_delayed_work` is called at line 353 BEFORE `hlist_add_head` at line 356. The work can be triggered (after the delay elapses) while the caller is concurrently destroying the table. `htable_gc` accesses `hinfo->hash`, `hinfo->lock`, `hinfo->cfg`, and `hinfo->count` without holding a reference that would prevent the underlying vmalloc'd memory from being freed by `vfree(hinfo)` in the destroy path.

2. **Integer overflow / heap overflow on cfg->size (P2)**: `cfg->size` is a user-controlled `u32`. In `hashlimit_mt_check_common` it is clamped to `HASHLIMIT_MAX_SIZE` only if it is *greater than* `HASHLIMIT_MAX_SIZE` (lines 848-851). If `HASHLIMIT_MAX_SIZE` is defined such that `struct_size(hinfo, hash, size)` can wrap (i.e., `size * sizeof(struct hlist_head)` overflows `size_t`), the `vmalloc()` at line 298 will allocate a region that is too small, and the loop at lines 316-317 (`INIT_HLIST_HEAD`) will write beyond the allocation. The actual exploitability depends on the value of `HASHLIMIT_MAX_SIZE` and the pointer size — needs verification.

3. **Stale *out_hinfo on error (secondary primitive)**: At line 301 `*out_hinfo = hinfo` is set unconditionally before the cfg_copy check (line 304) and before kstrdup (line 323). If either of those fails, `hinfo` is freed via `vfree(hinfo)` but `*out_hinfo` has already been written with the now-freed pointer. If the caller does not check the return value properly (or has a TOCTOU window), it may dereference the stale pointer.

The primary exploitable path is the GC UAF: a CAP_NET_ADMIN process in a user namespace creates a hashlimit match (iptables/nftables) that triggers htable_create, then immediately destroys the netns or the rule, racing the gc worker to cause hinfo to be accessed after vfree.

## Impact

No demonstrated exploitable impact. The theoretical UAF is prevented by cancel_delayed_work_sync() synchronization in the destroy path.

## Attack Path

```
sys_setsockopt / nf_setsockopt → xt_check_match → hashlimit_mt_check_v1/v2/v3 → hashlimit_mt_check_common → htable_create [line 353: queue_delayed_work(htable_gc)] → concurrent netns teardown / rule deletion → htable_destroy → vfree(hinfo) → htable_gc executes → UAF on freed hinfo
```

## Check-Bypass Analysis

1. The refcount set at line 319 (`refcount_set(&hinfo->use, 1)`) is intended to guard lifetime, but `queue_delayed_work` is called at line 353 WITHOUT incrementing the refcount. If the destroy path decrements the refcount to zero and calls vfree() before the delayed gc fires, the gc work item executes on freed memory. The window is controlled by `cfg->gc_interval` — an attacker can set this to a small but nonzero value (since 0 is rejected at line 846) to minimize the race window needed.
2. `hashlimit_mt_check_common` validates that `cfg->size <= HASHLIMIT_MAX_SIZE`, but does NOT validate that `struct_size(hinfo, hash, cfg->size)` will not overflow. If `HASHLIMIT_MAX_SIZE` is large enough (needs macro lookup), an attacker supplying a crafted `cfg->size` near SIZE_MAX / sizeof(struct hlist_head) could bypass the vmalloc size sanity.
3. User namespaces with `CAP_NET_ADMIN` (widely available via unshare) are sufficient to reach this code path — no host-level privileges required.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

Key evidence against confirmation: (1) htable_destroy in xt_hashlimit.c uses cancel_delayed_work_sync(&hinfo->gc_work) — this is verifiable in the upstream kernel source and is mandated by the embedded work-item pattern. (2) HASHLIMIT_MAX_SIZE=0x100000; struct_size(hinfo, hash, 0x100000) on 64-bit = sizeof(*hinfo) + 8*1048576 ~= 8MB, no overflow, and struct_size() uses __ab_c_size overflow checking. (3) The *out_hinfo stale pointer issue requires callers to ignore non-zero return values, which they do not. The primary agent's score of 12.7 exceeds the maximum CVSS v3.1 score of 10.0, indicating a scoring methodology error. All three sub-cases are either mitigated by existing kernel patterns or based on incorrect assumptions.

**False-positive reason:** The primary vulnerability claim (GC callback UAF) is mitigated by cancel_delayed_work_sync() in htable_destroy, which is the standard pattern for embedded delayed_work structures. The work item is embedded within hinfo itself (hinfo->gc_work), so htable_destroy must use cancel_delayed_work_sync() before vfree(hinfo) — this is universally done in the kernel's xt_hashlimit implementation and enforced by the kernel work-queue API contract for embedded work items. The integer overflow (P2) is not exploitable: HASHLIMIT_MAX_SIZE is 1<<20, and struct_size() uses overflow-safe arithmetic in modern kernels; the resulting allocation is ~8MB on 64-bit, well within size_t bounds. The stale *out_hinfo claim (P3) is not exploitable because all callers (hashlimit_mt_check_common) check the return value of htable_create before using *out_hinfo, and the error paths are taken before any external reference to hinfo is established. The primary agent incorrectly treats the absence of a refcount increment for the GC work as a vulnerability, ignoring that cancel_delayed_work_sync() provides equivalent synchronization for embedded work items without needing refcounting.

## Remediation

No remediation required. The existing cancel_delayed_work_sync() pattern correctly handles the lifecycle of the embedded gc_work item. If the actual htable_destroy implementation were found to use cancel_delayed_work() (non-sync) instead, that would require changing to cancel_delayed_work_sync().

---
*Graph vulnerability score: 12.66 | Betweenness: 0.0000 | PageRank: 0.000372*
