# [INFORMATIONAL] Parse Error in insert_tree (unknown)

**Generated:** 2026-03-06T04:18:12.208215+00:00  
**Report ID:** `insert_tree_39af5388`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nf_conncount.c` |
| Function | `insert_tree` |
| Line | 300 |
| Subsystem | net |

## Source Code

```c
  300 | insert_tree(struct net *net,
  301 | 	    struct nf_conncount_data *data,
  302 | 	    struct rb_root *root,
  303 | 	    unsigned int hash,
  304 | 	    const u32 *key,
  305 | 	    const struct nf_conntrack_tuple *tuple,
  306 | 	    const struct nf_conntrack_zone *zone)
  307 | {
  308 | 	struct nf_conncount_rb *gc_nodes[CONNCOUNT_GC_MAX_NODES];
  309 | 	struct rb_node **rbnode, *parent;
  310 | 	struct nf_conncount_rb *rbconn;
  311 | 	struct nf_conncount_tuple *conn;
  312 | 	unsigned int count = 0, gc_count = 0;
  313 | 	u8 keylen = data->keylen;
  314 | 	bool do_gc = true;
  315 | 
  316 | 	spin_lock_bh(&nf_conncount_locks[hash]);
  317 | restart:
  318 | 	parent = NULL;
  319 | 	rbnode = &(root->rb_node);
  320 | 	while (*rbnode) {
  321 | 		int diff;
  322 | 		rbconn = rb_entry(*rbnode, struct nf_conncount_rb, node);
  323 | 
  324 | 		parent = *rbnode;
  325 | 		diff = key_diff(key, rbconn->key, keylen);
  326 | 		if (diff < 0) {
  327 | 			rbnode = &((*rbnode)->rb_left);
  328 | 		} else if (diff > 0) {
  329 | 			rbnode = &((*rbnode)->rb_right);
  330 | 		} else {
  331 | 			int ret;
  332 | 
  333 | 			ret = nf_conncount_add(net, &rbconn->list, tuple, zone);
  334 | 			if (ret)
  335 | 				count = 0; /* hotdrop */
  336 | 			else
  337 | 				count = rbconn->list.count;
  338 | 			tree_nodes_free(root, gc_nodes, gc_count);
  339 | 			goto out_unlock;
  340 | 		}
  341 | 
  342 | 		if (gc_count >= ARRAY_SIZE(gc_nodes))
  343 | 			continue;
  344 | 
  345 | 		if (do_gc && nf_conncount_gc_list(net, &rbconn->list))
  346 | 			gc_nodes[gc_count++] = rbconn;
  347 | 	}
  348 | 
  349 | 	if (gc_count) {
  350 | 		tree_nodes_free(root, gc_nodes, gc_count);
  351 | 		schedule_gc_worker(data, hash);
  352 | 		gc_count = 0;
  353 | 		do_gc = false;
  354 | 		goto restart;
  355 | 	}
  356 | 
  357 | 	/* expected case: match, insert new node */
  358 | 	rbconn = kmem_cache_alloc(conncount_rb_cachep, GFP_ATOMIC);
  359 | 	if (rbconn == NULL)
  360 | 		goto out_unlock;
  361 | 
  362 | 	conn = kmem_cache_alloc(conncount_conn_cachep, GFP_ATOMIC);
  363 | 	if (conn == NULL) {
  364 | 		kmem_cache_free(conncount_rb_cachep, rbconn);
  365 | 		goto out_unlock;
  366 | 	}
  367 | 
  368 | 	conn->tuple = *tuple;
  369 | 	conn->zone = *zone;
  370 | 	memcpy(rbconn->key, key, sizeof(u32) * keylen);
  371 | 
  372 | 	nf_conncount_list_init(&rbconn->list);
  373 | 	list_add(&conn->node, &rbconn->list.head);
  374 | 	count = 1;
  375 | 	rbconn->list.count = count;
  376 | 
  377 | 	rb_link_node_rcu(&rbconn->node, parent, rbnode);
  378 | 	rb_insert_color(&rbconn->node, root);
  379 | out_unlock:
  380 | 	spin_unlock_bh(&nf_conncount_locks[hash]);
  381 | 	return count;
  382 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | unknown |
| Type | parse_error |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description


{
    "is_vulnerable": true,
    "confidence": "HIGH",
    "vulnerability_type": "use_after_free + heap_buffer_overflow",
    "description": "Two distinct vulnerabilities exist in insert_tree():\n\n**1. Use-After-Free (UAF) via GC race — PRIMARY VULNERABILITY (CVE pattern P7)**\n\nAt line 345-346, `nf_conncount_gc_list()` is called while traversing the RB-tree under `nf_conncount_locks[hash]`. When `nf_conncount_gc_list()` returns true, the `rbconn` node is queued in `gc_nodes[]`. Then at line 

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** LOW

Skipped verification (primary agent: not vulnerable)

**False-positive reason:** Primary agent did not flag as vulnerable

---
*Graph vulnerability score: 14.69 | Betweenness: 0.0000 | PageRank: 0.000567*
