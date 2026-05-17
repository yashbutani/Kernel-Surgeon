# [INFORMATIONAL] Use After Free + Heap Buffer Overflow in IPSET_TOKEN (CWE-362)

**Generated:** 2026-03-06T03:55:18.984509+00:00  
**Report ID:** `IPSET_TOKEN_6a9afaab`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/ipset/ip_set_hash_gen.h` |
| Function | `IPSET_TOKEN` |
| Line | 1451 |
| Subsystem | net |

## Source Code

```c
 1451 | IPSET_TOKEN(HTYPE, _create)(struct net *net, struct ip_set *set,
 1452 | 			    struct nlattr *tb[], u32 flags)
 1453 | {
 1454 | 	u32 hashsize = IPSET_DEFAULT_HASHSIZE, maxelem = IPSET_DEFAULT_MAXELEM;
 1455 | #ifdef IP_SET_HASH_WITH_MARKMASK
 1456 | 	u32 markmask;
 1457 | #endif
 1458 | 	u8 hbits;
 1459 | #ifdef IP_SET_HASH_WITH_NETMASK
 1460 | 	u8 netmask;
 1461 | #endif
 1462 | 	size_t hsize;
 1463 | 	struct htype *h;
 1464 | 	struct htable *t;
 1465 | 	u32 i;
 1466 | 
 1467 | 	pr_debug("Create set %s with family %s\n",
 1468 | 		 set->name, set->family == NFPROTO_IPV4 ? "inet" : "inet6");
 1469 | 
 1470 | #ifdef IP_SET_PROTO_UNDEF
 1471 | 	if (set->family != NFPROTO_UNSPEC)
 1472 | 		return -IPSET_ERR_INVALID_FAMILY;
 1473 | #else
 1474 | 	if (!(set->family == NFPROTO_IPV4 || set->family == NFPROTO_IPV6))
 1475 | 		return -IPSET_ERR_INVALID_FAMILY;
 1476 | #endif
 1477 | 
 1478 | 	if (unlikely(!ip_set_optattr_netorder(tb, IPSET_ATTR_HASHSIZE) ||
 1479 | 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_MAXELEM) ||
 1480 | 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_TIMEOUT) ||
 1481 | 		     !ip_set_optattr_netorder(tb, IPSET_ATTR_CADT_FLAGS)))
 1482 | 		return -IPSET_ERR_PROTOCOL;
 1483 | 
 1484 | #ifdef IP_SET_HASH_WITH_MARKMASK
 1485 | 	/* Separated condition in order to avoid directive in argument list */
 1486 | 	if (unlikely(!ip_set_optattr_netorder(tb, IPSET_ATTR_MARKMASK)))
 1487 | 		return -IPSET_ERR_PROTOCOL;
 1488 | 
 1489 | 	markmask = 0xffffffff;
 1490 | 	if (tb[IPSET_ATTR_MARKMASK]) {
 1491 | 		markmask = ntohl(nla_get_be32(tb[IPSET_ATTR_MARKMASK]));
 1492 | 		if (markmask == 0)
 1493 | 			return -IPSET_ERR_INVALID_MARKMASK;
 1494 | 	}
 1495 | #endif
 1496 | 
 1497 | #ifdef IP_SET_HASH_WITH_NETMASK
 1498 | 	netmask = set->family == NFPROTO_IPV4 ? 32 : 128;
 1499 | 	if (tb[IPSET_ATTR_NETMASK]) {
 1500 | 		netmask = nla_get_u8(tb[IPSET_ATTR_NETMASK]);
 1501 | 
 1502 | 		if ((set->family == NFPROTO_IPV4 && netmask > 32) ||
 1503 | 		    (set->family == NFPROTO_IPV6 && netmask > 128) ||
 1504 | 		    netmask == 0)
 1505 | 			return -IPSET_ERR_INVALID_NETMASK;
 1506 | 	}
 1507 | #endif
 1508 | 
 1509 | 	if (tb[IPSET_ATTR_HASHSIZE]) {
 1510 | 		hashsize = ip_set_get_h32(tb[IPSET_ATTR_HASHSIZE]);
 1511 | 		if (hashsize < IPSET_MIMINAL_HASHSIZE)
 1512 | 			hashsize = IPSET_MIMINAL_HASHSIZE;
 1513 | 	}
 1514 | 
 1515 | 	if (tb[IPSET_ATTR_MAXELEM])
 1516 | 		maxelem = ip_set_get_h32(tb[IPSET_ATTR_MAXELEM]);
 1517 | 
 1518 | 	hsize = sizeof(*h);
 1519 | 	h = kzalloc(hsize, GFP_KERNEL);
 1520 | 	if (!h)
 1521 | 		return -ENOMEM;
 1522 | 
 1523 | 	hbits = htable_bits(hashsize);
 1524 | 	hsize = htable_size(hbits);
 1525 | 	if (hsize == 0) {
 1526 | 		kfree(h);
 1527 | 		return -ENOMEM;
 1528 | 	}
 1529 | 	t = ip_set_alloc(hsize);
 1530 | 	if (!t) {
 1531 | 		kfree(h);
 1532 | 		return -ENOMEM;
 1533 | 	}
 1534 | 	t->hregion = ip_set_alloc(ahash_sizeof_regions(hbits));
 1535 | 	if (!t->hregion) {
 1536 | 		ip_set_free(t);
 1537 | 		kfree(h);
 1538 | 		return -ENOMEM;
 1539 | 	}
 1540 | 	h->gc.set = set;
 1541 | 	for (i = 0; i < ahash_numof_locks(hbits); i++)
 1542 | 		spin_lock_init(&t->hregion[i].lock);
 1543 | 	h->maxelem = maxelem;
 1544 | #ifdef IP_SET_HASH_WITH_NETMASK
 1545 | 	h->netmask = netmask;
 1546 | #endif
 1547 | #ifdef IP_SET_HASH_WITH_MARKMASK
 1548 | 	h->markmask = markmask;
 1549 | #endif
 1550 | 	get_random_bytes(&h->initval, sizeof(h->initval));
 1551 | 
 1552 | 	t->htable_bits = hbits;
 1553 | 	t->maxelem = h->maxelem / ahash_numof_locks(hbits);
 1554 | 	RCU_INIT_POINTER(h->table, t);
 1555 | 
 1556 | 	INIT_LIST_HEAD(&h->ad);
 1557 | 	set->data = h;
 1558 | #ifndef IP_SET_PROTO_UNDEF
 1559 | 	if (set->family == NFPROTO_IPV4) {
 1560 | #endif
 1561 | 		set->variant = &IPSET_TOKEN(HTYPE, 4_variant);
 1562 | 		set->dsize = ip_set_elem_len(set, tb,
 1563 | 			sizeof(struct IPSET_TOKEN(HTYPE, 4_elem)),
 1564 | 			__alignof__(struct IPSET_TOKEN(HTYPE, 4_elem)));
 1565 | #ifndef IP_SET_PROTO_UNDEF
 1566 | 	} else {
 1567 | 		set->variant = &IPSET_TOKEN(HTYPE, 6_variant);
 1568 | 		set->dsize = ip_set_elem_len(set, tb,
 1569 | 			sizeof(struct IPSET_TOKEN(HTYPE, 6_elem)),
 1570 | 			__alignof__(struct IPSET_TOKEN(HTYPE, 6_elem)));
 1571 | 	}
 1572 | #endif
 1573 | 	set->timeout = IPSET_NO_TIMEOUT;
 1574 | 	if (tb[IPSET_ATTR_TIMEOUT]) {
 1575 | 		set->timeout = ip_set_timeout_uget(tb[IPSET_ATTR_TIMEOUT]);
 1576 | #ifndef IP_SET_PROTO_UNDEF
 1577 | 		if (set->family == NFPROTO_IPV4)
 1578 | #endif
 1579 | 			IPSET_TOKEN(HTYPE, 4_gc_init)(&h->gc);
 1580 | #ifndef IP_SET_PROTO_UNDEF
 1581 | 		else
 1582 | 			IPSET_TOKEN(HTYPE, 6_gc_init)(&h->gc);
 1583 | #endif
 1584 | 	}
 1585 | 	pr_debug("create %s hashsize %u (%u) maxelem %u: %p(%p)\n",
 1586 | 		 set->name, jhash_size(t->htable_bits),
 1587 | 		 t->htable_bits, h->maxelem, set->data, t);
 1588 | 
 1589 | 	return 0;
 1590 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | CWE-362 |
| Type | use_after_free + heap_buffer_overflow |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

Two distinct vulnerability classes exist in this function:

**1. UAF via GC timer race (P7) — Primary Concern:**
At lines 1574-1583, when `tb[IPSET_ATTR_TIMEOUT]` is present, the garbage collection timer is initialized via `IPSET_TOKEN(HTYPE, 4_gc_init)(&h->gc)` or `IPSET_TOKEN(HTYPE, 6_gc_init)(&h->gc)`. This schedules an async timer callback (`mtype_gc`) that holds a reference to `h` (through `h->gc.set = set` at line 1540, and `set->data = h` at line 1557).

Critical race: If set creation fails after `gc_init` but before the set is fully registered (e.g., if a concurrent destroy operation races with the create path), the timer can fire and dereference `h` after it has been freed. Specifically:
- `h` is allocated at line 1519
- `h->gc.set = set` at line 1540 creates the back-reference
- `set->data = h` at line 1557
- Timer is armed at lines 1579/1582
- If the caller (ip_set_create) later encounters an error and calls mtype_destroy, `h` will be freed while the timer may still be pending

The `mtype_gc` caller shown accesses `map->set` from timer context — if the set is destroyed before the timer fires, this is a textbook UAF on the `h` struct and its embedded `htable` pointer.

**2. Integer overflow in htable allocation (P2):**
At line 1523, `hbits = htable_bits(hashsize)` computes the number of hash bits from a user-controlled `hashsize` (parsed from `tb[IPSET_ATTR_HASHSIZE]` at line 1510). While `htable_size()` does have an overflow guard (hbits > 31 returns 0), the intermediate path through `htable_bits()` is not shown — if `htable_bits()` can return a value > 31 for adversarial `hashsize` inputs, `htable_size()` returns 0 and the allocation is skipped (ENOMEM path), but if it returns exactly 31, `jhash_size(31) = 2^31 = 2147483648` buckets are requested. At line 1534, `ahash_sizeof_regions(hbits)` is called with this large `hbits` — if this function does NOT have equivalent overflow protection, an integer overflow can produce a small allocation that is then accessed out-of-bounds during the `spin_lock_init` loop at line 1541-1542.

Specifically: `ahash_sizeof_regions(hbits)` allocates memory for `ahash_numof_locks(hbits)` regions. If `hbits=31`, `ahash_numof_locks(31)` could yield a large value (depending on macro definition), and if `ahash_sizeof_regions()` overflows, the allocation at line 1534 is too small for the subsequent loop at line 1541-1542 which iterates `ahash_numof_locks(hbits)` times — writing past the end of `t->hregion`.

**3. maxelem division by zero / integer truncation (secondary):**
At line 1553: `t->maxelem = h->maxelem / ahash_numof_locks(hbits)`. If `ahash_numof_locks(hbits)` returns 0 for certain hbits values, this is a divide-by-zero. More likely, if `maxelem` is set to 0 by userspace (no lower bound check at line 1515-1516), subsequent per-region maxelem becomes 0, which may bypass capacity checks in the add path.

## Impact

No confirmed exploitable impact. The alleged vulnerabilities do not hold under scrutiny of the actual synchronization model and macro implementations.

## Attack Path

```
userspace (CAP_NET_ADMIN or user namespace) → nfnetlink_rcv_msg → ip_set_create (IPSET_CMD_CREATE) → IPSET_TOKEN(HTYPE,_create) → [1] timer UAF via gc_init race with concurrent destroy, [2] htable_size overflow if ahash_sizeof_regions lacks guards → OOB write in spin_lock_init loop at line 1541-1542
```

## Check-Bypass Analysis

1. `ip_set_create` is reachable via netlink socket with NFNL_SUBSYS_IPSET. In Linux user namespaces (since ~3.8), CAP_NET_ADMIN within a namespace is sufficient to call ipset create operations, making this reachable from unprivileged containers.

2. The `hashsize` value flows from userspace nlattr `IPSET_ATTR_HASHSIZE` → `ip_set_get_h32()` → `htable_bits()` → `ahash_sizeof_regions()`. The only validation is the minimum at line 1511-1512 (`IPSET_MIMINAL_HASHSIZE`), with no maximum cap. A value of 0x80000000 or similar large power-of-2 could stress the overflow path.

3. The GC timer UAF race: after `gc_init` arms the timer, there is no synchronization guarantee that the timer is cancelled before `h` is freed on error unwind paths. The caller `ip_set_create` must properly call `set->variant->destroy()` which would invoke `mtype_destroy` — but if mtype_destroy calls `del_timer_sync`, the race window is between timer arm and timer sync.

4. `maxelem` has no lower bound check — userspace can set it to 0 or 1, creating pathological behavior in per-region capacity calculations.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

Attack path 1 (timer UAF): nfnetlink serializes create/destroy operations; the set is not registered/visible until after successful return, so no concurrent destroy can race with gc_init. The function has no error path after gc_init. Attack path 2 (integer overflow): ahash_numof_locks is capped in standard implementations; without showing the macro definition, the overflow claim is unsubstantiated. The mtype_gc evidence is from bitmap, not hash, incorrectly cited. Attack path 3 (div-by-zero): ahash_numof_locks cannot return 0 for valid hbits values validated by htable_size().

**False-positive reason:** 1) The alleged UAF timer race is not viable: ip_set_create holds the nfnetlink subsystem mutex throughout the entire create operation, making concurrent destroy impossible during this window. The set is not visible to other operations until after successful return. There is no error path after gc_init in the shown code — the function returns 0 immediately after gc_init. 2) The integer overflow in ahash_sizeof_regions relies on ahash_numof_locks lacking a cap, but standard kernel ipset implementations cap this value (typically at AHASH_MAX_LOCKS_SHIFT), preventing overflow. The primary agent did not show the macro definitions to substantiate the overflow claim. 3) The mtype_gc code cited as evidence is from ip_set_bitmap_gen.h, not ip_set_hash_gen.h — a different subsystem entirely, making the UAF evidence cross-contaminated. 4) The division-by-zero at line 1553 is speculative; ahash_numof_locks returns at minimum 1 for any valid hbits. All three claimed vulnerabilities lack concrete evidence of exploitable code paths.

## Remediation

No immediate remediation required based on current evidence. If ahash_numof_locks and ahash_sizeof_regions macros are found to lack overflow guards, add explicit caps similar to the htable_size() guard (hbits > 31 check).

---
*Graph vulnerability score: 12.89 | Betweenness: 0.0000 | PageRank: 0.000539*
