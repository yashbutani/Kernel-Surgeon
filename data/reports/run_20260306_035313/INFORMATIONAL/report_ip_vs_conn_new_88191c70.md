# [INFORMATIONAL] Use After Free in ip_vs_conn_new (CWE-416)

**Generated:** 2026-03-06T03:54:20.675665+00:00  
**Report ID:** `ip_vs_conn_new_88191c70`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/ipvs/ip_vs_conn.c` |
| Function | `ip_vs_conn_new` |
| Line | 941 |
| Subsystem | net |

## Source Code

```c
  941 | ip_vs_conn_new(const struct ip_vs_conn_param *p, int dest_af,
  942 | 	       const union nf_inet_addr *daddr, __be16 dport, unsigned int flags,
  943 | 	       struct ip_vs_dest *dest, __u32 fwmark)
  944 | {
  945 | 	struct ip_vs_conn *cp;
  946 | 	struct netns_ipvs *ipvs = p->ipvs;
  947 | 	struct ip_vs_proto_data *pd = ip_vs_proto_data_get(p->ipvs,
  948 | 							   p->protocol);
  949 | 
  950 | 	cp = kmem_cache_alloc(ip_vs_conn_cachep, GFP_ATOMIC);
  951 | 	if (cp == NULL) {
  952 | 		IP_VS_ERR_RL("%s(): no memory\n", __func__);
  953 | 		return NULL;
  954 | 	}
  955 | 
  956 | 	INIT_HLIST_NODE(&cp->c_list);
  957 | 	timer_setup(&cp->timer, ip_vs_conn_expire, 0);
  958 | 	cp->ipvs	   = ipvs;
  959 | 	cp->af		   = p->af;
  960 | 	cp->daf		   = dest_af;
  961 | 	cp->protocol	   = p->protocol;
  962 | 	ip_vs_addr_set(p->af, &cp->caddr, p->caddr);
  963 | 	cp->cport	   = p->cport;
  964 | 	/* proto should only be IPPROTO_IP if p->vaddr is a fwmark */
  965 | 	ip_vs_addr_set(p->protocol == IPPROTO_IP ? AF_UNSPEC : p->af,
  966 | 		       &cp->vaddr, p->vaddr);
  967 | 	cp->vport	   = p->vport;
  968 | 	ip_vs_addr_set(cp->daf, &cp->daddr, daddr);
  969 | 	cp->dport          = dport;
  970 | 	cp->flags	   = flags;
  971 | 	cp->fwmark         = fwmark;
  972 | 	if (flags & IP_VS_CONN_F_TEMPLATE && p->pe) {
  973 | 		ip_vs_pe_get(p->pe);
  974 | 		cp->pe = p->pe;
  975 | 		cp->pe_data = p->pe_data;
  976 | 		cp->pe_data_len = p->pe_data_len;
  977 | 	} else {
  978 | 		cp->pe = NULL;
  979 | 		cp->pe_data = NULL;
  980 | 		cp->pe_data_len = 0;
  981 | 	}
  982 | 	spin_lock_init(&cp->lock);
  983 | 
  984 | 	/*
  985 | 	 * Set the entry is referenced by the current thread before hashing
  986 | 	 * it in the table, so that other thread run ip_vs_random_dropentry
  987 | 	 * but cannot drop this entry.
  988 | 	 */
  989 | 	refcount_set(&cp->refcnt, 1);
  990 | 
  991 | 	cp->control = NULL;
  992 | 	atomic_set(&cp->n_control, 0);
  993 | 	atomic_set(&cp->in_pkts, 0);
  994 | 
  995 | 	cp->packet_xmit = NULL;
  996 | 	cp->app = NULL;
  997 | 	cp->app_data = NULL;
  998 | 	/* reset struct ip_vs_seq */
  999 | 	cp->in_seq.delta = 0;
 1000 | 	cp->out_seq.delta = 0;
 1001 | 
 1002 | 	atomic_inc(&ipvs->conn_count);
 1003 | 	if (flags & IP_VS_CONN_F_NO_CPORT)
 1004 | 		atomic_inc(&ip_vs_conn_no_cport_cnt);
 1005 | 
 1006 | 	/* Bind the connection with a destination server */
 1007 | 	cp->dest = NULL;
 1008 | 	ip_vs_bind_dest(cp, dest);
 1009 | 
 1010 | 	/* Set its state and timeout */
 1011 | 	cp->state = 0;
 1012 | 	cp->old_state = 0;
 1013 | 	cp->timeout = 3*HZ;
 1014 | 	cp->sync_endtime = jiffies & ~3UL;
 1015 | 
 1016 | 	/* Bind its packet transmitter */
 1017 | #ifdef CONFIG_IP_VS_IPV6
 1018 | 	if (p->af == AF_INET6)
 1019 | 		ip_vs_bind_xmit_v6(cp);
 1020 | 	else
 1021 | #endif
 1022 | 		ip_vs_bind_xmit(cp);
 1023 | 
 1024 | 	if (unlikely(pd && atomic_read(&pd->appcnt)))
 1025 | 		ip_vs_bind_app(cp, pd->pp);
 1026 | 
 1027 | 	/*
 1028 | 	 * Allow conntrack to be preserved. By default, conntrack
 1029 | 	 * is created and destroyed for every packet.
 1030 | 	 * Sometimes keeping conntrack can be useful for
 1031 | 	 * IP_VS_CONN_F_ONE_PACKET too.
 1032 | 	 */
 1033 | 
 1034 | 	if (ip_vs_conntrack_enabled(ipvs))
 1035 | 		cp->flags |= IP_VS_CONN_F_NFCT;
 1036 | 
 1037 | 	/* Hash it in the ip_vs_conn_tab finally */
 1038 | 	ip_vs_conn_hash(cp);
 1039 | 
 1040 | 	return cp;
 1041 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | CWE-416 |
| Type | use_after_free |
| Attack Vector | NETWORK |
| Attack Complexity | HIGH |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

The function ip_vs_conn_new() contains a Use-After-Free (UAF) vulnerability rooted in the persistence engine (PE) state transfer at lines 972-976. When the IP_VS_CONN_F_TEMPLATE flag is set and p->pe is non-NULL, the function transfers pe_data ownership (line 975: cp->pe_data = p->pe_data) and pe_data_len (line 976: cp->pe_data_len = p->pe_data_len) from the caller-supplied param struct to the newly allocated connection cp WITHOUT duplicating or taking a reference on pe_data. The pe_data pointer is simply copied by reference. If the caller's ip_vs_conn_param (or the pe_data buffer it points to) is freed or reused before the newly created connection cp is destroyed, cp->pe_data becomes a dangling pointer. This is compounded by ip_vs_pe_get(p->pe) at line 973 — only the pe (protocol engine) gets a refcount increment, NOT pe_data. The pe_data buffer lifetime is entirely unguarded. Additionally, ip_vs_proc_conn() in ip_vs_sync.c creates ip_vs_conn_param on the stack and populates pe_data from network-received sync datagrams; the connection created from this param will hold a pe_data pointer into already-freed or reused stack/heap memory after ip_vs_proc_conn returns. A second related issue: ip_vs_bind_app() at line 1025 calls pp->app_conn_bind(cp) via a function pointer with the connection cp partially initialized (cp->app_data is NULL, cp->app is NULL) but cp->flags, cp->dest, and cp->packet_xmit are already set. If app_conn_bind() fails or panics due to a concurrent modification, the connection is already partially in the hash table (hash happens after at line 1038), creating a window where a malformed or partially-initialized connection is visible to other threads. The allocation itself (line 950, kmem_cache_alloc with GFP_ATOMIC) is from a fixed-size cache ip_vs_conn_cachep, so there's no integer overflow in the allocation size per se (P2 is less relevant), but the P7 UAF on pe_data is real and exploitable.

## Impact

Not demonstrated — the alleged UAF requires proof that pe_data is freed by callers after ip_vs_conn_new() returns, which is not shown in the provided code.

## Attack Path

```
Network packet received → netfilter hook → ip_vs_in() → ip_vs_schedule() → [tcp_conn_schedule | udp_conn_schedule | ip_vs_leave] → ip_vs_conn_new(param, ...) → line 975: cp->pe_data = p->pe_data (shallow copy, no refcount) → caller's param goes out of scope or pe_data buffer is freed → cp->pe_data is dangling UAF. Alternatively: sync daemon receives crafted sync packet → ip_vs_process_message() → ip_vs_proc_conn() → ip_vs_conn_new(param, ...) → param.pe_data points into heap buffer freed after ip_vs_proc_conn returns.
```

## Check-Bypass Analysis

1. ip_vs_proc_conn() (ip_vs_sync.c): Receives network-controlled sync datagrams. The param struct including pe_data is populated from the sync packet payload. ip_vs_proc_conn() passes this stack-local param directly to ip_vs_conn_new(). After ip_vs_conn_new() returns, the param goes out of scope, but cp->pe_data still points into the now-invalid pe_data from the sync packet processing buffer. A remote attacker with access to the IPVS sync network (multicast) can craft sync packets with IP_VS_CONN_F_TEMPLATE set and pe_data populated to trigger this. 2. ip_vs_ftp_out() calls ip_vs_conn_new() for data connections. The FTP PE populates pe_data from packet contents; if the FTP app frees pe_data after the call, UAF follows. 3. No lock protects the pe_data lifetime across ip_vs_conn_new() — ip_vs_pe_get() only increments the PE module refcount, NOT the pe_data buffer refcount. 4. The check at line 972 (flags & IP_VS_CONN_F_TEMPLATE && p->pe) is bypassable: the sync path sets IP_VS_CONN_F_TEMPLATE based on the received sync type field, which is fully attacker-controlled over the sync network.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

Code review of lines 972-976 confirms shallow pointer copy of pe_data without pe_data-specific refcounting. However, this matches a standard ownership-transfer pattern. ip_vs_pe_get() refcounts the PE engine to prevent module unload, which is the correct protection needed. pe_data lifecycle: allocated by pe->fill_param(), transferred to cp via ip_vs_conn_new(), freed when cp is destroyed via ip_vs_conn_expire(). No caller code was provided showing pe_data being freed after ip_vs_conn_new() returns. The sync path (ip_vs_proc_conn) requires CAP_NET_ADMIN for IPVS configuration and multicast network adjacency, further limiting exploitability. Finding is unsubstantiated without a concrete double-ownership code path.

**False-positive reason:** The alleged UAF relies on the assumption that callers free pe_data after ip_vs_conn_new() returns, but no actual caller code demonstrating this double-ownership pattern is provided. The code at lines 972-976 implements an ownership-transfer (move semantics) pattern common in the Linux kernel: pe_data is allocated by pe->fill_param() for the connection's use, and after ip_vs_conn_new() takes it, the caller no longer owns it. ip_vs_pe_get() correctly refcounts the PE engine module (preventing module unload), while pe_data ownership is implicitly transferred to cp — a consistent design. The primary agent provides no specific code showing a caller that (1) sets param.pe_data, (2) calls ip_vs_conn_new(), and (3) subsequently frees param.pe_data independently. Without this concrete evidence, the 'dangling pointer' scenario is theoretical. The ip_vs_proc_conn() caller path shown does not demonstrate pe_data being freed after the call. The secondary concern about ip_vs_bind_app() race is also not substantiated — hashing happens after bind_app(), not before.

## Remediation

No remediation required unless a concrete caller demonstrating double-ownership of pe_data can be identified. If such a caller exists, add explicit documentation of ownership transfer semantics or implement pe_data reference counting.

---
*Graph vulnerability score: 12.90 | Betweenness: 0.0000 | PageRank: 0.000684*
