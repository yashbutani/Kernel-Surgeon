# [INFORMATIONAL] Use After Free in ip_vs_conn_expire (CWE-416)

**Generated:** 2026-03-06T04:07:10.080172+00:00  
**Report ID:** `ip_vs_conn_expire_69d2285c`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/ipvs/ip_vs_conn.c` |
| Function | `ip_vs_conn_expire` |
| Line | 847 |
| Subsystem | net |

## Source Code

```c
  847 | static void ip_vs_conn_expire(struct timer_list *t)
  848 | {
  849 | 	struct ip_vs_conn *cp = from_timer(cp, t, timer);
  850 | 	struct netns_ipvs *ipvs = cp->ipvs;
  851 | 
  852 | 	/*
  853 | 	 *	do I control anybody?
  854 | 	 */
  855 | 	if (atomic_read(&cp->n_control))
  856 | 		goto expire_later;
  857 | 
  858 | 	/* Unlink conn if not referenced anymore */
  859 | 	if (likely(ip_vs_conn_unlink(cp))) {
  860 | 		struct ip_vs_conn *ct = cp->control;
  861 | 
  862 | 		/* delete the timer if it is activated by other users */
  863 | 		del_timer(&cp->timer);
  864 | 
  865 | 		/* does anybody control me? */
  866 | 		if (ct) {
  867 | 			bool has_ref = !cp->timeout && __ip_vs_conn_get(ct);
  868 | 
  869 | 			ip_vs_control_del(cp);
  870 | 			/* Drop CTL or non-assured TPL if not used anymore */
  871 | 			if (has_ref && !atomic_read(&ct->n_control) &&
  872 | 			    (!(ct->flags & IP_VS_CONN_F_TEMPLATE) ||
  873 | 			     !(ct->state & IP_VS_CTPL_S_ASSURED))) {
  874 | 				IP_VS_DBG(4, "drop controlling connection\n");
  875 | 				ip_vs_conn_del_put(ct);
  876 | 			} else if (has_ref) {
  877 | 				__ip_vs_conn_put(ct);
  878 | 			}
  879 | 		}
  880 | 
  881 | 		if ((cp->flags & IP_VS_CONN_F_NFCT) &&
  882 | 		    !(cp->flags & IP_VS_CONN_F_ONE_PACKET)) {
  883 | 			/* Do not access conntracks during subsys cleanup
  884 | 			 * because nf_conntrack_find_get can not be used after
  885 | 			 * conntrack cleanup for the net.
  886 | 			 */
  887 | 			smp_rmb();
  888 | 			if (ipvs->enable)
  889 | 				ip_vs_conn_drop_conntrack(cp);
  890 | 		}
  891 | 
  892 | 		if (unlikely(cp->app != NULL))
  893 | 			ip_vs_unbind_app(cp);
  894 | 		ip_vs_unbind_dest(cp);
  895 | 		if (cp->flags & IP_VS_CONN_F_NO_CPORT)
  896 | 			atomic_dec(&ip_vs_conn_no_cport_cnt);
  897 | 		if (cp->flags & IP_VS_CONN_F_ONE_PACKET)
  898 | 			ip_vs_conn_rcu_free(&cp->rcu_head);
  899 | 		else
  900 | 			call_rcu(&cp->rcu_head, ip_vs_conn_rcu_free);
  901 | 		atomic_dec(&ipvs->conn_count);
  902 | 		return;
  903 | 	}
  904 | 
  905 |   expire_later:
  906 | 	IP_VS_DBG(7, "delayed: conn->refcnt=%d conn->n_control=%d\n",
  907 | 		  refcount_read(&cp->refcnt),
  908 | 		  atomic_read(&cp->n_control));
  909 | 
  910 | 	refcount_inc(&cp->refcnt);
  911 | 	cp->timeout = 60*HZ;
  912 | 
  913 | 	if (ipvs->sync_state & IP_VS_STATE_MASTER)
  914 | 		ip_vs_sync_conn(ipvs, cp, sysctl_sync_threshold(ipvs));
  915 | 
  916 | 	__ip_vs_conn_put_timer(cp);
  917 | }
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
| Privileges Required | NONE |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

In ip_vs_conn_expire(), there is a Use-After-Free (UAF) vulnerability involving the controlling connection pointer `ct` (line 860: `struct ip_vs_conn *ct = cp->control`). The sequence is: (1) `ct = cp->control` is read (line 860); (2) `has_ref` is computed using `__ip_vs_conn_get(ct)` which conditionally increments ct's refcount (line 867); (3) `ip_vs_control_del(cp)` is called (line 869), which removes the control relationship; (4) the code then reads `ct->n_control` (line 871) and `ct->flags` and `ct->state` (lines 872-873) to make a branching decision. The critical issue: `ip_vs_conn_del_put(ct)` is called at line 875, which calls `ip_vs_conn_expire(&ct->timer)` directly (synchronously) if del_timer succeeds (see ip_vs_conn_del_put lines 836-841). This recursive call to ip_vs_conn_expire can fully free `ct` via `call_rcu(&cp->rcu_head, ip_vs_conn_rcu_free)` or `ip_vs_conn_rcu_free(&cp->rcu_head)`. However, if a concurrent thread racing on `ct` (e.g., another timer expiry or a packet processing path) has already decremented `ct`'s refcount to zero and freed it BETWEEN the `__ip_vs_conn_get(ct)` check and the subsequent accesses, `ct` memory could be accessed after free. More critically: the `has_ref` condition at line 867 is `!cp->timeout && __ip_vs_conn_get(ct)`. If `cp->timeout != 0`, `has_ref` is false and NO reference is taken on `ct`. This means at lines 871-878, `ct` is dereferenced (`ct->n_control`, `ct->flags`, `ct->state`) WITHOUT holding a reference, while a concurrent thread could free `ct`. The race window: between reading `cp->control` (line 860) and accessing `ct->n_control` (line 871), another CPU could decrement ct's refcount to zero and free it through a concurrent ip_vs_conn_expire on ct, especially since ip_vs_control_del(cp) at line 869 decrements ct->n_control which could trigger that path. Additionally, `ip_vs_conn_del_put` (lines 834-845) directly calls `ip_vs_conn_expire(&cp->timer)` after calling `__ip_vs_conn_put(cp)` which decrements the refcount — if this decrement takes refcount to zero and then ip_vs_conn_expire is called, the structure could already be freed or in an inconsistent state. The `cp->timeout = 0` write at line 839 to a potentially freed/freeing object is itself a write-after-free primitive.

## Impact

No demonstrated impact; the alleged UAF path does not exist because all accesses to ct are gated on has_ref which requires a successfully obtained reference

## Attack Path

```
Network packet reception → netfilter hook → ip_vs_in (ip_vs_core.c) → ip_vs_conn_put_timer / ip_vs_conn_expire (timer callback) → ip_vs_conn_expire(ct->timer) [recursive via ip_vs_conn_del_put] → UAF on `ct` at line 871-873. Alternatively: concurrent timer expiry on `ct` races with ip_vs_conn_expire reading ct->n_control/flags/state without reference at lines 871-873 when has_ref=false (cp->timeout != 0).
```

## Check-Bypass Analysis

The has_ref guard at line 867 is `!cp->timeout && __ip_vs_conn_get(ct)`. When cp->timeout is non-zero (set by the expire_later path: line 911 sets cp->timeout = 60*HZ), has_ref is false, meaning ct is accessed at lines 871-873 WITHOUT any reference being held. An attacker can manipulate connection state (via crafted network traffic or IPVS configuration) to ensure cp->timeout != 0 when the timer fires (e.g., by sending traffic that resets the connection state just before expiry, causing the expire_later path to execute on a previous invocation and set cp->timeout). In ip_vs_conn_flush, there is also a check at line 1383 for n_control but the actual expiry can race. ip_vs_conn_del_put calls __ip_vs_conn_put BEFORE ip_vs_conn_expire — if the refcount was already 1, __ip_vs_conn_put decrements to 0 and the subsequent ip_vs_conn_expire call is operating on a zero-refcount object.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

Code review shows lines 871-878 have two branches, both predicated on has_ref being true. When has_ref=false, the if(ct) block executes ip_vs_control_del(cp) but then falls through to the end of that block without touching ct fields. The primary agent incorrectly stated ct->n_control/flags/state are accessed when has_ref=false.

**False-positive reason:** The primary agent's core claim is incorrect. When has_ref=false (cp->timeout != 0), the code at lines 871-878 is entirely guarded by 'if (has_ref && ...)' and 'else if (has_ref)' — neither branch executes, so ct->n_control, ct->flags, and ct->state are NOT accessed without a reference. The has_ref flag serves as the proper guard: ct fields are only accessed when __ip_vs_conn_get(ct) succeeded and returned true, meaning a reference is held. The ip_vs_conn_del_put concern is also not a UAF: cp->timeout=0 is written while a reference is still held (del_timer succeeded), and __ip_vs_conn_put is called before ip_vs_conn_expire only to release the timer reference, with ip_vs_conn_unlink inside ip_vs_conn_expire providing the actual freeing gate via refcount_dec_if_one. No concrete race window without a reference exists in the presented code.

## Remediation

No remediation needed for the specific alleged vulnerability. The existing has_ref guard correctly protects ct field accesses.

---
*Graph vulnerability score: 10.99 | Betweenness: 0.0001 | PageRank: 0.002218*
