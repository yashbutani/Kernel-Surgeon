# [INFORMATIONAL] Use After Free + Off By One In Cleanup in start_sync_thread (CWE-119)

**Generated:** 2026-03-06T03:54:49.478697+00:00  
**Report ID:** `start_sync_thread_4331aa9e`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/ipvs/ip_vs_sync.c` |
| Function | `start_sync_thread` |
| Line | 1750 |
| Subsystem | net |

## Source Code

```c
 1750 | int start_sync_thread(struct netns_ipvs *ipvs, struct ipvs_sync_daemon_cfg *c,
 1751 | 		      int state)
 1752 | {
 1753 | 	struct ip_vs_sync_thread_data *ti = NULL, *tinfo;
 1754 | 	struct task_struct *task;
 1755 | 	struct net_device *dev;
 1756 | 	char *name;
 1757 | 	int (*threadfn)(void *data);
 1758 | 	int id = 0, count, hlen;
 1759 | 	int result = -ENOMEM;
 1760 | 	u16 mtu, min_mtu;
 1761 | 
 1762 | 	IP_VS_DBG(7, "%s(): pid %d\n", __func__, task_pid_nr(current));
 1763 | 	IP_VS_DBG(7, "Each ip_vs_sync_conn entry needs %zd bytes\n",
 1764 | 		  sizeof(struct ip_vs_sync_conn_v0));
 1765 | 
 1766 | 	/* increase the module use count */
 1767 | 	if (!ip_vs_use_count_inc())
 1768 | 		return -ENOPROTOOPT;
 1769 | 
 1770 | 	/* Do not hold one mutex and then to block on another */
 1771 | 	for (;;) {
 1772 | 		rtnl_lock();
 1773 | 		if (mutex_trylock(&ipvs->sync_mutex))
 1774 | 			break;
 1775 | 		rtnl_unlock();
 1776 | 		mutex_lock(&ipvs->sync_mutex);
 1777 | 		if (rtnl_trylock())
 1778 | 			break;
 1779 | 		mutex_unlock(&ipvs->sync_mutex);
 1780 | 	}
 1781 | 
 1782 | 	if (!ipvs->sync_state) {
 1783 | 		count = clamp(sysctl_sync_ports(ipvs), 1, IPVS_SYNC_PORTS_MAX);
 1784 | 		ipvs->threads_mask = count - 1;
 1785 | 	} else
 1786 | 		count = ipvs->threads_mask + 1;
 1787 | 
 1788 | 	if (c->mcast_af == AF_UNSPEC) {
 1789 | 		c->mcast_af = AF_INET;
 1790 | 		c->mcast_group.ip = cpu_to_be32(IP_VS_SYNC_GROUP);
 1791 | 	}
 1792 | 	if (!c->mcast_port)
 1793 | 		c->mcast_port = IP_VS_SYNC_PORT;
 1794 | 	if (!c->mcast_ttl)
 1795 | 		c->mcast_ttl = 1;
 1796 | 
 1797 | 	dev = __dev_get_by_name(ipvs->net, c->mcast_ifn);
 1798 | 	if (!dev) {
 1799 | 		pr_err("Unknown mcast interface: %s\n", c->mcast_ifn);
 1800 | 		result = -ENODEV;
 1801 | 		goto out_early;
 1802 | 	}
 1803 | 	hlen = (AF_INET6 == c->mcast_af) ?
 1804 | 	       sizeof(struct ipv6hdr) + sizeof(struct udphdr) :
 1805 | 	       sizeof(struct iphdr) + sizeof(struct udphdr);
 1806 | 	mtu = (state == IP_VS_STATE_BACKUP) ?
 1807 | 		  clamp(dev->mtu, 1500U, 65535U) : 1500U;
 1808 | 	min_mtu = (state == IP_VS_STATE_BACKUP) ? 1024 : 1;
 1809 | 
 1810 | 	if (c->sync_maxlen)
 1811 | 		c->sync_maxlen = clamp_t(unsigned int,
 1812 | 					 c->sync_maxlen, min_mtu,
 1813 | 					 65535 - hlen);
 1814 | 	else
 1815 | 		c->sync_maxlen = mtu - hlen;
 1816 | 
 1817 | 	if (state == IP_VS_STATE_MASTER) {
 1818 | 		result = -EEXIST;
 1819 | 		if (ipvs->ms)
 1820 | 			goto out_early;
 1821 | 
 1822 | 		ipvs->mcfg = *c;
 1823 | 		name = "ipvs-m:%d:%d";
 1824 | 		threadfn = sync_thread_master;
 1825 | 	} else if (state == IP_VS_STATE_BACKUP) {
 1826 | 		result = -EEXIST;
 1827 | 		if (ipvs->backup_tinfo)
 1828 | 			goto out_early;
 1829 | 
 1830 | 		ipvs->bcfg = *c;
 1831 | 		name = "ipvs-b:%d:%d";
 1832 | 		threadfn = sync_thread_backup;
 1833 | 	} else {
 1834 | 		result = -EINVAL;
 1835 | 		goto out_early;
 1836 | 	}
 1837 | 
 1838 | 	if (state == IP_VS_STATE_MASTER) {
 1839 | 		struct ipvs_master_sync_state *ms;
 1840 | 
 1841 | 		result = -ENOMEM;
 1842 | 		ipvs->ms = kcalloc(count, sizeof(ipvs->ms[0]), GFP_KERNEL);
 1843 | 		if (!ipvs->ms)
 1844 | 			goto out;
 1845 | 		ms = ipvs->ms;
 1846 | 		for (id = 0; id < count; id++, ms++) {
 1847 | 			INIT_LIST_HEAD(&ms->sync_queue);
 1848 | 			ms->sync_queue_len = 0;
 1849 | 			ms->sync_queue_delay = 0;
 1850 | 			INIT_DELAYED_WORK(&ms->master_wakeup_work,
 1851 | 					  master_wakeup_work_handler);
 1852 | 			ms->ipvs = ipvs;
 1853 | 		}
 1854 | 	}
 1855 | 	result = -ENOMEM;
 1856 | 	ti = kcalloc(count, sizeof(struct ip_vs_sync_thread_data),
 1857 | 		     GFP_KERNEL);
 1858 | 	if (!ti)
 1859 | 		goto out;
 1860 | 
 1861 | 	for (id = 0; id < count; id++) {
 1862 | 		tinfo = &ti[id];
 1863 | 		tinfo->ipvs = ipvs;
 1864 | 		if (state == IP_VS_STATE_BACKUP) {
 1865 | 			result = -ENOMEM;
 1866 | 			tinfo->buf = kmalloc(ipvs->bcfg.sync_maxlen,
 1867 | 					     GFP_KERNEL);
 1868 | 			if (!tinfo->buf)
 1869 | 				goto out;
 1870 | 		}
 1871 | 		tinfo->id = id;
 1872 | 		if (state == IP_VS_STATE_MASTER)
 1873 | 			result = make_send_sock(ipvs, id, dev, &tinfo->sock);
 1874 | 		else
 1875 | 			result = make_receive_sock(ipvs, id, dev, &tinfo->sock);
 1876 | 		if (result < 0)
 1877 | 			goto out;
 1878 | 
 1879 | 		task = kthread_run(threadfn, tinfo, name, ipvs->gen, id);
 1880 | 		if (IS_ERR(task)) {
 1881 | 			result = PTR_ERR(task);
 1882 | 			goto out;
 1883 | 		}
 1884 | 		tinfo->task = task;
 1885 | 	}
 1886 | 
 1887 | 	/* mark as active */
 1888 | 
 1889 | 	if (state == IP_VS_STATE_MASTER)
 1890 | 		ipvs->master_tinfo = ti;
 1891 | 	else
 1892 | 		ipvs->backup_tinfo = ti;
 1893 | 	spin_lock_bh(&ipvs->sync_buff_lock);
 1894 | 	ipvs->sync_state |= state;
 1895 | 	spin_unlock_bh(&ipvs->sync_buff_lock);
 1896 | 
 1897 | 	mutex_unlock(&ipvs->sync_mutex);
 1898 | 	rtnl_unlock();
 1899 | 
 1900 | 	return 0;
 1901 | 
 1902 | out:
 1903 | 	/* We do not need RTNL lock anymore, release it here so that
 1904 | 	 * sock_release below can use rtnl_lock to leave the mcast group.
 1905 | 	 */
 1906 | 	rtnl_unlock();
 1907 | 	id = min(id, count - 1);
 1908 | 	if (ti) {
 1909 | 		for (tinfo = ti + id; tinfo >= ti; tinfo--) {
 1910 | 			if (tinfo->task)
 1911 | 				kthread_stop(tinfo->task);
 1912 | 		}
 1913 | 	}
 1914 | 	if (!(ipvs->sync_state & IP_VS_STATE_MASTER)) {
 1915 | 		kfree(ipvs->ms);
 1916 | 		ipvs->ms = NULL;
 1917 | 	}
 1918 | 	mutex_unlock(&ipvs->sync_mutex);
 1919 | 
 1920 | 	/* No more mutexes, release socks */
 1921 | 	if (ti) {
 1922 | 		for (tinfo = ti + id; tinfo >= ti; tinfo--) {
 1923 | 			if (tinfo->sock)
 1924 | 				sock_release(tinfo->sock);
 1925 | 			kfree(tinfo->buf);
 1926 | 		}
 1927 | 		kfree(ti);
 1928 | 	}
 1929 | 
 1930 | 	/* decrease the module use count */
 1931 | 	ip_vs_use_count_dec();
 1932 | 	return result;
 1933 | 
 1934 | out_early:
 1935 | 	mutex_unlock(&ipvs->sync_mutex);
 1936 | 	rtnl_unlock();
 1937 | 
 1938 | 	/* decrease the module use count */
 1939 | 	ip_vs_use_count_dec();
 1940 | 	return result;
 1941 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | CWE-119 |
| Type | use_after_free + off_by_one_in_cleanup |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

There are two related vulnerabilities in start_sync_thread's error cleanup path:

**Vulnerability 1: Off-by-one / UAF in error cleanup loop (lines 1907-1926)**

At line 1907: `id = min(id, count - 1);`

The loop at line 1861 runs `for (id = 0; id < count; id++)`. When the loop body succeeds for all iterations, `id` exits as `count`. When `goto out` is triggered during iteration `id`, the variable `id` holds the index of the *currently-failing* entry.

Consider the error case where `kthread_run()` succeeds (line 1879) but then the *next* iteration fails. In this case, `tinfo->task` has been set for index `id-1`, but the failing allocation at index `id` causes `goto out` with `id` pointing to the entry that has NO valid task/sock yet.

The critical bug: `id = min(id, count - 1)` — if `id == count` (loop completed normally but some post-loop allocation failed — though in this code that cannot happen), this clamps correctly. BUT when `kthread_run` at line 1879 fails (`IS_ERR(task)`), `tinfo->task` is NOT set (it was zero-initialized by kcalloc), and `goto out` fires. The cleanup at lines 1909-1912 iterates `from ti+id DOWN to ti` calling `kthread_stop(tinfo->task)` for any non-NULL task. This is correct for the failing entry (task is NULL, check passes) but this logic is sound at first glance.

**Vulnerability 2: Race condition / UAF between kthread_stop and the running thread**

At line 1879, `kthread_run(threadfn, tinfo, ...)` is called. `tinfo` points into the `ti` array. The thread function (`sync_thread_master` or `sync_thread_backup`) receives `tinfo` as its `data` parameter and will access `tinfo->sock`, `tinfo->buf`, `tinfo->ipvs`, etc.

In the ERROR path (lines 1909-1912), `kthread_stop(tinfo->task)` is called to stop already-started threads. After `kthread_stop` returns, the code proceeds to `sock_release(tinfo->sock)` and `kfree(tinfo->buf)` (lines 1923-1925). THEN `kfree(ti)` is called at line 1927.

However: `kthread_stop` signals the thread to stop and waits for it to exit. The thread function accesses `tinfo` (which is allocated as part of `ti`). If `kthread_stop` returns but the thread has already exited and released its own reference to `tinfo->sock` or `tinfo->buf` internally, a double-free could occur. More critically, if the thread function accesses `tinfo->sock` AFTER the error path calls `sock_release(tinfo->sock)`, this is a UAF.

Looking more carefully: the thread function receives `tinfo` as a pointer to stack/heap data. After `kthread_stop()` returns in the cleanup loop (lines 1909-1912), all threads are stopped. THEN socks are released (line 1924) and buffers freed (line 1925). This ordering appears safe IF `kthread_stop` guarantees the thread has fully exited. `kthread_stop` does guarantee this in the Linux kernel. So this specific sequence is safe.

**Vulnerability 3: The REAL bug — `id = min(id, count - 1)` when `count` is 0**

At line 1783: `count = clamp(sysctl_sync_ports(ipvs), 1, IPVS_SYNC_PORTS_MAX)` — count is at least 1, so `count - 1 >= 0`. This looks safe.

But at line 1786: `count = ipvs->threads_mask + 1` — if `ipvs->threads_mask` is -1 (e.g., it was set to 0 and then decremented, or if a concurrent `stop_sync_thread` modifies `ipvs->threads_mask` under a different lock), `count` could be 0. With `count = 0`, `kcalloc(0, ...)` returns a non-NULL unique pointer, no threads are started, `id` remains 0, then `id = min(0, -1)` — but `count - 1` with count as unsigned/int... If count is `int` and is 0, then `count - 1 = -1`. `min(0, -1)` with signed comparison = -1. Then `tinfo = ti + (-1)` = pointer before `ti` buffer = **OUT-OF-BOUNDS ACCESS**.

**Vulnerability 4: The confirmed bug — cleanup loop direction is wrong for partially-initialized arrays**

When `goto out` fires at line 1882 (kthread_run fails) with id=N, the cleanup iterates ti[N] down to ti[0] calling kthread_stop. ti[N] has task=NULL (kthread_run failed), so it's skipped. ti[0..N-1] have valid tasks and are stopped. Then the second loop (1922-1926) releases socks and frees bufs for ti[0..N]. But ti[N].sock may be in a partially-initialized state: `make_send_sock`/`make_receive_sock` might have succeeded (line 1873/1875) but kthread_run failed (line 1879-1882). In this case ti[N].sock IS valid and IS released. This is actually correct.

HOWEVER: the MISSING cleanup for sock is in the FIRST loop. The first loop only stops tasks. The second loop (starting at line 1922) re-iterates to release socks. But what if `goto out` fires at line 1869 (tinfo->buf alloc fails) for id=N? At that point, ti[N].sock is NULL (make_receive_sock not yet called), ti[N].buf is NULL (alloc failed), ti[N].task is NULL. The second loop will call `kfree(NULL)` (safe) and `sock_release(NULL)` — wait, line 1923 checks `if (tinfo->sock)`. Safe. But for earlier entries ti[0..N-1], their tasks ARE running. But wait — the FIRST cleanup loop (1909-1912) calls kthread_stop for ti[0..N-1]. That's correct.

**Vulnerability 5: CONFIRMED — Socket leak when kthread_run fails after make_send/receive_sock succeeds**

At line 1879, if kthread_run fails, id still holds the current index. `goto out` fires. The cleanup first loop runs ti[id] down to ti[0], stopping tasks. Then the second loop runs the SAME range, releasing socks and freeing bufs. For ti[id]: task is NULL (kthread_run failed), sock IS set (make_send/receive_sock succeeded at line 1873/1875), buf may or may not be set. The second loop correctly releases ti[id].sock. This is actually handled.

**Vulnerability 6: CONFIRMED UAF — backup thread accessing freed tinfo->buf**

In `sync_thread_backup`, the thread uses `tinfo->buf` (sized `ipvs->bcfg.sync_maxlen`) to receive data. If `stop_sync_thread` is called concurrently (racing with start_sync_thread), it could free `ipvs->backup_tinfo` while threads are still running. This is the cross-function state (P7) vulnerability. The `ipvs->backup_tinfo` pointer is set at line 1892 AFTER threads are already running (started at line 1879). There is a window between when kthread_run starts the thread and when `ipvs->backup_tinfo` is set where the thread is running but the tinfo array isn't tracked yet — meaning a concurrent `stop_sync_thread` would miss these threads and kfree the tinfo array while threads are still accessing it.

## Impact

No confirmed exploitable impact; the alleged vulnerabilities are not reachable or are handled by existing logic

## Attack Path

```
userspace CAP_NET_ADMIN → setsockopt(IP_VS_SO_SET_STARTDAEMON) → do_ip_vs_set_ctl → start_sync_thread; OR: sendmsg(NETLINK_GENERIC, IPVS_CMD_NEW_DAEMON) → ip_vs_genl_set_daemon → ip_vs_genl_new_daemon → start_sync_thread
```

## Check-Bypass Analysis

1. CAP_NET_ADMIN is checked in do_ip_vs_set_ctl (line 2467) before calling start_sync_thread. The genl path (ip_vs_genl_set_daemon) also requires appropriate privileges via the genl framework. So privilege bypass is difficult from unprivileged userspace, but user namespaces (unshare -n) can grant CAP_NET_ADMIN within a namespace, making this reachable by non-root users with user namespace support enabled.

2. The `ipvs->threads_mask` read at line 1786 (when `ipvs->sync_state != 0`) is protected by `ipvs->sync_mutex` held throughout. However, the state check at line 1782 is inside the mutex, so this should be safe against concurrent start/stop.

3. The mcast_ifn string is copied via strlcpy in ip_vs_genl_new_daemon (line 3562) with sizeof(c.mcast_ifn) bound — safe.

4. TOCTOU: The `ipvs->sync_state` is read at line 1782 under sync_mutex, but `ipvs->sync_state |= state` is done under spin_lock_bh (line 1893-1895) AFTER mutex release... wait, mutex is still held at line 1893-1895 and released at line 1897. The spin_lock is nested inside mutex. This is correct but the ordering between setting `ipvs->master_tinfo`/`ipvs->backup_tinfo` (line 1890/1892) and `ipvs->sync_state` update (line 1894) means there's a brief window where tinfo is set but sync_state doesn't reflect it yet, though this is all mutex-protected so concurrent callers can't see it.

5. Key bypass: With user namespaces enabled (`CONFIG_USER_NS`), an unprivileged user can create a new network namespace and gain CAP_NET_ADMIN within it, then trigger this code path.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

count is always >=1 due to clamp(sysctl_sync_ports,1,MAX) on first call and threads_mask+1 on subsequent (threads_mask set from count-1>=0). sync_mutex serializes all state transitions. kthread_stop guarantees thread exit. Cleanup loops iterate ti[id] down to ti[0] covering exactly the right range. No confirmed bug.

**False-positive reason:** All alleged vulnerabilities fail on examination of the actual code: (1) count=0 is impossible because both branches guarantee count>=1 (clamp with min=1, or threads_mask set from count-1), making min(id,count-1) safe. (2) The cleanup loops correctly handle the partially-initialized array: ti[id] may have sock set but task NULL (kthread_run failed), the first loop skips it (NULL task check), the second loop releases its sock. (3) The concurrent stop_sync_thread race is blocked by sync_mutex held throughout start_sync_thread from line 1773 to 1897/1918. (4) kthread_stop guarantees full thread exit before returning, so sock_release/kfree after kthread_stop in the error path is safe. No exploitable UAF, OOB access, or race condition is demonstrated with concrete evidence.

## Remediation

No remediation required; the code is correct. If defensive programming is desired, an explicit assert(count > 0) after line 1786 and a comment explaining the cleanup loop invariants would aid readability.

---
*Graph vulnerability score: 12.90 | Betweenness: 0.0000 | PageRank: 0.002187*
