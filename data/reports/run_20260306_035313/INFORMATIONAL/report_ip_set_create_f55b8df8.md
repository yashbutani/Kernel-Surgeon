# [INFORMATIONAL] Use After Free + Heap Buffer Overflow in ip_set_create (CWE-362)

**Generated:** 2026-03-06T04:06:42.476966+00:00  
**Report ID:** `ip_set_create_f55b8df8`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/ipset/ip_set_core.c` |
| Function | `ip_set_create` |
| Line | 1053 |
| Subsystem | net |

## Source Code

```c
 1053 | static int ip_set_create(struct net *net, struct sock *ctnl,
 1054 | 			 struct sk_buff *skb, const struct nlmsghdr *nlh,
 1055 | 			 const struct nlattr * const attr[],
 1056 | 			 struct netlink_ext_ack *extack)
 1057 | {
 1058 | 	struct ip_set_net *inst = ip_set_pernet(net);
 1059 | 	struct ip_set *set, *clash = NULL;
 1060 | 	ip_set_id_t index = IPSET_INVALID_ID;
 1061 | 	struct nlattr *tb[IPSET_ATTR_CREATE_MAX + 1] = {};
 1062 | 	const char *name, *typename;
 1063 | 	u8 family, revision;
 1064 | 	u32 flags = flag_exist(nlh);
 1065 | 	int ret = 0;
 1066 | 
 1067 | 	if (unlikely(protocol_min_failed(attr) ||
 1068 | 		     !attr[IPSET_ATTR_SETNAME] ||
 1069 | 		     !attr[IPSET_ATTR_TYPENAME] ||
 1070 | 		     !attr[IPSET_ATTR_REVISION] ||
 1071 | 		     !attr[IPSET_ATTR_FAMILY] ||
 1072 | 		     (attr[IPSET_ATTR_DATA] &&
 1073 | 		      !flag_nested(attr[IPSET_ATTR_DATA]))))
 1074 | 		return -IPSET_ERR_PROTOCOL;
 1075 | 
 1076 | 	name = nla_data(attr[IPSET_ATTR_SETNAME]);
 1077 | 	typename = nla_data(attr[IPSET_ATTR_TYPENAME]);
 1078 | 	family = nla_get_u8(attr[IPSET_ATTR_FAMILY]);
 1079 | 	revision = nla_get_u8(attr[IPSET_ATTR_REVISION]);
 1080 | 	pr_debug("setname: %s, typename: %s, family: %s, revision: %u\n",
 1081 | 		 name, typename, family_name(family), revision);
 1082 | 
 1083 | 	/* First, and without any locks, allocate and initialize
 1084 | 	 * a normal base set structure.
 1085 | 	 */
 1086 | 	set = kzalloc(sizeof(*set), GFP_KERNEL);
 1087 | 	if (!set)
 1088 | 		return -ENOMEM;
 1089 | 	spin_lock_init(&set->lock);
 1090 | 	strlcpy(set->name, name, IPSET_MAXNAMELEN);
 1091 | 	set->family = family;
 1092 | 	set->revision = revision;
 1093 | 
 1094 | 	/* Next, check that we know the type, and take
 1095 | 	 * a reference on the type, to make sure it stays available
 1096 | 	 * while constructing our new set.
 1097 | 	 *
 1098 | 	 * After referencing the type, we try to create the type
 1099 | 	 * specific part of the set without holding any locks.
 1100 | 	 */
 1101 | 	ret = find_set_type_get(typename, family, revision, &set->type);
 1102 | 	if (ret)
 1103 | 		goto out;
 1104 | 
 1105 | 	/* Without holding any locks, create private part. */
 1106 | 	if (attr[IPSET_ATTR_DATA] &&
 1107 | 	    nla_parse_nested(tb, IPSET_ATTR_CREATE_MAX, attr[IPSET_ATTR_DATA],
 1108 | 			     set->type->create_policy, NULL)) {
 1109 | 		ret = -IPSET_ERR_PROTOCOL;
 1110 | 		goto put_out;
 1111 | 	}
 1112 | 
 1113 | 	ret = set->type->create(net, set, tb, flags);
 1114 | 	if (ret != 0)
 1115 | 		goto put_out;
 1116 | 
 1117 | 	/* BTW, ret==0 here. */
 1118 | 
 1119 | 	/* Here, we have a valid, constructed set and we are protected
 1120 | 	 * by the nfnl mutex. Find the first free index in ip_set_list
 1121 | 	 * and check clashing.
 1122 | 	 */
 1123 | 	ret = find_free_id(inst, set->name, &index, &clash);
 1124 | 	if (ret == -EEXIST) {
 1125 | 		/* If this is the same set and requested, ignore error */
 1126 | 		if ((flags & IPSET_FLAG_EXIST) &&
 1127 | 		    STRNCMP(set->type->name, clash->type->name) &&
 1128 | 		    set->type->family == clash->type->family &&
 1129 | 		    set->type->revision_min == clash->type->revision_min &&
 1130 | 		    set->type->revision_max == clash->type->revision_max &&
 1131 | 		    set->variant->same_set(set, clash))
 1132 | 			ret = 0;
 1133 | 		goto cleanup;
 1134 | 	} else if (ret == -IPSET_ERR_MAX_SETS) {
 1135 | 		struct ip_set **list, **tmp;
 1136 | 		ip_set_id_t i = inst->ip_set_max + IP_SET_INC;
 1137 | 
 1138 | 		if (i < inst->ip_set_max || i == IPSET_INVALID_ID)
 1139 | 			/* Wraparound */
 1140 | 			goto cleanup;
 1141 | 
 1142 | 		list = kvcalloc(i, sizeof(struct ip_set *), GFP_KERNEL);
 1143 | 		if (!list)
 1144 | 			goto cleanup;
 1145 | 		/* nfnl mutex is held, both lists are valid */
 1146 | 		tmp = ip_set_dereference(inst->ip_set_list);
 1147 | 		memcpy(list, tmp, sizeof(struct ip_set *) * inst->ip_set_max);
 1148 | 		rcu_assign_pointer(inst->ip_set_list, list);
 1149 | 		/* Make sure all current packets have passed through */
 1150 | 		synchronize_net();
 1151 | 		/* Use new list */
 1152 | 		index = inst->ip_set_max;
 1153 | 		inst->ip_set_max = i;
 1154 | 		kvfree(tmp);
 1155 | 		ret = 0;
 1156 | 	} else if (ret) {
 1157 | 		goto cleanup;
 1158 | 	}
 1159 | 
 1160 | 	/* Finally! Add our shiny new set to the list, and be done. */
 1161 | 	pr_debug("create: '%s' created with index %u!\n", set->name, index);
 1162 | 	ip_set(inst, index) = set;
 1163 | 
 1164 | 	return ret;
 1165 | 
 1166 | cleanup:
 1167 | 	set->variant->destroy(set);
 1168 | put_out:
 1169 | 	module_put(set->type->me);
 1170 | out:
 1171 | 	kfree(set);
 1172 | 	return ret;
 1173 | }
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
| Privileges Required | LOW |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

Two distinct vulnerabilities exist in ip_set_create:

1. **Use-After-Free (UAF) at line 1167 — cleanup label** (P7/HIGH):
At the `cleanup:` label (line 1166-1167), the code calls `set->variant->destroy(set)`. However, `set->variant` is only assigned inside `set->type->create(net, set, tb, flags)` at line 1113. If `find_free_id()` returns `-EEXIST` (line 1124) AND the `IPSET_FLAG_EXIST` branch at line 1126-1132 is NOT taken (i.e., types mismatch), execution falls through to `cleanup:` at line 1133. At this point, `set->variant` may be NULL or uninitialized if `set->type->create()` failed to set it, or more critically: if `find_free_id()` returns `-EEXIST` directly (before `create()` is called... wait, no — `create()` IS called at 1113 before `find_free_id()` at 1123). So `set->variant` SHOULD be set after a successful `create()`. The real UAF risk: if `set->type->create()` sets `set->variant` to point into a module's data, then `module_put(set->type->me)` at line 1169 releases the module reference, potentially allowing the module to be unloaded BEFORE `set->variant->destroy(set)` is called at line 1167. The execution order in the `cleanup:` path is: `destroy(set)` (line 1167) → `module_put()` (line 1169) — so this specific ordering is actually safe. HOWEVER: if execution reaches `cleanup:` via the `-EEXIST` path (line 1133), then `set->variant->destroy(set)` is called, which destroys the newly-created set's private data. This is correct behavior. But a subtle UAF exists if a concurrent thread frees the `clash` set between the `find_free_id()` returning `-EEXIST` and the `same_set` comparison at line 1131. The `clash` pointer returned by `find_free_id()` is not refcounted — if another thread destroys `clash` concurrently, `clash->type->name` etc. at lines 1127-1131 constitute a UAF.

2. **Integer Overflow → Heap Buffer Overflow at lines 1136-1154** (P2/HIGH):
At line 1136: `ip_set_id_t i = inst->ip_set_max + IP_SET_INC;`. The type `ip_set_id_t` is `u16` (16-bit unsigned). The overflow check at line 1138 is `if (i < inst->ip_set_max || i == IPSET_INVALID_ID)`. `IPSET_INVALID_ID` is `0xFFFF` (the max u16 value). If `inst->ip_set_max` is, say, `0xFFFF - IP_SET_INC + 1`, then `i` wraps around to a small value, triggering the wraparound guard. However, if `IP_SET_INC` is small (e.g., 64) and `inst->ip_set_max` = 0xFFBF (65471), then `i = 0xFFFF` which equals `IPSET_INVALID_ID` and is caught. But if the check passes, `kvcalloc(i, sizeof(struct ip_set *), GFP_KERNEL)` at line 1142 allocates `i` pointers. Then `memcpy(list, tmp, sizeof(struct ip_set *) * inst->ip_set_max)` at line 1147 copies `inst->ip_set_max` pointers into a buffer sized for `i` pointers. Since `i = inst->ip_set_max + IP_SET_INC`, the memcpy copies LESS than the allocation — this is actually safe in this direction. The concern is the inverse: if due to overflow `i < inst->ip_set_max`, the overflow check SHOULD catch it at line 1138 (`i < inst->ip_set_max`). BUT: since `i` is `u16`, if `inst->ip_set_max` is already at or near `IPSET_INVALID_ID - 1`, and IP_SET_INC causes a wrap to a small value, the allocation at line 1142 would be for a small number of pointers, but `memcpy` at line 1147 would copy `inst->ip_set_max` (large) pointers → **heap buffer overflow**. Wait — re-examining: the check `i < inst->ip_set_max` catches the wraparound case. If `i` wraps to 0 or small, `i < inst->ip_set_max` is true, so `goto cleanup` is taken. This check appears sound for u16. However, if `ip_set_id_t` is actually wider than u16 in some configurations, or if `IP_SET_INC` is attacker-influenced, there may be risk.

3. **Missing validation of `name` and `typename` NLA string lengths** (P4):
At lines 1076-1077, `nla_data()` is called on `IPSET_ATTR_SETNAME` and `IPSET_ATTR_TYPENAME` without validating that the netlink attributes are NUL-terminated strings of bounded length. The `strlcpy` at line 1090 bounds the copy to `IPSET_MAXNAMELEN`, but if the NLA policy does not enforce `NLA_NUL_STRING` type with max length, a non-NUL-terminated attribute could cause `strlcpy` to read past the NLA data into adjacent netlink buffer memory (information leak or OOB read). The `pr_debug` at line 1080-1081 also prints `name` and `typename` with `%s`, amplifying this read.

## Impact

No confirmed exploitable impact. Theoretical race is blocked by nfnl mutex serialization. Integer overflow path has correct wraparound guard. NLA string handling is bounded by strlcpy.

## Attack Path

```
Userspace netlink socket (NETLINK_NETFILTER / nfnetlink) → nfnetlink_rcv → nfnetlink_rcv_msg → nfnl_subsys_call → ip_set_create (via NFNL_SUBSYS_IPSET / IPSET_CMD_CREATE handler). Requires CAP_NET_ADMIN in the user namespace — but unprivileged user namespaces (if enabled) allow this attack from an unprivileged process. Attack for UAF: (1) Create set A, (2) concurrently destroy set A, (3) race the `clash` pointer dereference at lines 1127-1131 in ip_set_create. Attack for potential OOB: send IPSET_ATTR_SETNAME with NLA type not NLA_NUL_STRING and no NUL terminator.
```

## Check-Bypass Analysis

1. The `clash` UAF race: `find_free_id()` returns a pointer to an existing `ip_set` in `inst->ip_set_list` as `clash`. This pointer is obtained without incrementing a refcount. Between returning from `find_free_id()` and the comparisons at lines 1127-1131, another thread executing `ip_set_destroy` can free the `clash` set. The nfnl mutex SHOULD serialize netlink operations, but if `ip_set_destroy` is callable from a different path (e.g., ip_set_net exit), the mutex may not be held. Need to verify if nfnl mutex fully protects `clash` lifetime.
2. The overflow check at line 1138 relies on u16 arithmetic wrapping behavior. If the compiler performs the addition in a wider type before truncating to u16, the `i < inst->ip_set_max` check could be defeated. This is a well-known C integer promotion issue.
3. NLA attribute validation: The policy for IPSET_ATTR_SETNAME and IPSET_ATTR_TYPENAME must specify NLA_NUL_STRING with `.len = IPSET_MAXNAMELEN - 1` to be safe. If they use NLA_BINARY or NLA_STRING without length limit, the bounds check in strlcpy does not prevent OOB reads from the NLA payload.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

Key evidence against confirmation: (1) Line 1119-1121 comment and nfnl subsystem design confirm mutex is held throughout find_free_id() and clash dereference — ip_set_destroy requires the same mutex, making concurrent destruction impossible during lines 1127-1131. (2) Line 1138 check 'i < inst->ip_set_max' correctly catches u16 wraparound after integer-promoted addition truncated back to u16; memcpy at 1147 copies inst->ip_set_max entries into buffer of size i > inst->ip_set_max. (3) strlcpy(set->name, name, IPSET_MAXNAMELEN) at line 1090 prevents buffer overflow regardless of NLA NUL-termination status. The primary agent's score of 11.9 exceeds the CVSS 3.1 maximum of 10.0, indicating methodological errors in the automated analysis.

**False-positive reason:** All three claimed vulnerabilities have mitigations: (1) The 'clash' UAF race is prevented by the nfnl mutex, which serializes all ipset netlink operations including destroy — the primary agent's own analysis acknowledges this but fails to conclude it negates the race; (2) The integer overflow → heap overflow is prevented by the explicit wraparound check at line 1138 ('i < inst->ip_set_max'), which correctly catches u16 truncation due to C integer promotion semantics (addition in 'int', truncated back to u16 on assignment, then compared as u16); (3) The NLA string OOB read is speculative — strlcpy at line 1090 bounds the copy to IPSET_MAXNAMELEN regardless, and pr_debug is typically a no-op in production builds. The 'module_put before destroy' ordering concern is also moot since line 1167 (destroy) precedes line 1169 (module_put) in the cleanup path.

## Remediation

No immediate remediation required for confirmed vulnerabilities. As defensive hardening: verify NLA policy specifies NLA_NUL_STRING with .len = IPSET_MAXNAMELEN-1 for IPSET_ATTR_SETNAME and IPSET_ATTR_TYPENAME to prevent any theoretical OOB reads in pr_debug paths.

---
*Graph vulnerability score: 11.94 | Betweenness: 0.0000 | PageRank: 0.000658*
