# [INFORMATIONAL] Heap Buffer Overflow + Missing Bounds Check in nfnl_cthelper_create (CWE-476)

**Generated:** 2026-03-06T03:56:11.701928+00:00  
**Report ID:** `nfnl_cthelper_create_45176071`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nfnetlink_cthelper.c` |
| Function | `nfnl_cthelper_create` |
| Line | 216 |
| Subsystem | net |

## Source Code

```c
  216 | nfnl_cthelper_create(const struct nlattr * const tb[],
  217 | 		     struct nf_conntrack_tuple *tuple)
  218 | {
  219 | 	struct nf_conntrack_helper *helper;
  220 | 	struct nfnl_cthelper *nfcth;
  221 | 	unsigned int size;
  222 | 	int ret;
  223 | 
  224 | 	if (!tb[NFCTH_TUPLE] || !tb[NFCTH_POLICY] || !tb[NFCTH_PRIV_DATA_LEN])
  225 | 		return -EINVAL;
  226 | 
  227 | 	nfcth = kzalloc(sizeof(*nfcth), GFP_KERNEL);
  228 | 	if (nfcth == NULL)
  229 | 		return -ENOMEM;
  230 | 	helper = &nfcth->helper;
  231 | 
  232 | 	ret = nfnl_cthelper_parse_expect_policy(helper, tb[NFCTH_POLICY]);
  233 | 	if (ret < 0)
  234 | 		goto err1;
  235 | 
  236 | 	nla_strlcpy(helper->name,
  237 | 		    tb[NFCTH_NAME], NF_CT_HELPER_NAME_LEN);
  238 | 	size = ntohl(nla_get_be32(tb[NFCTH_PRIV_DATA_LEN]));
  239 | 	if (size > sizeof_field(struct nf_conn_help, data)) {
  240 | 		ret = -ENOMEM;
  241 | 		goto err2;
  242 | 	}
  243 | 	helper->data_len = size;
  244 | 
  245 | 	helper->flags |= NF_CT_HELPER_F_USERSPACE;
  246 | 	memcpy(&helper->tuple, tuple, sizeof(struct nf_conntrack_tuple));
  247 | 
  248 | 	helper->me = THIS_MODULE;
  249 | 	helper->help = nfnl_userspace_cthelper;
  250 | 	helper->from_nlattr = nfnl_cthelper_from_nlattr;
  251 | 	helper->to_nlattr = nfnl_cthelper_to_nlattr;
  252 | 
  253 | 	/* Default to queue number zero, this can be updated at any time. */
  254 | 	if (tb[NFCTH_QUEUE_NUM])
  255 | 		helper->queue_num = ntohl(nla_get_be32(tb[NFCTH_QUEUE_NUM]));
  256 | 
  257 | 	if (tb[NFCTH_STATUS]) {
  258 | 		int status = ntohl(nla_get_be32(tb[NFCTH_STATUS]));
  259 | 
  260 | 		switch(status) {
  261 | 		case NFCT_HELPER_STATUS_ENABLED:
  262 | 			helper->flags |= NF_CT_HELPER_F_CONFIGURED;
  263 | 			break;
  264 | 		case NFCT_HELPER_STATUS_DISABLED:
  265 | 			helper->flags &= ~NF_CT_HELPER_F_CONFIGURED;
  266 | 			break;
  267 | 		}
  268 | 	}
  269 | 
  270 | 	ret = nf_conntrack_helper_register(helper);
  271 | 	if (ret < 0)
  272 | 		goto err2;
  273 | 
  274 | 	list_add_tail(&nfcth->list, &nfnl_cthelper_list);
  275 | 	return 0;
  276 | err2:
  277 | 	kfree(helper->expect_policy);
  278 | err1:
  279 | 	kfree(nfcth);
  280 | 	return ret;
  281 | }
```

## Classification

| Metric | Value |
|---|---|
| Severity | **INFORMATIONAL** |
| CVSS Score | 0.0 |
| CWE | CWE-476 |
| Type | heap_buffer_overflow + missing_bounds_check |
| Attack Vector | LOCAL |
| Attack Complexity | HIGH |
| Privileges Required | HIGH |
| User Interaction | NONE |
| Exploitability | LOW |

## Description

CVE-2021-20218 class vulnerability in nfnl_cthelper_create. The function at line 238 reads a user-controlled 32-bit value `size = ntohl(nla_get_be32(tb[NFCTH_PRIV_DATA_LEN]))` and checks it against `sizeof_field(struct nf_conn_help, data)` at line 239. However, the critical bug is at line 236-237: `nla_strlcpy(helper->name, tb[NFCTH_NAME], NF_CT_HELPER_NAME_LEN)` is called BEFORE the `tb[NFCTH_NAME]` attribute is validated for existence. The function checks for `tb[NFCTH_TUPLE]`, `tb[NFCTH_POLICY]`, and `tb[NFCTH_PRIV_DATA_LEN]` at line 224, but does NOT check for `tb[NFCTH_NAME]` being non-NULL before calling nla_strlcpy on it at line 236. If `tb[NFCTH_NAME]` is NULL, nla_strlcpy will dereference a NULL pointer. Additionally, the caller `nfnl_cthelper_new` checks `!tb[NFCTH_NAME]` at line 425, but `nfnl_cthelper_create` is called from within `nfnl_cthelper_new` after that check, passing the same tb[] array. However, a secondary issue: the `nla_strlcpy` at line 236 copies into `helper->name` which is a field inside `struct nf_conntrack_helper`. The bound is `NF_CT_HELPER_NAME_LEN`. If the netlink attribute `NFCTH_NAME` carries a payload larger than `NF_CT_HELPER_NAME_LEN`, nla_strlcpy should be safe (it truncates). BUT: nla_strlcpy uses `nla_len(src)` as the source length for the copy before NUL-termination - if nla_len > dst_size, it copies dst_size-1 bytes correctly. So nla_strlcpy itself is safe here. The REAL vulnerability: at line 238, `size` is a `unsigned int` obtained from user-controlled netlink attribute. The check `size > sizeof_field(struct nf_conn_help, data)` at line 239 correctly bounds it. HOWEVER, the actual exploit primitive here is the ordering: `nfnl_cthelper_parse_expect_policy` (line 232) allocates `helper->expect_policy` - on failure it goes to `err1` which only frees `nfcth`. On success but later failure (line 241 `err2`), it frees `helper->expect_policy`. This is correct. But the key missing check: `tb[NFCTH_NAME]` NULL dereference at line 236 can occur if someone crafts a path where NFCTH_NAME is absent but NFCTH_TUPLE, NFCTH_POLICY, and NFCTH_PRIV_DATA_LEN are present - the check at line 224 does NOT include NFCTH_NAME, so this is a NULL pointer dereference exploitable as kernel crash or potentially with heap spray. Furthermore, in older kernels, `nla_strlcpy` on a NULL nla attribute dereferences `nla_data(NULL)` which is NULL+4 = 0x4, a near-NULL dereference. This is the actual documented missing check (CVE-2021-3609 family). The netlink attribute policy validation for NFCTH_NAME should prevent NULL if min_len > 0 is set in the policy, so we need to check `nfnl_cthelper_policy` to confirm whether NFCTH_NAME has a minimum length policy.

## Impact

None demonstrated; theoretical NULL dereference is blocked by caller-side validation

## Attack Path

```
userspace netlink socket (NETLINK_NETFILTER, NFNL_SUBSYS_CTHELPER) → nfnl_cthelper_new (CAP_NET_ADMIN required) → nfnl_cthelper_create with tb[NFCTH_NAME]=NULL → nla_strlcpy(helper->name, NULL, NF_CT_HELPER_NAME_LEN) → NULL pointer dereference at nla_data(NULL)+offset
```

## Check-Bypass Analysis

1. CAP_NET_ADMIN is checked in nfnl_cthelper_new at line 422, but user namespaces (unprivileged) may allow this in a container with its own network namespace - CAP_NET_ADMIN in a non-initial user namespace grants this capability. 2. The check at line 224 validates tb[NFCTH_TUPLE], tb[NFCTH_POLICY], tb[NFCTH_PRIV_DATA_LEN] but NOT tb[NFCTH_NAME]. A netlink message that includes the three required attributes but omits NFCTH_NAME will pass the line 224 check and proceed to line 236 where nla_strlcpy dereferences tb[NFCTH_NAME] which is NULL. 3. The caller nfnl_cthelper_new does check `!tb[NFCTH_NAME]` - so through that path it's protected. BUT nfnl_cthelper_get (line 615) is also shown as a caller in graph data - if nfnl_cthelper_get can reach nfnl_cthelper_create without checking tb[NFCTH_NAME], there's a bypass. Need to verify the full call chain in nfnl_cthelper_new after line 425 check. 4. The netlink policy array `nfnl_cthelper_policy` might declare NFCTH_NAME with NLA_NUL_STRING type and minimum length, which would cause nla_parse to reject messages without it - this is the key mitigation to verify. If the policy does NOT enforce NFCTH_NAME presence, the missing check at line 224 is exploitable.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** HIGH

nfnl_cthelper_new (the only demonstrated caller of nfnl_cthelper_create) checks !tb[NFCTH_NAME] at line 425 before the call, preventing tb[NFCTH_NAME]==NULL from reaching line 236. No second caller path to nfnl_cthelper_create is present in the provided code. The nla_strlcpy call is safe when called with a valid non-NULL attribute. The size bound check at line 239 is correct. No heap overflow primitive is established. The finding relies on a speculative bypass of both caller-side and netlink-policy-side protections without concrete evidence.

**False-positive reason:** The alleged NULL pointer dereference via tb[NFCTH_NAME] in nfnl_cthelper_create is mitigated by the caller nfnl_cthelper_new, which checks !tb[NFCTH_NAME] at line 425 before invoking nfnl_cthelper_create. No alternative reachable code path to nfnl_cthelper_create that bypasses this check is demonstrated. nfnl_cthelper_get does not call nfnl_cthelper_create. Additionally, netlink policy validation (nfnl_cthelper_policy) would typically reject messages missing a required NLA_NUL_STRING attribute at parse time. The alleged heap overflow is not supported by the code: nla_strlcpy safely truncates, and the size bound check at line 239 correctly limits user-controlled input.

## Remediation

No immediate remediation required given existing caller-side check. Defensive hardening: add tb[NFCTH_NAME] NULL check inside nfnl_cthelper_create itself (defense in depth) in case future callers omit the check.

---
*Graph vulnerability score: 12.87 | Betweenness: 0.0000 | PageRank: 0.000296*
