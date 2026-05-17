# [INFORMATIONAL] Use After Free in nft_add_set_elem (CWE-416)

**Generated:** 2026-03-06T03:53:44.393463+00:00  
**Report ID:** `nft_add_set_elem_e4093123`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nf_tables_api.c` |
| Function | `nft_add_set_elem` |
| Line | 5146 |
| Subsystem | net |

## Source Code

```c
 5146 | static int nft_add_set_elem(struct nft_ctx *ctx, struct nft_set *set,
 5147 | 			    const struct nlattr *attr, u32 nlmsg_flags)
 5148 | {
 5149 | 	struct nlattr *nla[NFTA_SET_ELEM_MAX + 1];
 5150 | 	u8 genmask = nft_genmask_next(ctx->net);
 5151 | 	struct nft_set_ext_tmpl tmpl;
 5152 | 	struct nft_set_ext *ext, *ext2;
 5153 | 	struct nft_set_elem elem;
 5154 | 	struct nft_set_binding *binding;
 5155 | 	struct nft_object *obj = NULL;
 5156 | 	struct nft_expr *expr = NULL;
 5157 | 	struct nft_userdata *udata;
 5158 | 	struct nft_data_desc desc;
 5159 | 	enum nft_registers dreg;
 5160 | 	struct nft_trans *trans;
 5161 | 	u32 flags = 0;
 5162 | 	u64 timeout;
 5163 | 	u64 expiration;
 5164 | 	u8 ulen;
 5165 | 	int err;
 5166 | 
 5167 | 	err = nla_parse_nested_deprecated(nla, NFTA_SET_ELEM_MAX, attr,
 5168 | 					  nft_set_elem_policy, NULL);
 5169 | 	if (err < 0)
 5170 | 		return err;
 5171 | 
 5172 | 	if (nla[NFTA_SET_ELEM_KEY] == NULL)
 5173 | 		return -EINVAL;
 5174 | 
 5175 | 	nft_set_ext_prepare(&tmpl);
 5176 | 
 5177 | 	err = nft_setelem_parse_flags(set, nla[NFTA_SET_ELEM_FLAGS], &flags);
 5178 | 	if (err < 0)
 5179 | 		return err;
 5180 | 	if (flags != 0)
 5181 | 		nft_set_ext_add(&tmpl, NFT_SET_EXT_FLAGS);
 5182 | 
 5183 | 	if (set->flags & NFT_SET_MAP) {
 5184 | 		if (nla[NFTA_SET_ELEM_DATA] == NULL &&
 5185 | 		    !(flags & NFT_SET_ELEM_INTERVAL_END))
 5186 | 			return -EINVAL;
 5187 | 	} else {
 5188 | 		if (nla[NFTA_SET_ELEM_DATA] != NULL)
 5189 | 			return -EINVAL;
 5190 | 	}
 5191 | 
 5192 | 	if ((flags & NFT_SET_ELEM_INTERVAL_END) &&
 5193 | 	     (nla[NFTA_SET_ELEM_DATA] ||
 5194 | 	      nla[NFTA_SET_ELEM_OBJREF] ||
 5195 | 	      nla[NFTA_SET_ELEM_TIMEOUT] ||
 5196 | 	      nla[NFTA_SET_ELEM_EXPIRATION] ||
 5197 | 	      nla[NFTA_SET_ELEM_USERDATA] ||
 5198 | 	      nla[NFTA_SET_ELEM_EXPR]))
 5199 | 		return -EINVAL;
 5200 | 
 5201 | 	timeout = 0;
 5202 | 	if (nla[NFTA_SET_ELEM_TIMEOUT] != NULL) {
 5203 | 		if (!(set->flags & NFT_SET_TIMEOUT))
 5204 | 			return -EINVAL;
 5205 | 		err = nf_msecs_to_jiffies64(nla[NFTA_SET_ELEM_TIMEOUT],
 5206 | 					    &timeout);
 5207 | 		if (err)
 5208 | 			return err;
 5209 | 	} else if (set->flags & NFT_SET_TIMEOUT) {
 5210 | 		timeout = set->timeout;
 5211 | 	}
 5212 | 
 5213 | 	expiration = 0;
 5214 | 	if (nla[NFTA_SET_ELEM_EXPIRATION] != NULL) {
 5215 | 		if (!(set->flags & NFT_SET_TIMEOUT))
 5216 | 			return -EINVAL;
 5217 | 		err = nf_msecs_to_jiffies64(nla[NFTA_SET_ELEM_EXPIRATION],
 5218 | 					    &expiration);
 5219 | 		if (err)
 5220 | 			return err;
 5221 | 	}
 5222 | 
 5223 | 	if (nla[NFTA_SET_ELEM_EXPR] != NULL) {
 5224 | 		expr = nft_set_elem_expr_alloc(ctx, set,
 5225 | 					       nla[NFTA_SET_ELEM_EXPR]);
 5226 | 		if (IS_ERR(expr))
 5227 | 			return PTR_ERR(expr);
 5228 | 
 5229 | 		err = -EOPNOTSUPP;
 5230 | 		if (set->expr && set->expr->ops != expr->ops)
 5231 | 			goto err_set_elem_expr;
 5232 | 	} else if (set->expr) {
 5233 | 		expr = kzalloc(set->expr->ops->size, GFP_KERNEL);
 5234 | 		if (!expr)
 5235 | 			return -ENOMEM;
 5236 | 
 5237 | 		err = nft_expr_clone(expr, set->expr);
 5238 | 		if (err < 0)
 5239 | 			goto err_set_elem_expr;
 5240 | 	}
 5241 | 
 5242 | 	err = nft_setelem_parse_key(ctx, set, &elem.key.val,
 5243 | 				    nla[NFTA_SET_ELEM_KEY]);
 5244 | 	if (err < 0)
 5245 | 		goto err_set_elem_expr;
 5246 |     // ... truncated ...
 5247 | 			if ((nft_set_ext_exists(ext, NFT_SET_EXT_DATA) &&
 5248 | 			     nft_set_ext_exists(ext2, NFT_SET_EXT_DATA) &&
 5249 | 			     memcmp(nft_set_ext_data(ext),
 5250 | 				    nft_set_ext_data(ext2), set->dlen) != 0) ||
 5251 | 			    (nft_set_ext_exists(ext, NFT_SET_EXT_OBJREF) &&
 5252 | 			     nft_set_ext_exists(ext2, NFT_SET_EXT_OBJREF) &&
 5253 | 			     *nft_set_ext_obj(ext) != *nft_set_ext_obj(ext2)))
 5254 | 				goto err_element_clash;
 5255 | 			else if (!(nlmsg_flags & NLM_F_EXCL))
 5256 | 				err = 0;
 5257 | 		} else if (err == -ENOTEMPTY) {
 5258 | 			/* ENOTEMPTY reports overlapping between this element
 5259 | 			 * and an existing one.
 5260 | 			 */
 5261 | 			err = -EEXIST;
 5262 | 		}
 5263 | 		goto err_element_clash;
 5264 | 	}
 5265 | 
 5266 | 	if (set->size &&
 5267 | 	    !atomic_add_unless(&set->nelems, 1, set->size + set->ndeact)) {
 5268 | 		err = -ENFILE;
 5269 | 		goto err_set_full;
 5270 | 	}
 5271 | 
 5272 | 	nft_trans_elem(trans) = elem;
 5273 | 	list_add_tail(&trans->list, &ctx->net->nft.commit_list);
 5274 | 	return 0;
 5275 | 
 5276 | err_set_full:
 5277 | 	set->ops->remove(ctx->net, set, &elem);
 5278 | err_element_clash:
 5279 | 	kfree(trans);
 5280 | err_trans:
 5281 | 	if (obj)
 5282 | 		obj->use--;
 5283 | 
 5284 | 	nf_tables_set_elem_destroy(ctx, set, elem.priv);
 5285 | err_parse_data:
 5286 | 	if (nla[NFTA_SET_ELEM_DATA] != NULL)
 5287 | 		nft_data_release(&elem.data.val, desc.type);
 5288 | err_parse_key_end:
 5289 | 	nft_data_release(&elem.key_end.val, NFT_DATA_VALUE);
 5290 | err_parse_key:
 5291 | 	nft_data_release(&elem.key.val, NFT_DATA_VALUE);
 5292 | err_set_elem_expr:
 5293 | 	if (expr != NULL)
 5294 | 		nft_expr_destroy(ctx, expr);
 5295 | 
 5296 | 	return err;
 5297 | }
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
| Exploitability | LOW |

## Description

nft_add_set_elem contains a use-after-free vulnerability in the error-handling path. Specifically, at line 5284, `nf_tables_set_elem_destroy(ctx, set, elem.priv)` is called unconditionally on the `err_trans` label. However, when execution reaches `err_set_full` (line 5276-5277), `set->ops->remove(ctx->net, set, &elem)` is called first to remove the element from the set backend, then falls through to `err_element_clash` which calls `kfree(trans)`, then falls through to `err_trans` which calls `nf_tables_set_elem_destroy(ctx, set, elem.priv)`. This means `elem.priv` (which was already removed from the set backend by `ops->remove`) is then destroyed again via `nf_tables_set_elem_destroy`, constituting a double-free / UAF on `elem.priv`.

Additionally, there is a critical missing `obj->use--` decrement path: when `err_set_full` is reached (after obj was incremented), execution falls through `err_element_clash -> err_trans`, where `obj->use--` IS present. However, the `err_element_clash` label (line 5278) skips `set->ops->remove`, meaning if we reach `err_element_clash` directly (e.g., from the element clash comparison block at line 5254 or 5263), the element was already inserted into the backend by `ops->insert` but `ops->remove` is NOT called — only `kfree(trans)` and `nf_tables_set_elem_destroy` are called. This means the set backend retains a pointer to memory that has been freed by `nf_tables_set_elem_destroy`, creating a classic UAF when the set is later walked/committed.

Secondly, in the truncated section (around line 5246), after `nft_setelem_parse_key` succeeds, if `set->ops->insert` succeeds and then we get a clash (err == -EEXIST from the backend), the code path at line 5254 `goto err_element_clash` bypasses `set->ops->remove`, leaving the element in the backend while `nf_tables_set_elem_destroy` frees `elem.priv`. Any subsequent access to that set element (during commit, GC, or lookup) will dereference freed memory.

A third issue: the `obj->use--` decrement at line 5282 is only protected by `if (obj)`, but there is no corresponding `nft_use_inc_restore` or proper reference counting rollback that pairs with the increment done in the (truncated) obj lookup path. If the obj refcount is decremented without proper synchronization, concurrent transactions can observe inconsistent refcounts.

## Impact

No confirmed exploitable UAF. The error handling paths in the visible code are consistent with correct resource cleanup semantics for nft set backends.

## Attack Path

```
userspace netlink socket → nfnetlink_rcv_msg → nf_tables_newsetelem → nft_add_set_elem → [ops->insert succeeds, clash detected] → goto err_element_clash → kfree(trans) → obj->use-- → nf_tables_set_elem_destroy(elem.priv) → [backend still holds stale elem.priv pointer] → UAF on subsequent commit/GC/lookup of the set element
```

## Check-Bypass Analysis

1. The caller `nf_tables_newsetelem` does call `nft_ctx_init_from_elemattr` and checks table/set lookup, but no locking prevents concurrent set modification between `ops->insert` and `ops->remove` in the error path. 2. The NFT_SET_ELEM_INTERVAL_END flag bypass: setting this flag causes `nla[NFTA_SET_ELEM_DATA]`, `OBJREF`, `TIMEOUT`, `EXPIRATION`, `USERDATA`, `EXPR` to all be rejected (line 5192-5199), but the key is still parsed and inserted — this narrows the attack surface but doesn't prevent the elem.priv UAF. 3. CAP_NET_ADMIN is required to reach this code (via nfnetlink), but network namespaces (user namespaces with CAP_NET_ADMIN in a child netns) make this reachable from unprivileged containers — a well-known Linux privilege escalation vector in container environments. 4. The NLM_F_EXCL flag at line 5255 affects whether err is cleared on clash, but both paths (clash and non-clash) reach `err_element_clash` without calling `ops->remove`, leaving the backend pointer dangling.

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** MEDIUM

Code truncation at line 5246 prevents complete verification. However: (1) err_set_full calls ops->remove then destroy — correct. (2) err_element_clash is reached when ops->insert returns -EEXIST, meaning the element was not retained by the backend, so destroy-without-remove is correct. (3) The obj->use-- at line 5282 is guarded by 'if (obj)' which is sufficient for the NULL-initialized obj pointer. The primary agent's scenario requires set backends to retain elem.priv on clash returns, which contradicts standard nft backend behavior. CAP_NET_ADMIN is required regardless.

**False-positive reason:** The primary agent's UAF claims rest on incorrect analysis of the error paths. (1) The err_set_full path correctly calls ops->remove before falling through to nf_tables_set_elem_destroy — no double-free. (2) For the err_element_clash path after ops->insert returns -EEXIST (clash): when a set backend reports -EEXIST, the new element was NOT inserted into the backend data structure; the existing conflicting element remains. Therefore elem.priv is not referenced by the backend, and calling nf_tables_set_elem_destroy on it is not a UAF — it is the correct cleanup of an element that was never committed to the backend. The truncated code (line 5246) prevents full verification, but the visible logic is consistent with correct error handling. The claimed 'backend still holds stale elem.priv pointer' after a clash return is unsupported — standard nft set backends (rbtree, hash, bitmap) do not retain the new element pointer on -EEXIST returns.

## Remediation

No remediation required based on current evidence. If future analysis with complete source confirms backend retains element pointer on -EEXIST in specific backends, add ops->remove call before err_element_clash label.

---
*Graph vulnerability score: 14.87 | Betweenness: 0.0000 | PageRank: 0.001251*
