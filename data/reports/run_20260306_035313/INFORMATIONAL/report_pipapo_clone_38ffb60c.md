# [INFORMATIONAL] Parse Error in pipapo_clone (unknown)

**Generated:** 2026-03-06T04:18:12.208756+00:00  
**Report ID:** `pipapo_clone_38ffb60c`

## Location

| Field | Value |
|---|---|
| File | `net/netfilter/nft_set_pipapo.c` |
| Function | `pipapo_clone` |
| Line | 1270 |
| Subsystem | net |

## Source Code

```c
 1270 | static struct nft_pipapo_match *pipapo_clone(struct nft_pipapo_match *old)
 1271 | {
 1272 | 	struct nft_pipapo_field *dst, *src;
 1273 | 	struct nft_pipapo_match *new;
 1274 | 	int i;
 1275 | 
 1276 | 	new = kmalloc(sizeof(*new) + sizeof(*dst) * old->field_count,
 1277 | 		      GFP_KERNEL);
 1278 | 	if (!new)
 1279 | 		return ERR_PTR(-ENOMEM);
 1280 | 
 1281 | 	new->field_count = old->field_count;
 1282 | 	new->bsize_max = old->bsize_max;
 1283 | 
 1284 | 	new->scratch = alloc_percpu(*new->scratch);
 1285 | 	if (!new->scratch)
 1286 | 		goto out_scratch;
 1287 | 
 1288 | #ifdef NFT_PIPAPO_ALIGN
 1289 | 	new->scratch_aligned = alloc_percpu(*new->scratch_aligned);
 1290 | 	if (!new->scratch_aligned)
 1291 | 		goto out_scratch;
 1292 | #endif
 1293 | 
 1294 | 	rcu_head_init(&new->rcu);
 1295 | 
 1296 | 	src = old->f;
 1297 | 	dst = new->f;
 1298 | 
 1299 | 	for (i = 0; i < old->field_count; i++) {
 1300 | 		unsigned long *new_lt;
 1301 | 
 1302 | 		memcpy(dst, src, offsetof(struct nft_pipapo_field, lt));
 1303 | 
 1304 | 		new_lt = kvzalloc(src->groups * NFT_PIPAPO_BUCKETS(src->bb) *
 1305 | 				  src->bsize * sizeof(*dst->lt) +
 1306 | 				  NFT_PIPAPO_ALIGN_HEADROOM,
 1307 | 				  GFP_KERNEL);
 1308 | 		if (!new_lt)
 1309 | 			goto out_lt;
 1310 | 
 1311 | 		NFT_PIPAPO_LT_ASSIGN(dst, new_lt);
 1312 | 
 1313 | 		memcpy(NFT_PIPAPO_LT_ALIGN(new_lt),
 1314 | 		       NFT_PIPAPO_LT_ALIGN(src->lt),
 1315 | 		       src->bsize * sizeof(*dst->lt) *
 1316 | 		       src->groups * NFT_PIPAPO_BUCKETS(src->bb));
 1317 | 
 1318 | 		dst->mt = kvmalloc(src->rules * sizeof(*src->mt), GFP_KERNEL);
 1319 | 		if (!dst->mt)
 1320 | 			goto out_mt;
 1321 | 
 1322 | 		memcpy(dst->mt, src->mt, src->rules * sizeof(*src->mt));
 1323 | 		src++;
 1324 | 		dst++;
 1325 | 	}
 1326 | 
 1327 | 	return new;
 1328 | 
 1329 | out_mt:
 1330 | 	kvfree(dst->lt);
 1331 | out_lt:
 1332 | 	for (dst--; i > 0; i--) {
 1333 | 		kvfree(dst->mt);
 1334 | 		kvfree(dst->lt);
 1335 | 		dst--;
 1336 | 	}
 1337 | #ifdef NFT_PIPAPO_ALIGN
 1338 | 	free_percpu(new->scratch_aligned);
 1339 | #endif
 1340 | out_scratch:
 1341 | 	free_percpu(new->scratch);
 1342 | 	kfree(new);
 1343 | 
 1344 | 	return ERR_PTR(-ENOMEM);
 1345 | }
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
    "vulnerability_type": "heap_buffer_overflow + use_after_free (error path)",
    "description": "Two distinct vulnerabilities exist in pipapo_clone():\n\n**Vulnerability 1: Integer Overflow in Size Calculation (P2 - Heap Buffer Overflow)**\nAt line 1304-1306, the allocation size is computed as:\n  `src->groups * NFT_PIPAPO_BUCKETS(src->bb) * src->bsize * sizeof(*dst->lt) + NFT_PIPAPO_ALIGN_HEADROOM`\n\nAll three multiplied operands (grou

## Verification

**Status:** ✗ NOT CONFIRMED  
**Verifier Confidence:** LOW

Skipped verification (primary agent: not vulnerable)

**False-positive reason:** Primary agent did not flag as vulnerable

---
*Graph vulnerability score: 12.73 | Betweenness: 0.0000 | PageRank: 0.000214*
