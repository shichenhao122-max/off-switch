# SPHINCS Register Map

## Profiles

| `SLH_PROFILE` | set | n | h | d | h′ | a | k | len | m | cat | sig B | elements = beats |
|---|---|---|---|---|---|---|---|---|---|---|---:|---|
| **LOW** | SHA2-128s | 16 | 63 | 7 | 9 | 12 | 14 | 35 | 30 | 1 | 7,856 | 491 × 128-b |
| **HIGH** | SHA2-256s | 32 | 64 | 8 | 8 | 14 | 22 | 67 | 47 | 5 | 29,792 | 931 × 256-b |


## 1. The official hash messages 

Verification uses `H_msg`, `F`, `H`, `T_l` (`PRF`/`PRF_msg` are signing-side; no secrets on chip). One shape, two instantiations:

```
            LOW (n=16, §11.2.1)                        HIGH (n=32, §11.2.2)
F    = Trunc16(SHA-256(seed ∥ 0^48 ∥ ADRSc ∥ M1))     Trunc32(SHA-256(seed ∥ 0^32 ∥ ADRSc ∥ M1))
H    = Trunc16(SHA-256(seed ∥ 0^48 ∥ ADRSc ∥ M2))     Trunc32(SHA-512(seed ∥ 0^96 ∥ ADRSc ∥ M2))
T_l  = Trunc16(SHA-256(seed ∥ 0^48 ∥ ADRSc ∥ M_l))    Trunc32(SHA-512(seed ∥ 0^96 ∥ ADRSc ∥ M_l))
H_msg= MGF1-SHA-256(R ∥ seed ∥ SHA-256(R ∥ seed ∥ root ∥ M'), m)   — same with SHA-512 at HIGH
       └── seed prefix pads to one hash block (64 B / 128 B) → precomputable midstate ──┘
```

| call | M | LOW: post-midstate B → blocks | HIGH: post-midstate B → blocks | used in |
|---|---|---|---|---|
| `F` | 1 node (n B) | 38 → **1** SHA-256 blk | 54 → **1** SHA-256 blk (63/64, exact fit) | WOTS chain steps, FORS leaves |
| `H` | left ∥ right (2n B) | 54 → **1** blk (63/64, exact fit) | 86 → **1** SHA-512 blk (103/128) | FORS + XMSS Merkle nodes |
| `T_k` | k FORS roots | 246 → 4 | 726 → 6 | FORS pk (FORS_ROOTS) |
| `T_len` | len WOTS endpoints | 582 → 10 | 2,166 → 18 | WOTS pk = XMSS leaf (WOTS_PK) |

**F and H are single-block in both profiles** — the chain and Merkle FSMs are literally profile-independent.

`H_msg` (once per verification; inner 2 blocks + MGF1 2 blocks in both; m ≤ digest size in both → MGF1 counter hardwired 0):

```
inner  = SHA( R(n) ∥ PK.seed(n) ∥ PK.root(n) ∥ 00 00 ∥ nonce(32) )    LOW 82 B / HIGH 130 B → 2 blocks
outer  = MGF1: SHA( R ∥ PK.seed ∥ inner-digest ∥ ctr=0 )              LOW 68 B / HIGH 132 B → 2 blocks
digest(m B) = md(⌈k·a/8⌉ B: k a-bit FORS digits) ∥ idx_tree(→ mod 2^(h−h′)) ∥ idx_leaf(→ mod 2^h′)
              LOW: 21 B ∥ 7 B→54 b ∥ 2 B→9 b        HIGH: 39 B ∥ 7 B→56 b ∥ 1 B→8 b
```

`00 00` = pure-mode domain byte + |ctx|=0 (Alg 24 line 4), hardwired.

## 2. ADRSc — the 22-byte variable field 

| bytes | field | LOW range | HIGH range | source |
|---|---|---|---|---|
| 0 | layer address | 0…6 | 0…7 | `layer_q` (3 b) |
| 1–8 | tree address | idx_tree, 54 b, ≫9/layer | 56 b, ≫8/layer | idx reg |
| 9 | type | 0 WOTS_HASH · 1 WOTS_PK · 2 TREE · 3 FORS_TREE · 4 FORS_ROOTS | same | const — FSM decode (analog of LMS `D_*` tags) |
| 10–13 | key-pair address | idx_leaf, 9 b | 8 b | idx reg |
| 14–17 | chain addr / tree height | ≤34 / ≤12 | ≤66 / ≤14 | chain ctr (6/7 b) / level ctr (4 b) |
| 18–21 | hash addr / tree index | ≤14 / ≤16 b | ≤14 / ≤19 b | step ctr (4 b) / node-index ctr |

WOTS_PRF/FORS_PRF never occur in verification; all other ADRSc bytes stay zero. `lg_w = 4` in both profiles → hash address 0…14 and the whole digit path are shared.

## 3. Constants — meaning and generation

| constant | meaning | generation | cost |
|---|---|---|---|
| PK.seed (n B) | pk half; domain-separates the hash forest | keygen; per signer like today's `PUBKEYS[]` | 0 — folded into midstate(s) |
| midstate₂₅₆ = SHA-256-state(seed ∥ 0^(64−n)) | constant first block of every F (and of H/T_l at LOW) | offline tool → localparam; loaded via `digest_i`/ctx | 0 (ROM, 256 b/signer) |
| midstate₅₁₂ = SHA-512-state(seed ∥ 0^(128−n)) | constant first block of H/T_l/… — **HIGH only** | same | 0 (ROM, 512 b/signer) |
| PK.root (n B) | hypertree root; H_msg input + final compare | keygen → `PUBKEYS[]`-style parameter | 0 (ROM) |
| type byte 0–4 | ADRS domain separation | FSM-state decode | 0 (mux) |
| `00 00` M′ prefix | pure mode, empty ctx | hardwired | 0 |
| MGF1 counter | always 0 (m ≤ digest bytes, both profiles) | hardwired | 0 |
| SHA padding | 0x80 + zeros + length (64-b field for SHA-256, 128-b for SHA-512); all message lengths fixed per profile | elaboration-time, like `calc_sha_blocks/pad_zeros` today | 0 |

## 4. Unified register file — widths as parameter formulas

| register | role | width | LOW | HIGH | vs today's LMS engine |
|---|---|---|---:|---:|---|
| `node` | current node / chain tmp / F input | 8n | 128 | 256 | = `hash_reg` role, n-scaled |
| sibling / R | auth-path sibling; R during H_msg — **no register**: consumed off the stream, ready deferred to the consuming hash's completion (producer's stage register is the storage) | — | 0 | 0 | `aux_reg`'s sibling role deleted per review |
| `md_reg` | k FORS digits; recycled: WOTS message per HT layer (8n ≤ width in both) | 8⌈k·a/8⌉ | 168 | 312 | **new** — md must persist across the whole FORS phase while node churns every hash |
| `idx` | idx_tree ∥ idx_leaf, digest split → end | h | 63 | 64 | `leaf_index_q` widened |
| `kc_state` | suspended T_l hash state; parks H_msg inner digest | digest state | 256 | 512 | widened at HIGH only |
| `bank` | T_l pending elements + carry (3 elements + (8n−80)-b carry; block/element ratio = 4 in both) | 3·8n + 8n−80 | 432 | 944 | = `kc_lo`+`kc_hi` geometry, n-scaled |
| counters + FSM | chain (6/7), step 4, level 4, node-index (16/19), layer 3, blk_idx 5, states ≈10 | — | ≈57 | ≈62 | ≈ today |
| **engine total** | | | **≈1,104** | **≈2,148** | today: 1,555 (`cur_I`/`prev_I` −256 and the sibling register −8n both deleted) |
| hash core | Pavona `prim_sha2` | `MultimodeEn = (PROFILE==HIGH)` | ≈1 K (today's config) | ≈2 K | |

The LOW profile lands *below* today's LMS engine because registers size to 8n instead of inheriting fixed 256-bit LMS registers. WOTS csum is combinational in both (adder tree over len1 nibbles: ≤480 → 9 b LOW, ≤960 → 10 b HIGH; the 3 csum digits are the nibbles of the 12-bit value).

## 5. Register occupancy per step (structure identical in both profiles)

Signature stream order (R → FORS → HT) equals consumption order exactly (Alg 8/17/20). `LICENSE_BEAT_W = 8n` → one element per beat in both profiles.

| step | node | stream beat (no reg — held by producer until ready) | md_reg | kc_state / bank | counters |
|---|---|---|---|---|---|
| H_msg inner (2 blk) | — | R on the bus (block 0 reads it) | — | inner digest → kc_state | blk_idx |
| H_msg MGF1 (2 blk) | — | R on the bus; ready pulses at completion | — | kc_state read | blk_idx |
| digest split | — | — | ← md | free | idx ← h bits |
| FORS tree i: F + a×H | node | sk beat → node load; each auth beat held through its H, ready at hash end | md | T_k state / ≤3 roots + carry | chain=i, level, node-index |
| T_k close | → PK_FORS | — | md (done) | drains | — |
| layer j: len chains | chain tmp | sig beat → node load | message (PK_FORS / prev root) | T_len state / ≤3 endpoints + carry | chain, step, layer=j |
| T_len close | → XMSS leaf | — | message (done) | drains | — |
| XMSS Merkle h′×H | node | each auth beat held through its H, ready at hash end | free | idle | level, node-index |
| layer boundary | root | — | ← root (next message) | idle | idx_leaf←idx_tree mod 2^h′; idx_tree≫h′; layer++ |
| after layer d−1 | root | — | — | — | compare vs PK.root ROM |



