# hbsv_verify — one engine for HSS-LMS and SLH-DSA

`hbsv_verify` replaces `hss_verify` and `slh_verify`: one control structure,
selected by the `SCH` parameter at elaboration, with every scheme-specific
byte layout supplied by packages. `security_block` instantiates it with
`SCHEME_LMS` for `CRYPTO_TYPE=1` and `SCHEME_SLH` for `CRYPTO_TYPE=2`.

## Package layering

| package | holds |
|---|---|
| `hbsv_ctrl_pkg` | `sch_e`; `ctrl_t`, the counter bundle both schemes drive (layer, chain, step, level, node index, leaf index, tree address), sized to the wider scheme |
| `hss_pkg` | LMS parameters and keys, plus the LMS hash-message structs in RFC 8554 field order (`lms_q_msg_t`, `lms_chain_msg_t`, `lms_intr_msg_t`, …) |
| `slh_pkg` | SLH parameters and keys, plus `slh_adrs_c_t` and the SLH message structs (`slh_f_msg_t`, `slh_tree_msg_t`, `slh_hmsg_msg_t`, `slh_mgf_msg_t`) |
| `hbsv_schs_pkg` | constant functions of `SCH`: scheme parameters, message widths, accumulator geometry, `ctrl2q` / `ctrl2adrs`, and the message builders (`ots_chain_msg`, `ots_tree_join_msg`, `ots_pk_prefix`, `msg_hash_msg`, …) that turn `ctrl_t` plus the live data into each scheme's layout |

Builders return their maximum width with the struct right-aligned; the
module narrows with a width cast and pads at elaboration with the shared
`calc_sha_blocks` / `calc_sha_pad_zeros`, exactly the old `hss_verify` idiom
with the width now a function of the scheme.

## What is shared and what is not

| stage | control | LMS data | SLH data |
|---|---|---|---|
| OTS chain walk | shared | 8-bit digits, ≤254 steps, `I‖q‖u16(i)‖u8(j)‖tmp` | 4-bit digits, ≤14 steps, `midstate ⧺ ADRSc‖tmp` |
| endpoint accumulation (Kc / T_k, T_len) | shared | 2 × 256-bit slots, 176-bit carry | 4 × 128-bit slots, 48-bit carry |
| Merkle walk | shared | `I‖u32(node)‖D_INTR‖L‖R`, 2 blocks | `midstate ⧺ ADRSc‖L‖R`, 1 block |
| per-layer schedule | scheme-only states | header beat → Q → chains → Kc → leaf hash → Merkle | (H_msg → FORS once) → chains → T_len → Merkle |

The accumulator is one formula because both schemes prefix their element
stream with 22 bytes (`I‖q‖D_PBLC` = 16+4+2, ADRSc = 22): with E-byte
elements a 512-bit block boundary always falls 10 bytes into an element, so
each absorbed block ends with an 80-bit head and leaves an (8E−80)-bit carry;
the first block carries the prefix and ⌊(64−22)/E⌋ elements, later blocks the
carry and 64/E − 1. Elements banked after the last absorb (0 for LMS Kc and
SLH T_len, 3 for SLH T_k) are elaboration constants, so the final padding
block is a constant layout.

Beats read straight into a hash block — the randomizer and every auth-path
sibling — are held by the licence producer and released in the cycle the
core captures the last block that reads them (`sha2_wrap.taken`); beats
latched into a register are taken at once.

## Results

| check | result |
|---|---|
| `tb_hss` (LMS unit) | valid, 514,602 cycles (514,652 with `hss_verify`: the sibling-load and endpoint-banking states no longer cost a cycle) |
| `tb_slh_verify` | 10/10, 147,563 cycles (unchanged) |
| `tb_slh_b2b` / `tb_top_slh` | 4/4 / 9/9 |
| `tb_top_hss` / `tb_top_ecdsa` | 20/20 / 16/16 |
| lint | verilator `-Wall` CRYPTO_TYPE 0/1/2 and verible clean |
| Nangate45 @ 10 ns, CRYPTO_TYPE=1 | 19,129 cells · 3,195 FF · 36,542 µm² (`hss_verify`: 20,200 · 3,377 · 38,615) |
| Nangate45 @ 10 ns, CRYPTO_TYPE=2 | 16,234 cells · 2,737 FF · 31,005 µm² (`slh_verify`: 15,978 · 2,734 · 30,620) |

The LMS build shrinks by 5%; the SLH build pays about 1% for the shared
structure. The SHA2-256s profile is a parameter lift of the same module
(`digest_w`, the SHA-512 mode per call, a second midstate entry).
