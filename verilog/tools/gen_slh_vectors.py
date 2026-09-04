#!/usr/bin/env python3
"""Generate SLH-DSA-SHA2-128s test vectors for the off-switch RTL testbench.

Uses slh_ref.py (FIPS 205 reference model).  Per-signer keys are derived
deterministically:  SK.seed / SK.prf / PK.seed for signer i are
SHA-256("off-switch-slh-signer-<i>-<field>")[0:16] with field in
{sk_seed, sk_prf, pk_seed}.

Signer 0 signs the 32-byte message nonce in pure mode with an empty context
(deterministic variant), i.e. M' = 0x00 0x00 || message, and the signature is
verified back before anything is written.

Outputs (relative to --out-dir unless noted):
  license_beats.hex   491 lines, one 128-bit beat per line: beat i is
                      signature bytes [16i .. 16i+15] in signature byte
                      order, byte 16i in bits [127:120] (MSB-first).
  meta.json           summary (message, signer, pk, expected result, sizes).
  intermediates.json  debugging oracle dumped from the instrumented verify
                      path (H_msg digest, md, idx_tree/idx_leaf, FORS leaves/
                      roots, PK_FORS, per-layer WOTS chain ends, XMSS leaf =
                      T_len of the chain ends, and XMSS root).
  slh_keys.svh        (in --keys-svh, default verilog/rtl/) SystemVerilog
                      include with per-signer {PK.seed, PK.root, SHA-256
                      midstate of PK.seed || toByte(0,48)}.
"""

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import slh_ref as S  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_OUT_DIR = os.path.join(REPO, "verilog", "tb", "vectors", "slh128s")
DEFAULT_KEYS_SVH = os.path.join(REPO, "verilog", "rtl", "slh_keys.svh")
DEFAULT_MESSAGE = bytes(range(32)).hex()
BEAT_BYTES = 16


def signer_keys(i):
    """Deterministic seeds for signer i."""
    def field(name):
        tag = "off-switch-slh-signer-%d-%s" % (i, name)
        return hashlib.sha256(tag.encode()).digest()[:S.n]
    return field("sk_seed"), field("sk_prf"), field("pk_seed")


def hexlist(items):
    return [b.hex() for b in items]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out-dir", default=DEFAULT_OUT_DIR,
                    help="output directory (default: %(default)s)")
    ap.add_argument("--message", default=DEFAULT_MESSAGE,
                    help="32-byte message nonce as 64 hex chars")
    ap.add_argument("--num-signers", type=int, default=2,
                    help="number of signer keys to generate (default 2)")
    ap.add_argument("--signer", type=int, default=0,
                    help="index of the signer that signs (default 0)")
    ap.add_argument("--ctx", default="",
                    help="context string as hex (default empty)")
    ap.add_argument("--keys-svh", default=DEFAULT_KEYS_SVH,
                    help="path of generated SystemVerilog include "
                         "(default: %(default)s)")
    args = ap.parse_args()

    message = bytes.fromhex(args.message)
    if len(message) != 32:
        ap.error("--message must be exactly 64 hex chars (32 bytes)")
    ctx = bytes.fromhex(args.ctx)
    if ctx:
        print("WARNING: non-empty --ctx produces vectors the RTL cannot "
              "verify (the engine hardwires M' = 00 00 || message)")
    if not (0 <= args.signer < args.num_signers):
        ap.error("--signer out of range")

    os.makedirs(args.out_dir, exist_ok=True)

    # ---- deterministic keygen for every signer -------------------------
    keys = []
    for i in range(args.num_signers):
        sk_seed, sk_prf, pk_seed = signer_keys(i)
        SK, PK = S.slh_keygen_internal(sk_seed, sk_prf, pk_seed)
        keys.append((SK, PK))
        print("signer %d: PK.seed=%s PK.root=%s"
              % (i, PK[0].hex(), PK[1].hex()))

    # ---- sign (pure mode, deterministic) and verify back ---------------
    SK, PK = keys[args.signer]
    sig = S.slh_sign(message, ctx, SK)          # deterministic variant
    assert len(sig) == S.SIG_BYTES, len(sig)
    ok = S.slh_verify(message, sig, ctx, PK)
    if not ok:
        print("FATAL: self-verification of generated signature failed")
        return 1
    print("signature: %d bytes, verifies OK" % len(sig))

    # ---- instrumented re-verification for the debugging oracle ---------
    Mp = S.toByte(0, 1) + S.toByte(len(ctx), 1) + ctx + message
    trace = {}
    assert S.slh_verify_internal(Mp, sig, PK, trace=trace)

    # ---- license_beats.hex ---------------------------------------------
    n_beats = S.SIG_BYTES // BEAT_BYTES         # 491
    beats_path = os.path.join(args.out_dir, "license_beats.hex")
    with open(beats_path, "w") as f:
        for i in range(n_beats):
            f.write(sig[i * BEAT_BYTES:(i + 1) * BEAT_BYTES].hex() + "\n")

    # ---- meta.json ------------------------------------------------------
    meta = {
        "parameter_set": "SLH-DSA-SHA2-128s",
        "message": message.hex(),
        "ctx": ctx.hex(),
        "signer_index": args.signer,
        "num_signers": args.num_signers,
        "pk_seed": PK[0].hex(),
        "pk_root": PK[1].hex(),
        "expected_result": True,
        "sig_bytes": len(sig),
        "beat_bytes": BEAT_BYTES,
        "beat_count": n_beats,
    }
    meta_path = os.path.join(args.out_dir, "meta.json")
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")

    # ---- message.hex (consumed by the testbenches via $readmemh) --------
    msg_path = os.path.join(args.out_dir, "message.hex")
    with open(msg_path, "w") as f:
        f.write(message.hex() + "\n")

    # ---- intermediates.json ---------------------------------------------
    inter = {
        "h_msg_digest": trace["digest"].hex(),
        "md": trace["md"].hex(),
        "idx_tree": trace["idx_tree"],
        "idx_leaf": trace["idx_leaf"],
        "fors_indices": trace["fors"]["indices"],
        "fors_leaves": hexlist(trace["fors"]["fors_leaves"]),
        "fors_roots": hexlist(trace["fors"]["fors_roots"]),
        "pk_fors": trace["fors"]["pk_fors"].hex(),
        "ht_layers": [
            {
                "layer": j,
                "wots_chain_ends": hexlist(lt["wots_chain_ends"]),
                "xmss_leaf": lt["wots_pk"].hex(),
                "xmss_root": lt["xmss_root"].hex(),
            }
            for j, lt in enumerate(trace["ht"])
        ],
    }
    inter_path = os.path.join(args.out_dir, "intermediates.json")
    with open(inter_path, "w") as f:
        json.dump(inter, f, indent=2)
        f.write("\n")

    # sanity: top-layer XMSS root must equal PK.root
    assert inter["ht_layers"][-1]["xmss_root"] == PK[1].hex()

    # ---- slh_keys.svh ----------------------------------------------------
    lines = []
    lines.append("// Generated by gen_slh_vectors.py -- do not edit.")
    lines.append("localparam int unsigned SLH_NUM_KEYS = %d;" % args.num_signers)
    lines.append("localparam slh_key_t SLH_KEYS [SLH_NUM_KEYS] = '{")
    for i, (_, PKi) in enumerate(keys):
        mid = S.sha256_midstate(PKi[0])
        mid_hex = "".join("%08x" % w for w in mid)
        sep = "," if i < len(keys) - 1 else ""
        lines.append("    '{seed: 128'h%s, root: 128'h%s, midstate: 256'h%s}%s"
                     % (PKi[0].hex(), PKi[1].hex(), mid_hex, sep))
    lines.append("};")
    with open(args.keys_svh, "w") as f:
        f.write("\n".join(lines) + "\n")

    print("wrote %s (%d beats)" % (beats_path, n_beats))
    print("wrote %s" % meta_path)
    print("wrote %s" % msg_path)
    print("wrote %s" % inter_path)
    print("wrote %s (%d keys)" % (args.keys_svh, args.num_signers))
    return 0


if __name__ == "__main__":
    sys.exit(main())
