#!/usr/bin/env python3
"""Cross-validate slh_ref.py against official NIST ACVP-Server test vectors.

Expects the internalProjection.json files from
  usnistgov/ACVP-Server: gen-val/json-files/SLH-DSA-sigVer-FIPS205/
  usnistgov/ACVP-Server: gen-val/json-files/SLH-DSA-keyGen-FIPS205/
downloaded into the acvp/ directory next to this script (they are gitignored):
  acvp/sigVer_internalProjection.json
  acvp/keyGen_internalProjection.json

Only the SLH-DSA-SHA2-128s parameter set is checked (that is the only set
slh_ref implements).  Every sigVer case must reproduce the vector's expected
testPassed verdict; every keyGen case must reproduce the expected SK and PK.
Exit status is nonzero on any mismatch.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import slh_ref as S  # noqa: E402

PARAM_SET = "SLH-DSA-SHA2-128s"
ACVP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "acvp")


def load(name):
    path = os.path.join(ACVP_DIR, name)
    if not os.path.exists(path):
        print("MISSING: %s (download it first) -- skipping" % path)
        return None
    with open(path) as f:
        return json.load(f)


def check_sigver(doc):
    run = passed = failed = skipped = 0
    for g in doc["testGroups"]:
        if g.get("parameterSet") != PARAM_SET:
            continue
        iface = g.get("signatureInterface")
        prehash = g.get("preHash")
        g_run = g_pass = 0
        for t in g["tests"]:
            msg = bytes.fromhex(t["message"])
            sig = bytes.fromhex(t["signature"])
            pk_raw = bytes.fromhex(t["pk"])
            pk = (pk_raw[:S.n], pk_raw[S.n:])
            expected = bool(t["testPassed"])
            if iface == "internal":
                got = S.slh_verify_internal(msg, sig, pk)
            elif prehash == "pure":
                ctx = bytes.fromhex(t.get("context", "") or "")
                got = S.slh_verify(msg, sig, ctx, pk)
            elif prehash == "preHash":
                ctx = bytes.fromhex(t.get("context", "") or "")
                alg = t.get("hashAlg")
                if alg not in S._PREHASH:
                    print("SKIP tgId=%s tcId=%s: unsupported hashAlg %s"
                          % (g["tgId"], t["tcId"], alg))
                    skipped += 1
                    continue
                got = S.hash_slh_verify(msg, sig, ctx, alg, pk)
            else:
                print("SKIP tgId=%s tcId=%s: unhandled group kind %s/%s"
                      % (g["tgId"], t["tcId"], iface, prehash))
                skipped += 1
                continue
            run += 1
            g_run += 1
            if got == expected:
                passed += 1
                g_pass += 1
            else:
                failed += 1
                print("MISMATCH sigVer tgId=%s tcId=%s: got %s expected %s "
                      "(reason: %s)" % (g["tgId"], t["tcId"], got, expected,
                                        t.get("reason")))
        print("sigVer tgId=%2d (%s, %s): %d/%d cases match"
              % (g["tgId"], iface, prehash, g_pass, g_run))
    return run, passed, failed, skipped


def check_keygen(doc):
    run = passed = failed = 0
    for g in doc["testGroups"]:
        if g.get("parameterSet") != PARAM_SET:
            continue
        g_run = g_pass = 0
        for t in g["tests"]:
            sk_seed = bytes.fromhex(t["skSeed"])
            sk_prf = bytes.fromhex(t["skPrf"])
            pk_seed = bytes.fromhex(t["pkSeed"])
            SK, PK = S.slh_keygen_internal(sk_seed, sk_prf, pk_seed)
            got_pk = PK[0] + PK[1]
            got_sk = SK[0] + SK[1] + SK[2] + SK[3]
            ok = (got_pk == bytes.fromhex(t["pk"])
                  and got_sk == bytes.fromhex(t["sk"]))
            run += 1
            g_run += 1
            if ok:
                passed += 1
                g_pass += 1
            else:
                failed += 1
                print("MISMATCH keyGen tgId=%s tcId=%s: got pk=%s"
                      % (g["tgId"], t["tcId"], got_pk.hex()))
        print("keyGen tgId=%2d: %d/%d cases match" % (g["tgId"], g_pass, g_run))
    return run, passed, failed


def main():
    any_failed = False

    # Missing vector files are a FAIL, not a skip: this script's whole job is
    # to prove the model against the official vectors, so "ran nothing" must
    # never print PASS.
    doc = load("sigVer_internalProjection.json")
    if doc is None:
        any_failed = True
    else:
        run, passed, failed, skipped = check_sigver(doc)
        print("sigVer[%s] total: run=%d passed=%d failed=%d skipped=%d"
              % (PARAM_SET, run, passed, failed, skipped))
        any_failed |= failed > 0 or run == 0

    doc = load("keyGen_internalProjection.json")
    if doc is None:
        any_failed = True
    else:
        run, passed, failed = check_keygen(doc)
        print("keyGen[%s] total: run=%d passed=%d failed=%d"
              % (PARAM_SET, run, passed, failed))
        any_failed |= failed > 0 or run == 0

    print("ACVP CROSS-VALIDATION: %s" % ("FAIL" if any_failed else "PASS"))
    return 1 if any_failed else 0


if __name__ == "__main__":
    sys.exit(main())
