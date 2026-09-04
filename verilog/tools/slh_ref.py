#!/usr/bin/env python3
"""SLH-DSA-SHA2-128s reference model (FIPS 205, published August 13, 2024).

Pure Python 3 stdlib (hashlib/hmac).  Function names, argument order, and
control flow deliberately mirror the FIPS 205 pseudocode so the file can be
reviewed side by side with the standard:

  Alg 2/3/4    toInt / toByte / base_2b            (Section 4.4)
  Alg 5..8     chain, wots_pkGen/sign/pkFromSig    (Section 5)
  Alg 9..11    xmss_node/sign/pkFromSig            (Section 6)
  Alg 12/13    ht_sign / ht_verify                 (Section 7)
  Alg 14..17   fors_skGen/node/sign/pkFromSig      (Section 8)
  Alg 18..20   slh_keygen/sign/verify_internal     (Section 9)
  Alg 22/24/25 slh_sign / slh_verify / hash_slh_verify (Section 10, pure+prehash)

Hash instantiations are the SHA2/security-category-1 set of Section 11.2.1
(everything is SHA-256).  ADRS is the 32-byte structure of Section 4.2/4.3
(Table 1); the SHA2 instantiations consume the 22-byte compressed ADRS^c of
Section 11.2 (Figure 18).

The optional `trace` arguments on the *verification* path are debugging hooks
used by gen_slh_vectors.py to dump intermediate values for the RTL testbench;
they do not alter any computed value.

A pure-Python SHA-256 compression function is included at the bottom for
computing the hardware "midstate" of the constant first block
(PK.seed || toByte(0,48)); see sha256_midstate()/sha256_from_state().

NOTE (local environment): the miniconda Python 3.13.9 on this machine crashes
nondeterministically (segfaults / spurious SystemError) on this hash-heavy
recursive workload -- an interpreter bug, not a property of this file.  Use
/usr/bin/python3 (3.10.12), under which all self-tests and the full NIST ACVP
cross-validation pass deterministically.
"""

import hashlib
import hmac as hmac_mod

# --------------------------------------------------------------------------
# Parameter set SLH-DSA-SHA2-128s (FIPS 205 Table 2)
# --------------------------------------------------------------------------
n = 16          # security parameter (bytes)
h = 63          # total hypertree height
d = 7           # number of hypertree layers
hp = 9          # h' = h/d, height of each XMSS tree
a = 12          # FORS tree height
k = 14          # number of FORS trees
lg_w = 4        # log2 of Winternitz parameter
w = 16          # 2**lg_w                                  (Eq 5.1)
len1 = 32       # ceil(8n/lg_w)                            (Eq 5.2)
len2 = 3        # WOTS+ checksum chains                    (Eq 5.3)
len_ = 35       # len1 + len2                              (Eq 5.4)
m = 30          # message-digest length: 21 + 7 + 2 bytes  (Section 9)

SIG_BYTES = (1 + k * (1 + a) + h + d * len_) * n    # 7856
PK_BYTES = 2 * n                                    # 32

# ADRS type constants (Section 4.2)
WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
WOTS_PRF = 5
FORS_PRF = 6


# --------------------------------------------------------------------------
# Section 4.4 -- Algorithms 2, 3, 4
# --------------------------------------------------------------------------
def toInt(X, n_):
    """Algorithm 2: convert byte string X of length n_ to an integer."""
    total = 0
    for i in range(n_):
        total = 256 * total + X[i]
    return total


def toByte(x, n_):
    """Algorithm 3: convert integer x to an n_-byte big-endian string."""
    S = bytearray(n_)
    total = x
    for i in range(n_):
        S[n_ - 1 - i] = total & 0xFF
        total >>= 8
    return bytes(S)


def base_2b(X, b, out_len):
    """Algorithm 4: compute the base-2^b representation of X."""
    in_ = 0
    bits = 0
    total = 0
    baseb = []
    for _ in range(out_len):
        while bits < b:
            total = (total << 8) + X[in_]
            in_ += 1
            bits += 8
        bits -= b
        baseb.append((total >> bits) % (1 << b))
    return baseb


# --------------------------------------------------------------------------
# Section 4.2/4.3 -- 32-byte ADRS with the member functions of Table 1,
# plus the 22-byte compression ADRS^c of Section 11.2 (Figure 18):
#   ADRS^c = ADRS[3] || ADRS[8:16] || ADRS[19] || ADRS[20:32]
# --------------------------------------------------------------------------
class ADRS:
    __slots__ = ("A",)

    def __init__(self, raw=None):
        self.A = bytearray(32) if raw is None else bytearray(raw)

    def copy(self):
        return ADRS(self.A)

    def setLayerAddress(self, l):
        self.A[0:4] = toByte(l, 4)

    def setTreeAddress(self, t):
        self.A[4:16] = toByte(t, 12)

    def setTypeAndClear(self, Y):
        self.A[16:20] = toByte(Y, 4)
        self.A[20:32] = bytes(12)

    def setKeyPairAddress(self, i):
        self.A[20:24] = toByte(i, 4)

    def setChainAddress(self, i):
        self.A[24:28] = toByte(i, 4)

    def setTreeHeight(self, i):
        self.A[24:28] = toByte(i, 4)

    def setHashAddress(self, i):
        self.A[28:32] = toByte(i, 4)

    def setTreeIndex(self, i):
        self.A[28:32] = toByte(i, 4)

    def getKeyPairAddress(self):
        return toInt(self.A[20:24], 4)

    def getTreeIndex(self):
        return toInt(self.A[28:32], 4)

    def compress(self):
        A = self.A
        return bytes(A[3:4]) + bytes(A[8:16]) + bytes(A[19:20]) + bytes(A[20:32])


def compress_adrs(adrs):
    """22-byte compressed address ADRS^c (Section 11.2)."""
    return adrs.compress()


# --------------------------------------------------------------------------
# Section 11.2.1 -- hash-function instantiations for SLH-DSA-SHA2-128s
# (security category 1: everything is SHA-256; Trunc_n = leftmost n bytes)
# --------------------------------------------------------------------------
# Every PRF/F/H/T call hashes the same constant 64-byte first block
# PK.seed || toByte(0, 64-n).  We cache a hashlib object holding that block's
# midstate and .copy() it per call -- the software analogue of the hardware
# midstate register (see sha256_midstate below).
_block1_cache = {}


def _sha256_after_block1(seed):
    key = bytes(seed)
    base = _block1_cache.get(key)
    if base is None:
        base = hashlib.sha256(key + bytes(64 - n))
        _block1_cache[key] = base
    return base.copy()


def mgf1_sha256(mgf_seed, mask_len):
    """MGF1 with SHA-256 (RFC 8017, Appendix B.2.1)."""
    T = b""
    counter = 0
    while len(T) < mask_len:
        T += hashlib.sha256(mgf_seed + toByte(counter, 4)).digest()
        counter += 1
    return T[:mask_len]


def H_msg(R, pk_seed, pk_root, M):
    inner = hashlib.sha256(R + pk_seed + pk_root + M).digest()
    return mgf1_sha256(R + pk_seed + inner, m)


def PRF(pk_seed, sk_seed, adrs):
    hh = _sha256_after_block1(pk_seed)
    hh.update(adrs.compress() + sk_seed)
    return hh.digest()[:n]


def PRF_msg(sk_prf, opt_rand, M):
    return hmac_mod.new(sk_prf, opt_rand + M, hashlib.sha256).digest()[:n]


def F(pk_seed, adrs, M1):
    hh = _sha256_after_block1(pk_seed)
    hh.update(adrs.compress() + M1)
    return hh.digest()[:n]


def H(pk_seed, adrs, M2):
    hh = _sha256_after_block1(pk_seed)
    hh.update(adrs.compress() + M2)
    return hh.digest()[:n]


def T_l(pk_seed, adrs, Ml):
    hh = _sha256_after_block1(pk_seed)
    hh.update(adrs.compress() + Ml)
    return hh.digest()[:n]


# --------------------------------------------------------------------------
# Section 5 -- WOTS+ (Algorithms 5, 6, 7, 8)
# --------------------------------------------------------------------------
def chain(X, i, s, pk_seed, adrs):
    """Algorithm 5: iterate F s times on X starting from index i."""
    tmp = X
    for j in range(i, i + s):
        adrs.setHashAddress(j)
        tmp = F(pk_seed, adrs, tmp)
    return tmp


def wots_pkGen(sk_seed, pk_seed, adrs):
    """Algorithm 6: generate a WOTS+ public key."""
    skADRS = adrs.copy()
    skADRS.setTypeAndClear(WOTS_PRF)
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress())
    tmp = []
    for i in range(len_):
        skADRS.setChainAddress(i)
        sk = PRF(pk_seed, sk_seed, skADRS)
        adrs.setChainAddress(i)
        tmp.append(chain(sk, 0, w - 1, pk_seed, adrs))
    wotspkADRS = adrs.copy()
    wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())
    return T_l(pk_seed, wotspkADRS, b"".join(tmp))


def _wots_msg_and_csum(M):
    """Common lines 1-7 of Algorithms 7 and 8 (message + checksum digits)."""
    csum = 0
    msg = base_2b(M, lg_w, len1)
    for i in range(len1):
        csum += w - 1 - msg[i]
    csum <<= (8 - ((len2 * lg_w) % 8)) % 8
    msg = msg + base_2b(toByte(csum, (len2 * lg_w + 7) // 8), lg_w, len2)
    return msg


def wots_sign(M, sk_seed, pk_seed, adrs):
    """Algorithm 7: generate a WOTS+ signature on an n-byte message."""
    msg = _wots_msg_and_csum(M)
    skADRS = adrs.copy()
    skADRS.setTypeAndClear(WOTS_PRF)
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress())
    sig = []
    for i in range(len_):
        skADRS.setChainAddress(i)
        sk = PRF(pk_seed, sk_seed, skADRS)
        adrs.setChainAddress(i)
        sig.append(chain(sk, 0, msg[i], pk_seed, adrs))
    return b"".join(sig)


def wots_pkFromSig(sig, M, pk_seed, adrs, trace=None):
    """Algorithm 8: compute a WOTS+ public key from a signature."""
    msg = _wots_msg_and_csum(M)
    tmp = []
    for i in range(len_):
        adrs.setChainAddress(i)
        tmp.append(chain(sig[i * n:(i + 1) * n], msg[i], w - 1 - msg[i],
                         pk_seed, adrs))
    wotspkADRS = adrs.copy()
    wotspkADRS.setTypeAndClear(WOTS_PK)
    wotspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())
    pk_sig = T_l(pk_seed, wotspkADRS, b"".join(tmp))
    if trace is not None:
        trace["wots_chain_ends"] = list(tmp)
        trace["wots_pk"] = pk_sig
    return pk_sig


# --------------------------------------------------------------------------
# Section 6 -- XMSS (Algorithms 9, 10, 11)
# --------------------------------------------------------------------------
def xmss_node(sk_seed, i, z, pk_seed, adrs):
    """Algorithm 9: compute the root of a Merkle subtree of WOTS+ pks."""
    if z == 0:
        adrs.setTypeAndClear(WOTS_HASH)
        adrs.setKeyPairAddress(i)
        node = wots_pkGen(sk_seed, pk_seed, adrs)
    else:
        lnode = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
        rnode = xmss_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
        adrs.setTypeAndClear(TREE)
        adrs.setTreeHeight(z)
        adrs.setTreeIndex(i)
        node = H(pk_seed, adrs, lnode + rnode)
    return node


def xmss_sign(M, sk_seed, idx, pk_seed, adrs):
    """Algorithm 10: generate an XMSS signature (WOTS+ sig || AUTH)."""
    AUTH = []
    for j in range(hp):
        kk = (idx >> j) ^ 1
        AUTH.append(xmss_node(sk_seed, kk, j, pk_seed, adrs))
    adrs.setTypeAndClear(WOTS_HASH)
    adrs.setKeyPairAddress(idx)
    sig = wots_sign(M, sk_seed, pk_seed, adrs)
    return sig + b"".join(AUTH)


def xmss_pkFromSig(idx, sig_xmss, M, pk_seed, adrs, trace=None):
    """Algorithm 11: compute an XMSS public key from an XMSS signature."""
    adrs.setTypeAndClear(WOTS_HASH)
    adrs.setKeyPairAddress(idx)
    sig = sig_xmss[0:len_ * n]
    AUTH = sig_xmss[len_ * n:(len_ + hp) * n]
    node0 = wots_pkFromSig(sig, M, pk_seed, adrs, trace=trace)
    adrs.setTypeAndClear(TREE)
    adrs.setTreeIndex(idx)
    for kk in range(hp):
        adrs.setTreeHeight(kk + 1)
        auth_k = AUTH[kk * n:(kk + 1) * n]
        if ((idx >> kk) & 1) == 0:
            adrs.setTreeIndex(adrs.getTreeIndex() // 2)
            node1 = H(pk_seed, adrs, node0 + auth_k)
        else:
            adrs.setTreeIndex((adrs.getTreeIndex() - 1) // 2)
            node1 = H(pk_seed, adrs, auth_k + node0)
        node0 = node1
    if trace is not None:
        trace["xmss_root"] = node0
    return node0


# --------------------------------------------------------------------------
# Section 7 -- Hypertree (Algorithms 12, 13)
# --------------------------------------------------------------------------
def ht_sign(M, sk_seed, pk_seed, idx_tree, idx_leaf):
    """Algorithm 12: generate a hypertree signature."""
    adrs = ADRS()
    adrs.setTreeAddress(idx_tree)
    sig_tmp = xmss_sign(M, sk_seed, idx_leaf, pk_seed, adrs)
    sig_ht = sig_tmp
    root = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, adrs)
    for j in range(1, d):
        idx_leaf = idx_tree % (1 << hp)
        idx_tree >>= hp
        adrs.setLayerAddress(j)
        adrs.setTreeAddress(idx_tree)
        sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs)
        sig_ht += sig_tmp
        if j < d - 1:
            root = xmss_pkFromSig(idx_leaf, sig_tmp, root, pk_seed, adrs)
    return sig_ht


def ht_verify(M, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root, trace=None):
    """Algorithm 13: verify a hypertree signature."""
    xmss_sig_bytes = (hp + len_) * n
    adrs = ADRS()
    adrs.setTreeAddress(idx_tree)
    layer_trace = {} if trace is not None else None
    sig_tmp = sig_ht[0:xmss_sig_bytes]
    node = xmss_pkFromSig(idx_leaf, sig_tmp, M, pk_seed, adrs,
                          trace=layer_trace)
    if trace is not None:
        trace.append(layer_trace)
    for j in range(1, d):
        idx_leaf = idx_tree % (1 << hp)
        idx_tree >>= hp
        adrs.setLayerAddress(j)
        adrs.setTreeAddress(idx_tree)
        sig_tmp = sig_ht[j * xmss_sig_bytes:(j + 1) * xmss_sig_bytes]
        layer_trace = {} if trace is not None else None
        node = xmss_pkFromSig(idx_leaf, sig_tmp, node, pk_seed, adrs,
                              trace=layer_trace)
        if trace is not None:
            trace.append(layer_trace)
    return node == pk_root


# --------------------------------------------------------------------------
# Section 8 -- FORS (Algorithms 14, 15, 16, 17)
# --------------------------------------------------------------------------
def fors_skGen(sk_seed, pk_seed, adrs, idx):
    """Algorithm 14: generate a FORS private-key value."""
    skADRS = adrs.copy()
    skADRS.setTypeAndClear(FORS_PRF)
    skADRS.setKeyPairAddress(adrs.getKeyPairAddress())
    skADRS.setTreeIndex(idx)
    return PRF(pk_seed, sk_seed, skADRS)


def fors_node(sk_seed, i, z, pk_seed, adrs):
    """Algorithm 15: compute the root of a Merkle subtree of FORS values."""
    if z == 0:
        sk = fors_skGen(sk_seed, pk_seed, adrs, i)
        adrs.setTreeHeight(0)
        adrs.setTreeIndex(i)
        node = F(pk_seed, adrs, sk)
    else:
        lnode = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs)
        rnode = fors_node(sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)
        adrs.setTreeHeight(z)
        adrs.setTreeIndex(i)
        node = H(pk_seed, adrs, lnode + rnode)
    return node


def fors_sign(md, sk_seed, pk_seed, adrs):
    """Algorithm 16: generate a FORS signature."""
    sig_fors = b""
    indices = base_2b(md, a, k)
    for i in range(k):
        sig_fors += fors_skGen(sk_seed, pk_seed, adrs, i * (1 << a) + indices[i])
        AUTH = []
        for j in range(a):
            s = (indices[i] >> j) ^ 1
            AUTH.append(fors_node(sk_seed, i * (1 << (a - j)) + s, j,
                                  pk_seed, adrs))
        sig_fors += b"".join(AUTH)
    return sig_fors


def fors_pkFromSig(sig_fors, md, pk_seed, adrs, trace=None):
    """Algorithm 17: compute a FORS public key from a FORS signature."""
    indices = base_2b(md, a, k)
    root = []
    leaves = []
    for i in range(k):
        sk = sig_fors[i * (a + 1) * n:(i * (a + 1) + 1) * n]
        adrs.setTreeHeight(0)
        adrs.setTreeIndex(i * (1 << a) + indices[i])
        node0 = F(pk_seed, adrs, sk)
        leaves.append(node0)
        auth = sig_fors[(i * (a + 1) + 1) * n:(i + 1) * (a + 1) * n]
        for j in range(a):
            adrs.setTreeHeight(j + 1)
            auth_j = auth[j * n:(j + 1) * n]
            if ((indices[i] >> j) & 1) == 0:
                adrs.setTreeIndex(adrs.getTreeIndex() // 2)
                node1 = H(pk_seed, adrs, node0 + auth_j)
            else:
                adrs.setTreeIndex((adrs.getTreeIndex() - 1) // 2)
                node1 = H(pk_seed, adrs, auth_j + node0)
            node0 = node1
        root.append(node0)
    forspkADRS = adrs.copy()
    forspkADRS.setTypeAndClear(FORS_ROOTS)
    forspkADRS.setKeyPairAddress(adrs.getKeyPairAddress())
    pk = T_l(pk_seed, forspkADRS, b"".join(root))
    if trace is not None:
        trace["indices"] = list(indices)
        trace["fors_leaves"] = leaves
        trace["fors_roots"] = list(root)
        trace["pk_fors"] = pk
    return pk


# --------------------------------------------------------------------------
# Section 9 -- SLH-DSA internal functions (Algorithms 18, 19, 20)
# --------------------------------------------------------------------------
def slh_keygen_internal(sk_seed, sk_prf, pk_seed):
    """Algorithm 18: generate an SLH-DSA key pair.

    Returns ((SK.seed, SK.prf, PK.seed, PK.root), (PK.seed, PK.root)).
    """
    adrs = ADRS()
    adrs.setLayerAddress(d - 1)
    pk_root = xmss_node(sk_seed, 0, hp, pk_seed, adrs)
    return ((sk_seed, sk_prf, pk_seed, pk_root), (pk_seed, pk_root))


def _split_digest(digest):
    """Digest split common to Algorithms 19 and 20 (md, idx_tree, idx_leaf)."""
    ka8 = (k * a + 7) // 8                    # 21 bytes
    hhd8 = (h - h // d + 7) // 8              # 7 bytes
    hd8 = (h + 8 * d - 1) // (8 * d)          # 2 bytes
    md = digest[0:ka8]
    tmp_idx_tree = digest[ka8:ka8 + hhd8]
    tmp_idx_leaf = digest[ka8 + hhd8:ka8 + hhd8 + hd8]
    idx_tree = toInt(tmp_idx_tree, hhd8) % (1 << (h - h // d))
    idx_leaf = toInt(tmp_idx_leaf, hd8) % (1 << (h // d))
    return md, idx_tree, idx_leaf


def slh_sign_internal(M, SK, addrnd=None):
    """Algorithm 19: generate an SLH-DSA signature.

    addrnd=None selects the deterministic variant (opt_rand = PK.seed).
    """
    sk_seed, sk_prf, pk_seed, pk_root = SK
    adrs = ADRS()
    opt_rand = pk_seed if addrnd is None else addrnd
    R = PRF_msg(sk_prf, opt_rand, M)
    SIG = R
    digest = H_msg(R, pk_seed, pk_root, M)
    md, idx_tree, idx_leaf = _split_digest(digest)
    adrs.setTreeAddress(idx_tree)
    adrs.setTypeAndClear(FORS_TREE)
    adrs.setKeyPairAddress(idx_leaf)
    sig_fors = fors_sign(md, sk_seed, pk_seed, adrs)
    SIG += sig_fors
    pk_fors = fors_pkFromSig(sig_fors, md, pk_seed, adrs)
    sig_ht = ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)
    SIG += sig_ht
    return SIG


def slh_verify_internal(M, SIG, PK, trace=None):
    """Algorithm 20: verify an SLH-DSA signature."""
    pk_seed, pk_root = PK
    if len(SIG) != SIG_BYTES:
        return False
    adrs = ADRS()
    R = SIG[0:n]
    sig_fors = SIG[n:(1 + k * (1 + a)) * n]
    sig_ht = SIG[(1 + k * (1 + a)) * n:]
    digest = H_msg(R, pk_seed, pk_root, M)
    md, idx_tree, idx_leaf = _split_digest(digest)
    adrs.setTreeAddress(idx_tree)
    adrs.setTypeAndClear(FORS_TREE)
    adrs.setKeyPairAddress(idx_leaf)
    fors_trace = {} if trace is not None else None
    pk_fors = fors_pkFromSig(sig_fors, md, pk_seed, adrs, trace=fors_trace)
    ht_trace = [] if trace is not None else None
    ok = ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root,
                   trace=ht_trace)
    if trace is not None:
        trace["digest"] = digest
        trace["md"] = md
        trace["idx_tree"] = idx_tree
        trace["idx_leaf"] = idx_leaf
        trace["fors"] = fors_trace
        trace["ht"] = ht_trace
    return ok


# --------------------------------------------------------------------------
# Section 10 -- SLH-DSA external functions (pure: Algorithms 22 and 24;
# pre-hash verification: Algorithm 25, provided for ACVP cross-checks)
# --------------------------------------------------------------------------
def slh_sign(M, ctx, SK, addrnd=None):
    """Algorithm 22: generate a pure SLH-DSA signature.

    addrnd=None selects the deterministic variant.
    """
    if len(ctx) > 255:
        raise ValueError("context string too long")
    Mp = toByte(0, 1) + toByte(len(ctx), 1) + ctx + M
    return slh_sign_internal(Mp, SK, addrnd)


def slh_verify(M, SIG, ctx, PK):
    """Algorithm 24: verify a pure SLH-DSA signature."""
    if len(ctx) > 255:
        return False
    Mp = toByte(0, 1) + toByte(len(ctx), 1) + ctx + M
    return slh_verify_internal(Mp, SIG, PK)


def _hash_oid(arc):
    """DER encoding (tag+length) of OID 2.16.840.1.101.3.4.2.<arc>."""
    return bytes.fromhex("06096086480165030402") + bytes([arc])


_PREHASH = {
    # PH name (ACVP spelling) -> (DER-encoded OID, digest function).
    # SHA-256/SHA-512/SHAKE cases are shown in Algorithm 23/25; the rest are
    # the "other approved hash functions or XOFs" with their NIST OID arcs.
    "SHA2-256": (_hash_oid(1), lambda M: hashlib.sha256(M).digest()),
    "SHA2-384": (_hash_oid(2), lambda M: hashlib.sha384(M).digest()),
    "SHA2-512": (_hash_oid(3), lambda M: hashlib.sha512(M).digest()),
    "SHA2-224": (_hash_oid(4), lambda M: hashlib.sha224(M).digest()),
    "SHA2-512/224": (_hash_oid(5),
                     lambda M: hashlib.new("sha512_224", M).digest()),
    "SHA2-512/256": (_hash_oid(6),
                     lambda M: hashlib.new("sha512_256", M).digest()),
    "SHA3-224": (_hash_oid(7), lambda M: hashlib.sha3_224(M).digest()),
    "SHA3-256": (_hash_oid(8), lambda M: hashlib.sha3_256(M).digest()),
    "SHA3-384": (_hash_oid(9), lambda M: hashlib.sha3_384(M).digest()),
    "SHA3-512": (_hash_oid(10), lambda M: hashlib.sha3_512(M).digest()),
    "SHAKE-128": (_hash_oid(11), lambda M: hashlib.shake_128(M).digest(32)),
    "SHAKE-256": (_hash_oid(12), lambda M: hashlib.shake_256(M).digest(64)),
}


def hash_slh_verify(M, SIG, ctx, PH, PK):
    """Algorithm 25: verify a pre-hash SLH-DSA signature (PH by name)."""
    if len(ctx) > 255 or PH not in _PREHASH:
        return False
    oid, digestfn = _PREHASH[PH]
    Mp = toByte(1, 1) + toByte(len(ctx), 1) + ctx + oid + digestfn(M)
    return slh_verify_internal(Mp, SIG, PK)


# --------------------------------------------------------------------------
# Pure-Python SHA-256 compression function (FIPS 180-4) -- used to compute
# the hardware midstate after absorbing the constant first block
# PK.seed || toByte(0, 48).
# --------------------------------------------------------------------------
SHA256_IV = (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
             0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19)

_SHA256_K = (
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1,
    0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786,
    0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147,
    0x06CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B,
    0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A,
    0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2)


def _rotr(x, r):
    return ((x >> r) | (x << (32 - r))) & 0xFFFFFFFF


def sha256_compress(state, block):
    """One SHA-256 compression of a 64-byte block; returns the new 8-word
    state as a tuple of 32-bit integers."""
    assert len(block) == 64
    W = list(int.from_bytes(block[4 * t:4 * t + 4], "big") for t in range(16))
    for t in range(16, 64):
        s0 = _rotr(W[t - 15], 7) ^ _rotr(W[t - 15], 18) ^ (W[t - 15] >> 3)
        s1 = _rotr(W[t - 2], 17) ^ _rotr(W[t - 2], 19) ^ (W[t - 2] >> 10)
        W.append((W[t - 16] + s0 + W[t - 7] + s1) & 0xFFFFFFFF)
    aa, bb, cc, dd, ee, ff, gg, hh = state
    for t in range(64):
        S1 = _rotr(ee, 6) ^ _rotr(ee, 11) ^ _rotr(ee, 25)
        ch = (ee & ff) ^ (~ee & gg)
        temp1 = (hh + S1 + ch + _SHA256_K[t] + W[t]) & 0xFFFFFFFF
        S0 = _rotr(aa, 2) ^ _rotr(aa, 13) ^ _rotr(aa, 22)
        maj = (aa & bb) ^ (aa & cc) ^ (bb & cc)
        temp2 = (S0 + maj) & 0xFFFFFFFF
        hh, gg, ff, ee = gg, ff, ee, (dd + temp1) & 0xFFFFFFFF
        dd, cc, bb, aa = cc, bb, aa, (temp1 + temp2) & 0xFFFFFFFF
    return tuple((s + v) & 0xFFFFFFFF
                 for s, v in zip(state, (aa, bb, cc, dd, ee, ff, gg, hh)))


def sha256_midstate(seed):
    """8-word SHA-256 state after compressing the single 64-byte block
    seed || toByte(0, 64 - len(seed)) into the initial state (H0..H7)."""
    return sha256_compress(SHA256_IV, seed + bytes(64 - len(seed)))


def sha256_from_state(state, bytes_done, tail):
    """Finish SHA-256 from a saved midstate.

    `state` is the 8-word state after `bytes_done` bytes (a multiple of 64)
    have been compressed; `tail` is the remainder of the message.  Returns
    the 32-byte digest of the full message.
    """
    assert bytes_done % 64 == 0
    total = bytes_done + len(tail)
    padded = tail + b"\x80"
    padded += bytes((-(total + 1 + 8)) % 64)
    padded += (8 * total).to_bytes(8, "big")
    for off in range(0, len(padded), 64):
        state = sha256_compress(state, padded[off:off + 64])
    return b"".join(word.to_bytes(4, "big") for word in state)


def midstate_selfcheck(trials=8, seed_material=b"slh_ref midstate selfcheck"):
    """Resuming from midstate(seed) must reproduce hashlib's digest of
    sha256(seed || toByte(0,48) || tail) for several pseudorandom tails."""
    for t in range(trials):
        blob = hashlib.sha256(seed_material + toByte(t, 4)).digest()
        seed = blob[:n]
        tail_len = 1 + (blob[16] % 200)
        tail = (blob * ((tail_len // 32) + 1))[:tail_len]
        ref = hashlib.sha256(seed + bytes(64 - n) + tail).digest()
        got = sha256_from_state(sha256_midstate(seed), 64, tail)
        if ref != got:
            return False
    return True


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------
def _selftest():
    failures = 0

    def check(name, ok):
        nonlocal failures
        print(("PASS: " if ok else "FAIL: ") + name)
        if not ok:
            failures += 1

    check("midstate self-check (resume vs hashlib, 8 random tails)",
          midstate_selfcheck())

    sk_seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    sk_prf = bytes.fromhex("101112131415161718191a1b1c1d1e1f")
    pk_seed = bytes.fromhex("202122232425262728292a2b2c2d2e2f")
    SK, PK = slh_keygen_internal(sk_seed, sk_prf, pk_seed)
    check("keygen produced 16-byte PK.root", len(PK[1]) == n)

    msg = b"off-switch SLH-DSA-SHA2-128s self-test message"
    ctx = b""
    sig = slh_sign(msg, ctx, SK)          # deterministic variant
    check("sig length == %d" % SIG_BYTES, len(sig) == SIG_BYTES)
    check("verify(valid signature)", slh_verify(msg, sig, ctx, PK))

    fors_bytes = k * (1 + a) * n          # 2912
    regions = {
        "R region (byte 3)": 3,
        "FORS region (byte %d)" % (n + 100): n + 100,
        "HT region (byte %d)" % (n + fors_bytes + 1000): n + fors_bytes + 1000,
    }
    for name, off in regions.items():
        bad = bytearray(sig)
        bad[off] ^= 0x01
        check("reject flipped bit in " + name,
              not slh_verify(msg, bytes(bad), ctx, PK))

    check("reject tampered message",
          not slh_verify(msg + b"x", sig, ctx, PK))
    bad_root = bytes(x ^ 0xFF for x in PK[1])
    check("reject wrong PK.root",
          not slh_verify(msg, sig, ctx, (PK[0], bad_root)))
    check("reject truncated signature",
          not slh_verify(msg, sig[:-1], ctx, PK))

    print("%s (%d failure%s)" %
          ("ALL SELF-TESTS PASSED" if failures == 0 else "SELF-TEST FAILURES",
           failures, "" if failures == 1 else "s"))
    return failures


if __name__ == "__main__":
    import sys
    sys.setrecursionlimit(10000)
    sys.exit(1 if _selftest() else 0)
