#!/usr/bin/env /usr/bin/python3
"""Search for messages whose signatures exercise rare WOTS digit edges:
  edge15: some layer's chain-34 digit == 15 (skip path at the absorb slot)
  edge0:  some layer's chain-34 digit == 0  (maximum hashing on that chain)
Emits one vector set per edge via gen_slh_vectors.py."""
import hashlib, json, subprocess, sys, os, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_BASE = os.path.join(HERE, '..', 'tb', 'vectors')

def layer_digits(msg16):
    digits = [(msg16[i // 2] >> (4 if i % 2 == 0 else 0)) & 0xF for i in range(32)]
    csum = sum(15 - d for d in digits)
    return digits + [(csum >> 8) & 0xF, (csum >> 4) & 0xF, csum & 0xF]

def probe(message_hex, tmpdir):
    subprocess.run([sys.executable, os.path.join(HERE, 'gen_slh_vectors.py'),
                    '--message', message_hex, '--out-dir', tmpdir,
                    '--keys-svh', os.path.join(tmpdir, 'slh_keys.svh')],
                   check=True, capture_output=True)
    inter = json.load(open(os.path.join(tmpdir, 'intermediates.json')))
    msgs = [inter['pk_fors']] + [l['xmss_root'] for l in inter['ht_layers'][:-1]]
    last = [layer_digits(bytes.fromhex(m))[34] for m in msgs]
    return last

def main():
    found = {}
    tmp = tempfile.mkdtemp(prefix='slh-edge-probe-')
    for i in range(64):
        mh = hashlib.sha256(b'off-switch-edge-%d' % i).hexdigest()
        last34 = probe(mh, tmp)
        print(f'candidate {i}: chain-34 digits per layer = {last34}', flush=True)
        if 15 in last34 and 'edge15' not in found: found['edge15'] = mh
        if 0 in last34 and 'edge0' not in found:  found['edge0'] = mh
        if len(found) == 2: break
    for name, mh in found.items():
        out = os.path.join(OUT_BASE, f'slh128s_{name}')
        subprocess.run([sys.executable, os.path.join(HERE, 'gen_slh_vectors.py'),
                        '--message', mh, '--out-dir', out], check=True)
        print(f'{name}: message {mh} -> {out}', flush=True)
    if len(found) < 2:
        print('WARNING: not all edges found in 64 candidates', flush=True)

if __name__ == '__main__':
    main()
