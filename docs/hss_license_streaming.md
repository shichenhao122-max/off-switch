# Streaming the HSS-LMS license delivery

Branch `off-switch-stream`. Scope: the `CRYPTO_TYPE = 1` (HSS-LMS) license
path of `security_block`.

The HSS-LMS license port was 31,040 bits wide, sixty times the ECDSA path.
Thus it cannot realistically be routed.
This change moves the WOTS+ chain signature values and the Merkle authentication path out of the license struct and onto a single 256-bit valid/ready element stream. This is safe because both fields were already consumed strictly in order and each element is read exactly once and then discarded.

## Implementation
The implementation borrows existing machinery wherever it can. 
On the chain side, "read the mux" simply becomes "wait for the stream" in the existing StWotsLoad state. The authentication-path side needs slightly more,
because a sibling must stay stable for the whole two-block hash it feeds, so
the Merkle sub-FSM gains one load state that latches the element into
aux_reg. I believe this is what the module comments claimed aux_reg was for.
Separately, auth_path had been dimensioned by TREE_H_MAX = 25. I removed it; tree height stays a free parameter.

security_block gains three ports; the inputs carry default values,
so configurations and testbenches that do not use HSS never mention them, and
the four unrelated testbenches change by one line each — tying off an output,
no logic. The PYNQ AXI wrapper, the one instantiation that becomes real
hardware, connects all three ports explicitly and relies on no defaults. The
testbench signing package now stores its material per signer, which lets the
replay test select the original signer's data instead of snapshotting the
stream. The affected header comments are updated to match. 

## Effect
The license port shrinks from 31,040 to 832 bits. The two multiplexers disappear — generic synthesis shows a net reduction of over
thirty-one thousand mux cells — and the six-to-seven-level select trees they
put on the critical path go with them. Verification takes 499,770 cycles
instead of 499,760; the ten extra cycles are the new load state, one per
layer per tree level.

## Issue
The stream currently has no end marker, no length check and no timeout. If the producer stops one element short, the verifier waits forever. Worse, the allowance decrement runs independently of the state machine, so while the verifier hangs the allowance drains to zero and the chip halts with no retry path; only a reset recovers it. The old wide port degraded better: garbage data merely failed verification and could be retried.

## Proposed fix
The proposed fix is a verification watchdog in security_block rather than stream framing.
Framing only catches an announced early end; a producer that goes silent offers nothing to observe, and the verifier would wait for a marker that never comes. 
A watchdog on the verification wait would fail the transaction after 2^N cycles exactly as if the signature were invalid: nonce and signer index retained, allowance
untouched, and a one-cycle engine reset so the next attempt starts clean.
That reuses the existing fail-and-retry path, adds no FSM state, and covers a
hang from any of the three engines, not just this stream. The budget would be
a power of two, making expiry a single counter bit.
