// Hash-based signature verifier — scheme dispatch.
//
// hbsv_verify is one control structure; everything that depends on the
// signature scheme lives here as elaboration-time constants and constant
// functions of the SCH parameter: scheme parameters, hash-message widths,
// the accumulator geometry, and the message builders that turn the shared
// ctrl_t bundle plus the current data values into each scheme's byte layout
// (hss_pkg / slh_pkg own the structs). Builders return their maximum width;
// the caller narrows with a width cast, so structs sit right-aligned.

package hbsv_schs_pkg;

    import hbsv_ctrl_pkg::*;

    // Builder arguments are passed at the widest scheme's width and narrowed
    // per scheme inside; the unused high/low bits are intentional.
    /* verilator lint_off UNUSEDSIGNAL */

    // -------------------------------------------------------------------------
    // Scheme parameters
    // -------------------------------------------------------------------------

    // Node / signature-element / licence-beat width
    function automatic int unsigned digest_w(input sch_e s);
        return (s == SCHEME_SLH) ? slh_pkg::SLH_NW : arith_pkg::WIDTH;    // 128 / 256
    endfunction

    // Key context: LMS tree identifier I, SLH PK.seed
    localparam int unsigned KCTX_W = 128;

    // Winternitz digit width and chain geometry
    function automatic int unsigned digit_w(input sch_e s);
        return (s == SCHEME_SLH) ? slh_pkg::SLH_LGW : hss_pkg::WOTS_W;    // 4 / 8
    endfunction
    function automatic int unsigned ots_len1(input sch_e s);
        return (s == SCHEME_SLH) ? slh_pkg::SLH_LEN1 : hss_pkg::WOTS_P1;  // 32 / 32
    endfunction
    function automatic int unsigned ots_len2(input sch_e s);
        return (s == SCHEME_SLH) ? slh_pkg::SLH_LEN2 : hss_pkg::WOTS_P2;  // 3 / 2
    endfunction
    function automatic int unsigned ots_len(input sch_e s);
        return ots_len1(s) + ots_len2(s);                                 // 35 / 34
    endfunction
    // Last hash address of a chain (w - 2); a digit of w - 1 needs no hash
    function automatic int unsigned step_max(input sch_e s);
        return (1 << digit_w(s)) - 2;                                      // 14 / 254
    endfunction

    // Hypertree
    function automatic int unsigned layers(input sch_e s);
        return (s == SCHEME_SLH) ? slh_pkg::SLH_D : hss_pkg::HSS_LEVELS;  // 7 / 2
    endfunction
    function automatic int unsigned tree_h(input sch_e s);
        return (s == SCHEME_SLH) ? slh_pkg::SLH_HP : hss_pkg::TREE_H;     // 9 / 5
    endfunction

    // FORS (SLH only)
    function automatic int unsigned fors_k(input sch_e s);
        return (s == SCHEME_SLH) ? slh_pkg::SLH_K : 0;
    endfunction
    function automatic int unsigned fors_h(input sch_e s);
        return (s == SCHEME_SLH) ? slh_pkg::SLH_A : 0;
    endfunction

    // Structural switches
    function automatic bit uses_midstate(input sch_e s);   // constant first block precomputed
        return (s == SCHEME_SLH);
    endfunction
    function automatic bit has_leaf_hash(input sch_e s);   // LMS hashes Kc once more for the leaf
        return (s == SCHEME_LMS);
    endfunction

    // -------------------------------------------------------------------------
    // Endpoint accumulation geometry (LMS Kc, SLH T_k / T_len)
    //
    // Both schemes prefix the element stream with 22 bytes (I||q||D_PBLC,
    // ADRSc), so with E-byte elements a 64-byte block boundary always falls
    // 10 bytes into an element: every absorbed block ends with an 80-bit
    // element head and leaves an (8E-80)-bit carry. The first block carries
    // the prefix and (64-22)/E full elements, later blocks the carry and
    // 64/E - 1 full elements.
    // -------------------------------------------------------------------------

    localparam int unsigned ACC_PREFIX_W = 176;
    localparam int unsigned ACC_HEAD_W   = 80;

    function automatic int unsigned acc_first_full(input sch_e s);
        return (512 - ACC_PREFIX_W) / digest_w(s);                         // 2 / 1
    endfunction
    function automatic int unsigned acc_mid_full(input sch_e s);
        return 512 / digest_w(s) - 1;                                      // 3 / 1
    endfunction
    function automatic int unsigned acc_carry_w(input sch_e s);
        return digest_w(s) - ACC_HEAD_W;                                   // 48 / 176
    endfunction
    // Elements still banked when a stream of n elements ends, i.e. what the
    // final padding block carries besides the carry (absorbs fall at
    // first_full, then every mid_full + 1 elements).
    function automatic int unsigned acc_tail_elems(input sch_e s, input int unsigned n);
        if (n <= acc_first_full(s)) return n;
        return (n - 1 - acc_first_full(s)) % (acc_mid_full(s) + 1);      // LMS 0; SLH 0 / 3
    endfunction

    // -------------------------------------------------------------------------
    // Hash-message widths (bits actually presented after any midstate block)
    // -------------------------------------------------------------------------

    localparam int unsigned MAX_MSG_HASH_BITS  = 880;   // LMS Q with serialised pubkey
    localparam int unsigned MAX_MSG_HASH2_BITS = 544;   // SLH MGF1
    localparam int unsigned MAX_CHAIN_MSG_BITS = 440;   // LMS chain step
    localparam int unsigned MAX_LEAF_MSG_BITS  = 432;   // LMS leaf
    localparam int unsigned MAX_TREE_MSG_BITS  = 688;   // LMS interior node

    function automatic int unsigned msg_hash_bits(input sch_e s, input bit sub);
        return (s == SCHEME_SLH) ? $bits(slh_pkg::slh_hmsg_msg_t)
                                 : (sub ? $bits(hss_pkg::lms_q_sub_msg_t)
                                        : $bits(hss_pkg::lms_q_msg_t));   // 656 / 880,688
    endfunction
    function automatic int unsigned msg_hash2_bits(input sch_e s);
        return (s == SCHEME_SLH) ? $bits(slh_pkg::slh_mgf_msg_t) : 0;     // 544 / -
    endfunction
    function automatic int unsigned chain_msg_bits(input sch_e s);
        return (s == SCHEME_SLH) ? $bits(slh_pkg::slh_f_msg_t)
                                 : $bits(hss_pkg::lms_chain_msg_t);       // 304 / 440
    endfunction
    function automatic int unsigned leaf_msg_bits(input sch_e s);
        return (s == SCHEME_SLH) ? 0 : $bits(hss_pkg::lms_leaf_msg_t);    // - / 432
    endfunction
    function automatic int unsigned tree_msg_bits(input sch_e s);
        return (s == SCHEME_SLH) ? $bits(slh_pkg::slh_tree_msg_t)
                                 : $bits(hss_pkg::lms_intr_msg_t);        // 432 / 688
    endfunction
    // Bits the padding length field must add for the precomputed first block
    function automatic int unsigned midstate_bits(input sch_e s);
        return uses_midstate(s) ? 512 : 0;
    endfunction
    // Accumulated message length: prefix block(s) + N elements
    function automatic int unsigned acc_msg_bits(input sch_e s, input int unsigned n);
        return midstate_bits(s) + ACC_PREFIX_W + n * digest_w(s);
    endfunction

    // -------------------------------------------------------------------------
    // SHA-256 padding helpers (shared by every message)
    // -------------------------------------------------------------------------

    localparam int unsigned SHA_PAD_OVERHEAD = 1 + 64;

    function automatic int unsigned calc_sha_blocks(input int unsigned data_bits);
        return (data_bits + SHA_PAD_OVERHEAD + 511) / 512;
    endfunction
    function automatic int unsigned calc_sha_pad_zeros(input int unsigned data_bits);
        return calc_sha_blocks(data_bits) * 512 - (data_bits + SHA_PAD_OVERHEAD);
    endfunction

    // -------------------------------------------------------------------------
    // ctrl_t -> scheme fields
    // -------------------------------------------------------------------------

    // LMS: the u32 field is the leaf index q, or the parent node number
    // during a Merkle step (nodes are numbered 2n / 2n+1 from parent n).
    function automatic logic [31:0] ctrl2q(input ctrl_t c);
        return c.leaf;
    endfunction
    function automatic logic [31:0] ctrl2node(input ctrl_t c);
        return c.nidx >> 1;
    endfunction

    // SLH: compressed address for the given type. mrkl selects the Merkle
    // interpretation of words 6/7 (height = level+1, index = parent) over the
    // leaf one (height 0, index = the leaf's tree index).
    function automatic slh_pkg::slh_adrs_c_t ctrl2adrs(input ctrl_t c, input logic [7:0] typ,
                                                       input bit mrkl);
        slh_pkg::slh_adrs_c_t a;
        a.layer = {5'b0, c.layer};
        a.tree  = {10'b0, c.tree};
        a.typ   = typ;
        a.kp    = (typ == slh_pkg::ADRS_TREE) ? 32'b0 : c.leaf;
        a.w6    = '0;
        a.w7    = '0;
        case (typ)
            slh_pkg::ADRS_WOTS_HASH: begin
                a.w6 = {25'b0, c.chain};
                a.w7 = {24'b0, c.step};
            end
            slh_pkg::ADRS_TREE, slh_pkg::ADRS_FORS_TREE: begin
                if (mrkl) begin
                    a.w6 = {27'b0, c.level} + 32'd1;
                    a.w7 = c.nidx >> 1;
                end else begin
                    a.w7 = c.nidx;            // FORS leaf: height 0, index = leaf
                end
            end
            default: ;                        // WOTS_PK / FORS_ROOTS: words 6/7 zero
        endcase
        return a;
    endfunction

    // -------------------------------------------------------------------------
    // Message builders. Data arguments are passed at the widest width (256)
    // and narrowed inside the SLH branch; the result is right-aligned.
    // -------------------------------------------------------------------------

    // Per-layer message hash. LMS: Q over the randomizer beat and either the
    // user message (layer 0) or the serialised public key of the layer below.
    // SLH: the inner SHA-256 of H_msg over R (the randomizer beat), PK.seed,
    // PK.root and 0x0000 || message.
    function automatic logic [MAX_MSG_HASH_BITS-1:0] msg_hash_msg(
        input sch_e            s,
        input logic [KCTX_W-1:0] kctx,       // I / PK.seed
        input logic [255:0]    root,         // PK.root (SLH)
        input ctrl_t           c,
        input logic [255:0]    rand_beat,    // C / R, straight off the stream
        input logic [255:0]    message,
        input bit              sub,          // LMS upper layer
        input logic [KCTX_W-1:0] prev_kctx,  // LMS: identifier of the layer below
        input logic [255:0]    prev_root);   // LMS: root computed for the layer below
        case (s)
            SCHEME_LMS: begin
                if (sub) return MAX_MSG_HASH_BITS'(hss_pkg::lms_q_sub_msg_t'{
                    pre:        hss_pkg::lms_prefix_t'{i: kctx, q: ctrl2q(c), d: hss_pkg::D_MESG},
                    c:          rand_beat,
                    lms_type:   32'(hss_pkg::LMS_TYPE),
                    lmots_type: 32'(hss_pkg::LMOTS_TYPE),
                    sub_i:      prev_kctx,
                    root:       prev_root});
                else     return MAX_MSG_HASH_BITS'(hss_pkg::lms_q_msg_t'{
                    pre:        hss_pkg::lms_prefix_t'{i: kctx, q: ctrl2q(c), d: hss_pkg::D_MESG},
                    c:          rand_beat,
                    msg:        message});
            end
            default: return MAX_MSG_HASH_BITS'(slh_pkg::slh_hmsg_msg_t'{
                    r:    rand_beat[255 -: slh_pkg::SLH_NW],
                    seed: kctx[KCTX_W-1 -: slh_pkg::SLH_NW],
                    root: root[255 -: slh_pkg::SLH_NW],
                    pre:  16'h0000,
                    m:    message});
        endcase
    endfunction

    // SLH only: MGF1-SHA-256 counter-0 call over R || PK.seed || inner digest
    function automatic logic [MAX_MSG_HASH2_BITS-1:0] msg_hash2_msg(
        input logic [KCTX_W-1:0] kctx,
        input logic [255:0]    rand_beat,
        input logic [255:0]    inner);
        return MAX_MSG_HASH2_BITS'(slh_pkg::slh_mgf_msg_t'{
                    r:     rand_beat[255 -: slh_pkg::SLH_NW],
                    seed:  kctx[KCTX_W-1 -: slh_pkg::SLH_NW],
                    inner: inner,
                    ctr:   32'h0});
    endfunction

    // OTS chain step: LMS H(I||q||i||j||tmp), SLH F(ADRSc(WOTS_HASH)||tmp)
    function automatic logic [MAX_CHAIN_MSG_BITS-1:0] ots_chain_msg(
        input sch_e s, input logic [KCTX_W-1:0] kctx, input ctrl_t c, input logic [255:0] tmp);
        case (s)
            SCHEME_LMS: return MAX_CHAIN_MSG_BITS'(hss_pkg::lms_chain_msg_t'{
                    i: kctx, q: ctrl2q(c), chain: {9'b0, c.chain}, step: c.step, tmp: tmp});
            default:    return MAX_CHAIN_MSG_BITS'(slh_pkg::slh_f_msg_t'{
                    adrs: ctrl2adrs(c, slh_pkg::ADRS_WOTS_HASH, 1'b0),
                    m1:   tmp[255 -: slh_pkg::SLH_NW]});
        endcase
    endfunction

    // SLH only: FORS leaf F(ADRSc(FORS_TREE, height 0, index)||sk)
    function automatic logic [MAX_CHAIN_MSG_BITS-1:0] fors_leaf_msg(
        input ctrl_t c, input logic [255:0] sk);
        return MAX_CHAIN_MSG_BITS'(slh_pkg::slh_f_msg_t'{
                    adrs: ctrl2adrs(c, slh_pkg::ADRS_FORS_TREE, 1'b0),
                    m1:   sk[255 -: slh_pkg::SLH_NW]});
    endfunction

    // First-block prefix of the endpoint accumulation: LMS I||q||D_PBLC,
    // SLH ADRSc(WOTS_PK) or ADRSc(FORS_ROOTS)
    function automatic logic [ACC_PREFIX_W-1:0] ots_pk_prefix(
        input sch_e s, input logic [KCTX_W-1:0] kctx, input ctrl_t c, input bit fors);
        case (s)
            SCHEME_LMS: return hss_pkg::lms_prefix_t'{i: kctx, q: ctrl2q(c), d: hss_pkg::D_PBLC};
            default:    return ctrl2adrs(c, fors ? slh_pkg::ADRS_FORS_ROOTS
                                                : slh_pkg::ADRS_WOTS_PK, 1'b0);
        endcase
    endfunction

    // LMS only: leaf H(I||q||D_LEAF||Kc)
    function automatic logic [MAX_LEAF_MSG_BITS-1:0] leaf_msg(
        input logic [KCTX_W-1:0] kctx, input ctrl_t c, input logic [255:0] kc);
        return MAX_LEAF_MSG_BITS'(hss_pkg::lms_leaf_msg_t'{
                    pre: hss_pkg::lms_prefix_t'{i: kctx, q: ctrl2q(c), d: hss_pkg::D_LEAF},
                    kc:  kc});
    endfunction

    // Merkle interior node: LMS H(I||node||D_INTR||l||r),
    // SLH H(ADRSc(TREE | FORS_TREE, height, parent)||l||r)
    function automatic logic [MAX_TREE_MSG_BITS-1:0] ots_tree_join_msg(
        input sch_e s, input logic [KCTX_W-1:0] kctx, input ctrl_t c, input bit fors,
        input logic [255:0] left, input logic [255:0] right);
        case (s)
            SCHEME_LMS: return MAX_TREE_MSG_BITS'(hss_pkg::lms_intr_msg_t'{
                    i: kctx, node: ctrl2node(c), d: hss_pkg::D_INTR, left: left, right: right});
            default:    return MAX_TREE_MSG_BITS'(slh_pkg::slh_tree_msg_t'{
                    adrs:  ctrl2adrs(c, fors ? slh_pkg::ADRS_FORS_TREE : slh_pkg::ADRS_TREE, 1'b1),
                    left:  left[255 -: slh_pkg::SLH_NW],
                    right: right[255 -: slh_pkg::SLH_NW]});
        endcase
    endfunction

    // -------------------------------------------------------------------------
    // Winternitz digits of the message being signed (combinational)
    //
    // LMS: 32 byte digits of the 256-bit Q, then the 16-bit checksum
    // sum(255 - d) as two bytes (w = 8, no shift). SLH: 32 nibbles of the
    // top 128 bits, then csum = sum(15 - d) left-shifted by 4 and taken as
    // three nibbles. Returned at the LMS width.
    // -------------------------------------------------------------------------

    function automatic logic [7:0] ots_digit(input sch_e s, input logic [255:0] msg,
                                             input int unsigned i);
        logic [15:0] csum;
        csum = '0;
        case (s)
            SCHEME_LMS: begin
                if (i < 32) return msg[255 - 8*i -: 8];
                for (int k = 0; k < 32; k++) csum += 16'd255 - 16'(msg[255 - 8*k -: 8]);
                return (i == 32) ? csum[15:8] : csum[7:0];
            end
            default: begin
                logic [8:0] csum9;   // sum(15 - d) over 32 nibbles <= 480
                csum9 = '0;
                if (i < 32) return {4'b0, msg[255 - 4*i -: 4]};
                for (int k = 0; k < 32; k++) csum9 += 9'd15 - 9'(msg[255 - 4*k -: 4]);
                case (i)
                    32:      return {4'b0, 3'b0, csum9[8]};
                    33:      return {4'b0, csum9[7:4]};
                    default: return {4'b0, csum9[3:0]};
                endcase
            end
        endcase
    endfunction

    /* verilator lint_on UNUSEDSIGNAL */

endpackage
