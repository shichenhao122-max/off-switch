// Hash-based signature verification — HSS/LMS (RFC 8554) or SLH-DSA
// (FIPS 205, SPHINCS+), selected by the SCH parameter at elaboration.
//
// One control structure serves both schemes: a single shared SHA-256 core,
// one sequencer, and a register file whose widths derive from the scheme.
// Everything scheme-specific — hash-message byte layouts, digit geometry,
// tree shapes — comes from hbsv_schs_pkg as constants and constant
// functions of SCH, so the module body is the same for both.
//
//   Idle → [LMS: Hdr → MsgHash | SLH: MsgHash → MsgHash2 → Fors...]
//        → Wots (Load/Hash, endpoints absorbed in flight) → AccFinal
//        → [LMS: Leaf] → Mrkl × tree height → next layer | Done
//
// Shared machinery:
//   - OTS chain walk: load an element, hash digit-by-digit to the endpoint.
//   - Endpoint accumulation (LMS Kc, SLH T_k / T_len): elements are banked
//     until a 512-bit block completes, absorbed into a suspended hash via
//     the wrapper's save/restore, and the state re-saved. Both schemes put a
//     22-byte prefix before the element stream, so the block geometry is one
//     formula of the element width (hbsv_schs_pkg).
//   - Merkle walk: sibling off the licence stream, parity order, index
//     halving. Shared by LMS trees, SLH FORS trees and SLH XMSS trees.
//
// SLH-only: H_msg (inner hash + MGF1) and its digest split, the FORS
// phase; every F/H/T call resumes from the precomputed midstate of the
// constant first block PK.seed || 0^48. LMS-only: per-layer header beats,
// the per-layer Q hash (over the message, or the serialised public key of
// the layer below), and the leaf hash after Kc.
//
// Protocol: hold message stable throughout; supply beats on
// valid/ready/data (first beat starts verification, no start signal);
// verify_done pulses with verif_passed valid in that cycle. Beats consumed
// by a register (header, chain element, FORS secret) are taken at once;
// beats read straight into a hash block (randomizer, auth-path siblings)
// are held by the producer and released in the cycle the core captures the
// last block that reads them (sha2_wrap's taken). A licence is exactly the
// scheme's element count; the engine cannot observe stream length.

module hbsv_verify
    import arith_pkg::*;
    import hbsv_ctrl_pkg::*;
    import hbsv_schs_pkg::*;
#(
    parameter  sch_e        SCH    = SCHEME_LMS,
    localparam int unsigned DW     = digest_w(SCH),   // node / element / beat width
    localparam int unsigned BEAT_W = DW
)(
    input  logic               clk,
    input  logic               rst_n,

    input  logic [WIDTH-1:0]   message,    // nonce being verified
    input  logic [KCTX_W-1:0]  key_ctx,    // LMS: top-tree identifier I; SLH: PK.seed
    input  logic [DW-1:0]      root,       // LMS: root public key; SLH: PK.root
    input  logic [255:0]       midstate,   // SLH: SHA-256 state of PK.seed || 0^48

    input  logic               valid,
    output logic               ready,
    input  logic [BEAT_W-1:0]  data,

    output logic               verify_done,
    output logic               verif_passed
);

    // -------------------------------------------------------------------------
    // Scheme-derived constants
    // -------------------------------------------------------------------------

    localparam bit          IS_SLH    = (SCH == SCHEME_SLH);
    localparam bit          IS_LMS    = (SCH == SCHEME_LMS);
    localparam bit          MIDSTATE  = uses_midstate(SCH);
    localparam bit          LEAF_HASH = has_leaf_hash(SCH);

    localparam int unsigned DIGIT_W   = digit_w(SCH);
    localparam int unsigned LEN       = ots_len(SCH);
    localparam int unsigned STEP_MAX  = step_max(SCH);
    localparam logic [7:0]  DIGIT_MAX = 8'((1 << DIGIT_W) - 1);

    localparam int unsigned LAYERS    = layers(SCH);
    localparam int unsigned TREE_H    = tree_h(SCH);
    localparam int unsigned FORS_K    = fors_k(SCH);
    localparam int unsigned FORS_H    = fors_h(SCH);

    localparam int unsigned ACC_FIRST = acc_first_full(SCH);
    localparam int unsigned ACC_MID   = acc_mid_full(SCH);
    localparam int unsigned CARRY_W   = acc_carry_w(SCH);
    localparam int unsigned MS_BITS   = midstate_bits(SCH);

    // Register widths
    localparam int unsigned MSG_W    = IS_SLH ? slh_pkg::SLH_MD_W : WIDTH;   // 168 / 256
    localparam int unsigned LEAF_W   = IS_SLH ? slh_pkg::SLH_IDX_LEAF_W : 32;
    localparam int unsigned TREE_W   = IS_SLH ? slh_pkg::SLH_IDX_TREE_W : 1;
    localparam int unsigned NIDX_W   = IS_SLH ? 16 : 32;
    localparam int unsigned LEVEL_W  = 5;
    localparam int unsigned CHAIN_W  = 6;
    localparam int unsigned LAYER_W  = (LAYERS > 1) ? $clog2(LAYERS) : 1;
    localparam int unsigned POS_W    = $clog2(ACC_MID + 1);

    // Message widths, block counts and padding (elaboration-time)
    localparam int unsigned MH_W    = msg_hash_bits(SCH, 1'b0);     // LMS Q (message) / SLH inner
    localparam int unsigned MHS_W   = msg_hash_bits(SCH, 1'b1);     // LMS Q (serialised pubkey)
    localparam int unsigned MH2_W   = IS_SLH ? msg_hash2_bits(SCH) : 1;
    localparam int unsigned CH_W    = chain_msg_bits(SCH);
    localparam int unsigned LF_W    = IS_LMS ? leaf_msg_bits(SCH) : 1;
    localparam int unsigned TR_W    = tree_msg_bits(SCH);

    localparam int unsigned MH_NB   = calc_sha_blocks(MH_W);
    localparam int unsigned MHS_NB  = calc_sha_blocks(MHS_W);
    localparam int unsigned MH2_NB  = calc_sha_blocks(MH2_W);
    localparam int unsigned TR_NB   = calc_sha_blocks(TR_W);
    // chain, leaf, FORS-leaf and every accumulator block are single blocks
    localparam int unsigned NB_A    = (MHS_NB > MH_NB) ? MHS_NB : MH_NB;
    localparam int unsigned NB_B    = (MH2_NB > TR_NB) ? MH2_NB : TR_NB;
    localparam int unsigned MAX_NB  = (NB_A > NB_B) ? NB_A : NB_B;
    localparam int unsigned BLK_W   = (MAX_NB > 1) ? $clog2(MAX_NB) : 1;

    localparam int unsigned MH_PZ   = calc_sha_pad_zeros(MH_W);
    localparam int unsigned MHS_PZ  = calc_sha_pad_zeros(MHS_W);
    localparam int unsigned MH2_PZ  = calc_sha_pad_zeros(MH2_W);
    localparam int unsigned CH_PZ   = calc_sha_pad_zeros(CH_W);
    localparam int unsigned LF_PZ   = calc_sha_pad_zeros(LF_W);
    localparam int unsigned TR_PZ   = calc_sha_pad_zeros(TR_W);

    // -------------------------------------------------------------------------
    // FSM
    // -------------------------------------------------------------------------

    typedef enum logic [3:0] {
        StIdle,
        StHdr,                    // LMS: per-layer header beat {q, sub_I}
        StMsgHash,                // LMS: Q; SLH: H_msg inner
        StMsgHash2,               // SLH: MGF1
        StForsLoad, StForsLeaf,   // SLH
        StWotsLoad, StWotsHash,
        StAbsorb, StAccFinal,
        StLeaf,                   // LMS
        StMrklHash,
        StDone
    } state_e;

    state_e st_q, st_d;

    // -------------------------------------------------------------------------
    // Registers
    // -------------------------------------------------------------------------

    logic [DW-1:0]      node_q, node_d;          // current node / chain value
    logic [MSG_W-1:0]   msg_q, msg_d;            // LMS Q digest; SLH md, then the WOTS message
    logic [LEAF_W-1:0]  leaf_q, leaf_d;          // LMS q; SLH idx_leaf
    logic [TREE_W-1:0]  tree_q, tree_d;          // SLH idx_tree
    logic [NIDX_W-1:0]  nidx_q, nidx_d;
    logic [LEVEL_W-1:0] level_q, level_d;
    logic [CHAIN_W-1:0] chain_q, chain_d;        // OTS chain / FORS tree index
    logic [DIGIT_W-1:0] step_q, step_d;
    logic [LAYER_W-1:0] layer_q, layer_d;        // processing order, 0 = message layer
    logic [BLK_W-1:0]   blk_q, blk_d;            // block within a multi-block message
    logic               fors_q, fors_d;          // SLH FORS phase

    // LMS key context: this layer's sub_I and the one below (the layer above
    // signs the serialised public key of the layer below).
    logic [KCTX_W-1:0]  kctx_q, kctx_d, pkctx_q, pkctx_d;

    // Endpoint accumulation
    logic [255:0]       acc_state_q;             // suspended hash state (SLH: parks H_msg inner)
    logic [DW-1:0]      acc_bank_q [ACC_MID];
    logic [CARRY_W-1:0] acc_carry_q;
    logic [POS_W-1:0]   acc_pos_q, acc_pos_d;    // elements banked since the last absorb
    logic               acc_first_q, acc_first_d;

    // -------------------------------------------------------------------------
    // SHA-256 wrapper
    // -------------------------------------------------------------------------

    logic         sha_valid;
    logic [511:0] sha_block;
    logic         sha_last, sha_save, sha_restore;
    logic [255:0] sha_ctx;
    wire          sha_ready, sha_taken;
    wire  [255:0] sha_digest;

    sha2_wrap u_sha256 (
        .clk (clk), .rst_n (rst_n),
        .valid (sha_valid), .block (sha_block), .last (sha_last),
        .save (sha_save), .restore (sha_restore), .ctx (sha_ctx),
        .ready (sha_ready), .taken (sha_taken), .digest (sha_digest)
    );

    wire hash_complete = sha_last && sha_ready;
    wire [DW-1:0] trunc_digest = sha_digest[255 -: DW];   // Trunc_n = leftmost bytes

    // -------------------------------------------------------------------------
    // Widened views for the scheme functions (values left-aligned in 256 bits)
    // -------------------------------------------------------------------------

    logic [255:0] node256, data256, msg256;
    if (DW < 256) begin : gen_widen
        assign node256 = {node_q, {(256-DW){1'b0}}};
        assign data256 = {data,   {(256-DW){1'b0}}};
    end else begin : gen_full
        assign node256 = node_q;
        assign data256 = data;
    end
    if (MSG_W < 256) begin : gen_widen_msg
        assign msg256 = {msg_q, {(256-MSG_W){1'b0}}};
    end else begin : gen_full_msg
        assign msg256 = msg_q;
    end

    // Effective key context: LMS uses the port for the top tree and the
    // header-supplied sub_I below it; SLH's PK.seed is the port throughout.
    wire is_top_layer = (int'(layer_q) == LAYERS - 1);
    wire [KCTX_W-1:0] kctx = (IS_LMS && !is_top_layer) ? kctx_q : key_ctx;

    wire ctrl_t c = '{layer: 3'(layer_q), chain: 7'(chain_q), step: 8'(step_q),
                      level: 5'(level_q), nidx: 32'(nidx_q), leaf: 32'(leaf_q),
                      tree: 54'(tree_q)};

    // -------------------------------------------------------------------------
    // Digits
    // -------------------------------------------------------------------------

    wire [7:0] cur_digit = ots_digit(SCH, msg256, int'(chain_q));

    // SLH FORS digit of tree chain_q: a-bit slices of md, MSB first
    logic [slh_pkg::SLH_A-1:0] fors_digit;
    always_comb begin
        fors_digit = '0;
        if (IS_SLH) begin
            for (int i = 0; i < slh_pkg::SLH_K; i++) begin
                if (int'(chain_q) == i)
                    fors_digit = msg_q[MSG_W-1 - slh_pkg::SLH_A*i -: slh_pkg::SLH_A];
            end
        end
    end

    // -------------------------------------------------------------------------
    // Hash messages — built from the scheme package, padded at elaboration
    // -------------------------------------------------------------------------

    wire is_sub_q = IS_LMS && (layer_q != '0);   // LMS upper layer: Q over the serialised pubkey

    wire [MH_W-1:0]  mh_msg  = MH_W'(msg_hash_msg(SCH, kctx, {root, {(256-DW){1'b0}}}, c, data256,
                                                  message, 1'b0, pkctx_q, node256));
    wire [MHS_W-1:0] mhs_msg = MHS_W'(msg_hash_msg(SCH, kctx, {root, {(256-DW){1'b0}}}, c, data256,
                                                   message, 1'b1, pkctx_q, node256));
    wire [MH2_W-1:0] mh2_msg = MH2_W'(msg_hash2_msg(kctx, data256, acc_state_q));
    wire [CH_W-1:0]  ch_msg  = CH_W'(ots_chain_msg(SCH, kctx, c, node256));
    wire [CH_W-1:0]  fl_msg  = CH_W'(fors_leaf_msg(c, node256));
    wire [LF_W-1:0]  lf_msg  = LF_W'(leaf_msg(kctx, c, node256));

    logic [255:0] left256, right256;
    assign {left256, right256} = nidx_q[0] ? {data256, node256} : {node256, data256};
    wire [TR_W-1:0]  tr_msg  = TR_W'(ots_tree_join_msg(SCH, kctx, c, fors_q, left256, right256));

    // Length fields count the precomputed midstate block where one applies
    wire [MH_NB*512-1:0]  mh_pad  = {mh_msg,  1'b1, {MH_PZ{1'b0}},  64'(MH_W)};
    wire [MHS_NB*512-1:0] mhs_pad = {mhs_msg, 1'b1, {MHS_PZ{1'b0}}, 64'(MHS_W)};
    wire [MH2_NB*512-1:0] mh2_pad = {mh2_msg, 1'b1, {MH2_PZ{1'b0}}, 64'(MH2_W)};
    wire [511:0]          ch_pad  = {ch_msg,  1'b1, {CH_PZ{1'b0}},  64'(CH_W + MS_BITS)};
    wire [511:0]          fl_pad  = {fl_msg,  1'b1, {CH_PZ{1'b0}},  64'(CH_W + MS_BITS)};
    wire [511:0]          lf_pad  = {lf_msg,  1'b1, {LF_PZ{1'b0}},  64'(LF_W)};
    wire [TR_NB*512-1:0]  tr_pad  = {tr_msg,  1'b1, {TR_PZ{1'b0}},  64'(TR_W + MS_BITS)};

    // -------------------------------------------------------------------------
    // Endpoint accumulation blocks
    //
    // The element being absorbed sits in node_q: its top 80 bits close the
    // block, its low CARRY_W bits become the next carry. The first block of
    // an accumulation starts with the 22-byte prefix and ACC_FIRST banked
    // elements; later blocks with the carry and ACC_MID.
    // -------------------------------------------------------------------------

    wire [ACC_PREFIX_W-1:0] acc_prefix = ots_pk_prefix(SCH, kctx, c, fors_q);

    logic [ACC_MID*DW-1:0] bank_flat;             // bank[0] in the MSBs
    always_comb begin
        for (int i = 0; i < ACC_MID; i++)
            bank_flat[ACC_MID*DW-1 - i*DW -: DW] = acc_bank_q[i];
    end

    localparam int unsigned FIRST_BANK_W = ACC_FIRST * DW;
    wire [511:0] acc_first_blk = {acc_prefix, bank_flat[ACC_MID*DW-1 -: FIRST_BANK_W],
                                  node_q[DW-1 -: ACC_HEAD_W]};
    wire [511:0] acc_mid_blk   = {acc_carry_q, bank_flat, node_q[DW-1 -: ACC_HEAD_W]};

    // Final padding block: the carry plus the elements banked after the last
    // absorb. Both counts are elaboration-time per accumulation (OTS
    // endpoints / FORS roots), so each layout is a constant; one fits in a
    // block in every case.
    localparam int unsigned TAIL_OTS  = acc_tail_elems(SCH, LEN);
    localparam int unsigned TAIL_FORS = (FORS_K > 0) ? acc_tail_elems(SCH, FORS_K) : 0;
    localparam logic [63:0] LEN_OTS   = 64'(acc_msg_bits(SCH, LEN));
    localparam logic [63:0] LEN_FORS  = 64'(acc_msg_bits(SCH, FORS_K));

    function automatic logic [511:0] acc_final_layout(
        input int unsigned          tail,
        input logic [63:0]          len,
        input logic [CARRY_W-1:0]   carry,
        input logic [ACC_MID*DW-1:0] banks);
        logic [511:0] v;
        v = '0;
        v[511 -: CARRY_W] = carry;
        for (int i = 0; i < ACC_MID; i++)
            if (i < tail) v[511 - CARRY_W - i*DW -: DW] = banks[ACC_MID*DW-1 - i*DW -: DW];
        v[511 - CARRY_W - tail*DW] = 1'b1;
        v[63:0] = len;
        return v;
    endfunction

    wire [511:0] acc_final_ots  = acc_final_layout(TAIL_OTS,  LEN_OTS,  acc_carry_q, bank_flat);
    wire [511:0] acc_final_fors = acc_final_layout(TAIL_FORS, LEN_FORS, acc_carry_q, bank_flat);
    wire [511:0] acc_final_blk  = fors_q ? acc_final_fors : acc_final_ots;

    // -------------------------------------------------------------------------
    // Block selection, block counter, SHA control
    // -------------------------------------------------------------------------

    int unsigned num_blocks;

    // Block i of a padded multi-block message (constant slices, NB-way mux)
    always_comb begin
        num_blocks = 1;
        sha_block  = '0;

        unique case (st_q)
            StMsgHash: begin
                if (is_sub_q) begin
                    num_blocks = MHS_NB;
                    for (int i = 0; i < MHS_NB; i++)
                        if (int'(blk_q) == i) sha_block = mhs_pad[MHS_NB*512-1 - i*512 -: 512];
                end else begin
                    num_blocks = MH_NB;
                    for (int i = 0; i < MH_NB; i++)
                        if (int'(blk_q) == i) sha_block = mh_pad[MH_NB*512-1 - i*512 -: 512];
                end
            end
            StMsgHash2: begin
                num_blocks = MH2_NB;
                for (int i = 0; i < MH2_NB; i++)
                    if (int'(blk_q) == i) sha_block = mh2_pad[MH2_NB*512-1 - i*512 -: 512];
            end
            StForsLeaf:  sha_block = fl_pad;
            StWotsHash:  sha_block = ch_pad;
            StLeaf:      sha_block = lf_pad;
            StMrklHash: begin
                num_blocks = TR_NB;
                for (int i = 0; i < TR_NB; i++)
                    if (int'(blk_q) == i) sha_block = tr_pad[TR_NB*512-1 - i*512 -: 512];
            end
            StAbsorb:    sha_block = acc_first_q ? acc_first_blk : acc_mid_blk;
            StAccFinal:  sha_block = acc_final_blk;
            default: ;
        endcase
    end

    wire last_blk = (int'(blk_q) == num_blocks - 1);

    assign sha_last    = (st_q == StAbsorb) ? 1'b0 : last_blk;
    assign sha_save    = (st_q == StAbsorb);

    // Resume points: SLH F/H/T calls from the midstate; every absorb after
    // the first (or from the midstate on the first) and the final block from
    // the accumulation state.
    wire fh_state = (st_q == StForsLeaf) || (st_q == StWotsHash) || (st_q == StMrklHash);
    assign sha_restore = (MIDSTATE && fh_state)
                      || ((st_q == StAbsorb) && (!acc_first_q || MIDSTATE))
                      || (st_q == StAccFinal);
    assign sha_ctx     = ((st_q == StAbsorb && !acc_first_q) || (st_q == StAccFinal))
                       ? acc_state_q : midstate;

    // Block counter: multi-block messages only; absorbs are single blocks
    always_comb begin
        blk_d = blk_q;
        if (hash_complete)                                   blk_d = '0;
        else if (sha_ready && !sha_last && (st_q != StAbsorb)) blk_d = blk_q + 1'b1;
    end

    // -------------------------------------------------------------------------
    // Stream handshake
    // -------------------------------------------------------------------------

    // Beats latched into registers are consumed at once
    wire wants_load = (st_q == StHdr) || (st_q == StForsLoad) || (st_q == StWotsLoad);

    // Beats read straight into a hash block are released when the core
    // captures the last block that reads them: the randomizer (LMS Q block
    // 0; SLH MGF1 block 0, after the inner hash read it too) and every
    // auth-path sibling.
    wire rand_last_read = IS_LMS ? ((st_q == StMsgHash)  && (blk_q == '0))
                                 : ((st_q == StMsgHash2) && (blk_q == '0));
    wire bus_consume = sha_taken && (rand_last_read || ((st_q == StMrklHash) && last_blk));

    assign ready = valid && (wants_load || bus_consume);

    // Blocks that read the bus may only be offered while the beat is present
    wire reads_bus = ((st_q == StMsgHash)  && (blk_q == '0))
                  || ((st_q == StMsgHash2) && (blk_q == '0))
                  || (st_q == StMrklHash);

    // -------------------------------------------------------------------------
    // Element completion and accumulation routing
    // -------------------------------------------------------------------------

    wire last_level = fors_q ? (int'(level_q) == FORS_H - 1)
                             : (int'(level_q) == TREE_H - 1);
    wire acc_n_last = fors_q ? (int'(chain_q) == FORS_K - 1)
                             : (int'(chain_q) == LEN - 1);
    wire last_layer = is_top_layer;

    wire wots_skip = (st_q == StWotsLoad) && valid && (cur_digit == DIGIT_MAX);
    wire elem_done = wots_skip
                  || ((st_q == StWotsHash) && hash_complete && (int'(step_q) == STEP_MAX))
                  || (fors_q && (st_q == StMrklHash) && hash_complete && last_level);

    wire [DW-1:0] elem_val = wots_skip ? data : trunc_digest;

    // This element completes a block when the bank already holds the quota
    wire [POS_W:0] acc_quota = acc_first_q ? (POS_W+1)'(ACC_FIRST) : (POS_W+1)'(ACC_MID);
    wire elem_absorbs = ((POS_W+1)'(acc_pos_q) == acc_quota);

    // Where an element-producing loop continues
    wire state_e next_elem_state = fors_q ? StForsLoad : StWotsLoad;

    // -------------------------------------------------------------------------
    // Main FSM
    // -------------------------------------------------------------------------

    always_comb begin
        st_d        = st_q;
        leaf_d      = leaf_q;
        tree_d      = tree_q;
        nidx_d      = nidx_q;
        level_d     = level_q;
        chain_d     = chain_q;
        step_d      = step_q;
        layer_d     = layer_q;
        fors_d      = fors_q;
        kctx_d      = kctx_q;
        pkctx_d     = pkctx_q;
        acc_pos_d   = acc_pos_q;
        acc_first_d = acc_first_q;

        sha_valid    = 1'b0;
        verify_done  = 1'b0;
        verif_passed = 1'b0;

        unique case (st_q)

            StIdle: begin
                if (valid) begin
                    layer_d     = '0;
                    chain_d     = '0;
                    fors_d      = 1'b0;
                    acc_pos_d   = '0;
                    acc_first_d = 1'b1;
                    st_d        = IS_LMS ? StHdr : StMsgHash;
                end
            end

            // LMS: header beat {q, sub_I}; the randomizer beat that follows
            // stays on the bus for the Q hash.
            StHdr: begin
                if (valid) begin
                    leaf_d  = data256[255 -: LEAF_W];
                    pkctx_d = kctx_q;
                    kctx_d  = data256[223 -: KCTX_W];
                    st_d    = StMsgHash;
                end
            end

            StMsgHash: begin
                sha_valid = reads_bus ? valid : 1'b1;
                if (hash_complete) begin
                    if (IS_LMS) begin
                        // Q digest latches into msg (enable below)
                        chain_d     = '0;
                        acc_pos_d   = '0;
                        acc_first_d = 1'b1;
                        st_d        = StWotsLoad;
                    end else begin
                        st_d = StMsgHash2;   // inner digest parks in acc_state
                    end
                end
            end

            StMsgHash2: begin
                sha_valid = reads_bus ? valid : 1'b1;
                if (hash_complete) begin
                    // md / idx_tree / idx_leaf split (enables below)
                    fors_d      = 1'b1;
                    chain_d     = '0;
                    acc_pos_d   = '0;
                    acc_first_d = 1'b1;
                    st_d        = StForsLoad;
                end
            end

            StForsLoad: begin
                if (valid) begin
                    nidx_d  = NIDX_W'({chain_q[3:0], fors_digit});   // tree*2^a + digit
                    level_d = '0;
                    st_d    = StForsLeaf;
                end
            end

            StForsLeaf: begin
                sha_valid = 1'b1;
                if (hash_complete) st_d = StMrklHash;
            end

            StWotsLoad: begin
                if (valid) begin
                    step_d = cur_digit[DIGIT_W-1:0];
                    if (cur_digit == DIGIT_MAX) begin
                        // Already at the endpoint: route the element
                        if (elem_absorbs) st_d = StAbsorb;
                        else begin
                            acc_pos_d = acc_pos_q + 1'b1;
                            chain_d   = chain_q + 1'b1;
                            st_d      = acc_n_last ? StAccFinal : StWotsLoad;
                        end
                    end else begin
                        st_d = StWotsHash;
                    end
                end
            end

            StWotsHash: begin
                sha_valid = 1'b1;
                if (hash_complete) begin
                    if (int'(step_q) != STEP_MAX) begin
                        step_d = step_q + 1'b1;
                    end else if (elem_absorbs) begin
                        st_d = StAbsorb;
                    end else begin
                        acc_pos_d = acc_pos_q + 1'b1;
                        chain_d   = chain_q + 1'b1;
                        st_d      = acc_n_last ? StAccFinal : StWotsLoad;
                    end
                end
            end

            StAbsorb: begin
                sha_valid = 1'b1;
                if (sha_ready) begin   // state and carry latch at this pulse
                    acc_pos_d   = '0;
                    acc_first_d = 1'b0;
                    chain_d     = chain_q + 1'b1;
                    st_d        = acc_n_last ? StAccFinal : next_elem_state;
                end
            end

            StAccFinal: begin
                sha_valid = 1'b1;
                if (hash_complete) begin
                    if (LEAF_HASH) begin
                        st_d = StLeaf;                 // Kc -> leaf hash
                    end else if (fors_q) begin
                        // PK_FORS becomes the message being WOTS-signed
                        fors_d      = 1'b0;
                        chain_d     = '0;
                        acc_pos_d   = '0;
                        acc_first_d = 1'b1;
                        st_d        = StWotsLoad;
                    end else begin
                        // XMSS leaf; walk the tree from idx_leaf
                        nidx_d  = NIDX_W'(leaf_q);
                        level_d = '0;
                        st_d    = StMrklHash;
                    end
                end
            end

            StLeaf: begin
                sha_valid = 1'b1;
                if (hash_complete) begin
                    nidx_d  = NIDX_W'(32'd1 << TREE_H) | NIDX_W'(leaf_q);
                    level_d = '0;
                    st_d    = StMrklHash;
                end
            end

            StMrklHash: begin
                sha_valid = valid;      // the sibling rides on the bus
                if (hash_complete) begin
                    if (!last_level) begin
                        level_d = level_q + 1'b1;
                        nidx_d  = nidx_q >> 1;
                    end else if (fors_q) begin
                        // FORS root: route into T_k
                        if (elem_absorbs) st_d = StAbsorb;
                        else begin
                            acc_pos_d = acc_pos_q + 1'b1;
                            chain_d   = chain_q + 1'b1;
                            st_d      = acc_n_last ? StAccFinal : StForsLoad;
                        end
                    end else if (last_layer) begin
                        st_d = StDone;
                    end else begin
                        // Next hypertree layer
                        layer_d     = layer_q + 1'b1;
                        chain_d     = '0;
                        acc_pos_d   = '0;
                        acc_first_d = 1'b1;
                        if (IS_LMS) begin
                            st_d = StHdr;              // root stays in node for the Q payload
                        end else begin
                            // message <= root (enable below); idx shift (Alg 13)
                            leaf_d = LEAF_W'(tree_q);
                            tree_d = tree_q >> LEAF_W;
                            st_d   = StWotsLoad;
                        end
                    end
                end
            end

            StDone: begin
                verify_done  = 1'b1;
                verif_passed = (node_q == root);
                st_d         = StIdle;
            end

            default: st_d = StIdle;
        endcase
    end

    // -------------------------------------------------------------------------
    // node — element loads and hash results
    // -------------------------------------------------------------------------

    wire node_load = ((st_q == StForsLoad) || (st_q == StWotsLoad)) && valid;
    // AccFinal's digest is the LMS Kc (input of the leaf hash) or the SLH
    // XMSS leaf; PK_FORS goes to msg instead.
    wire node_hash = hash_complete && ((st_q == StForsLeaf) || (st_q == StWotsHash)
                                    || (st_q == StMrklHash) || (st_q == StLeaf)
                                    || ((st_q == StAccFinal) && !(IS_SLH && fors_q)));
    assign node_d = node_load ? data : trunc_digest;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n)                      node_q <= '0;
        else if (node_load || node_hash) node_q <= node_d;
    end

    // -------------------------------------------------------------------------
    // msg — LMS: Q digest per layer; SLH: md, then the running WOTS message
    // -------------------------------------------------------------------------

    wire msg_split = hash_complete && (IS_LMS ? (st_q == StMsgHash) : (st_q == StMsgHash2));
    wire msg_root  = IS_SLH && hash_complete
                  && (((st_q == StAccFinal) && fors_q)
                      || ((st_q == StMrklHash) && last_level && !fors_q && !last_layer));

    if (IS_SLH) begin : gen_msg_slh
        assign msg_d = msg_split ? sha_digest[255 -: MSG_W]
                                 : {trunc_digest, {(MSG_W-DW){1'b0}}};
    end else begin : gen_msg_lms
        assign msg_d = sha_digest;
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n)                     msg_q <= '0;
        else if (msg_split || msg_root) msg_q <= msg_d;
    end

    // -------------------------------------------------------------------------
    // Counters and indices
    // -------------------------------------------------------------------------

    // SLH digest split: idx_tree = bytes 21..27 mod 2^54, idx_leaf = bytes 28..29 mod 2^9
    wire slh_split = IS_SLH && msg_split;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            leaf_q <= '0;
            tree_q <= '0;
        end else if (slh_split) begin
            leaf_q <= LEAF_W'(sha_digest[24:16]);
            tree_q <= TREE_W'(sha_digest[85:32]);
        end else begin
            leaf_q <= leaf_d;
            tree_q <= tree_d;
        end
    end

    // -------------------------------------------------------------------------
    // Accumulation registers
    // -------------------------------------------------------------------------

    wire acc_saved = sha_save && sha_ready;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < ACC_MID; i++) acc_bank_q[i] <= '0;
        end else if (elem_done && !elem_absorbs) begin
            for (int i = 0; i < ACC_MID; i++)
                if (int'(acc_pos_q) == i) acc_bank_q[i] <= elem_val;
        end
    end

    wire acc_state_en = acc_saved || (IS_SLH && (st_q == StMsgHash) && hash_complete);

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            acc_state_q <= '0;
            acc_carry_q <= '0;
        end else begin
            if (acc_state_en) acc_state_q <= sha_digest;
            if (acc_saved)    acc_carry_q <= node_q[CARRY_W-1:0];
        end
    end

    // -------------------------------------------------------------------------
    // Sequential — FSM and counters
    // -------------------------------------------------------------------------

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            st_q        <= StIdle;
            nidx_q      <= '0;
            level_q     <= '0;
            chain_q     <= '0;
            step_q      <= '0;
            layer_q     <= '0;
            blk_q       <= '0;
            fors_q      <= 1'b0;
            kctx_q      <= '0;
            pkctx_q     <= '0;
            acc_pos_q   <= '0;
            acc_first_q <= 1'b1;
        end else begin
            st_q        <= st_d;
            nidx_q      <= nidx_d;
            level_q     <= level_d;
            chain_q     <= chain_d;
            step_q      <= step_d;
            layer_q     <= layer_d;
            blk_q       <= blk_d;
            fors_q      <= fors_d;
            kctx_q      <= kctx_d;
            pkctx_q     <= pkctx_d;
            acc_pos_q   <= acc_pos_d;
            acc_first_q <= acc_first_d;
        end
    end

endmodule
