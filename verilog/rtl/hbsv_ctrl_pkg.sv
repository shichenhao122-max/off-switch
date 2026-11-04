// Hash-based signature verifier — shared control bundle.
//
// The verifier's counters as one bundle, so that a scheme package can turn
// them into that scheme's message fields: where the verifier is in the
// hypertree, in the Merkle tree it is walking, in the OTS chain and among
// the FORS trees. The Merkle fields serve the layer's tree and the FORS
// trees alike. A message that needs a value the counters do not hold at
// that step (the key pair's leaf during FORS) takes it as an argument of
// its own rather than a field here.
//
// Each field is sized for the widest scheme the bundle serves; a narrower
// scheme zero-extends into it.

package hbsv_ctrl_pkg;

    // Signature scheme a verifier is elaborated for
    typedef enum int unsigned {
        SCHEME_HSS      = 0,   // RFC 8554 HSS/LMS
        SCHEME_SLH_128S = 1,   // FIPS 205 SLH-DSA-SHA2-128s
        SCHEME_MAX      = 2    // number of schemes; loops over them end here
    } sch_e;

    // Field widths; the verifier's counters are declared with the same ones
    localparam int unsigned HT_LAYER_W   = 3;
    localparam int unsigned MSS_TREE_W   = 54;
    localparam int unsigned MRKL_LEAF_W  = 32;
    localparam int unsigned MRKL_LEVEL_W = 5;
    localparam int unsigned CHAIN_IDX_W  = 7;
    localparam int unsigned CHAIN_STEP_W = 8;
    localparam int unsigned FORS_TREE_W  = 6;

    typedef struct packed {
        // Hypertree
        logic [HT_LAYER_W-1:0]   ht_layer;    // layer, counted from the top: 0 holds the
                                              // public key, the highest signs the message
        logic [MSS_TREE_W-1:0]   mss_tree;    // SLH: index of the tree in its layer (HSS: the
                                              // layer has one tree, 0)
        // Merkle walk, in the layer's tree or in a FORS tree
        logic [MRKL_LEAF_W-1:0]  mrkl_leaf;   // leaf the walk starts from: the key pair's, or
                                              // the one the FORS tree reveals
        logic [MRKL_LEVEL_W-1:0] mrkl_level;  // level the walk has reached
        // OTS chain
        logic [CHAIN_IDX_W-1:0]  chain_idx;   // chain
        logic [CHAIN_STEP_W-1:0] chain_step;  // hash step within the chain
        // FORS
        logic [FORS_TREE_W-1:0]  fors_tree;   // tree the Merkle fields are in
    } ctrl_t;

endpackage
