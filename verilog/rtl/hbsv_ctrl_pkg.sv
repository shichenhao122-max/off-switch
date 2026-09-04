// Hash-based signature verifier — shared control bundle.
//
// One counter set serves both schemes; every field is sized to the wider of
// the two. The scheme packages (hss_pkg, slh_pkg) own the byte layouts, and
// hbsv_schs_pkg turns this bundle into each scheme's message fields.

package hbsv_ctrl_pkg;

    typedef enum int unsigned {
        SCHEME_LMS = 0,   // RFC 8554 HSS/LMS
        SCHEME_SLH = 1    // FIPS 205 SLH-DSA (SPHINCS+)
    } sch_e;

    typedef struct packed {
        logic [2:0]  layer;   // hypertree layer in processing order; 0 signs the message
        logic [6:0]  chain;   // OTS chain index (LMS 0..33, SLH 0..34); FORS tree index (0..13)
        logic [7:0]  step;    // OTS hash address (LMS 0..255, SLH 0..15)
        logic [4:0]  level;   // Merkle level within the current tree
        logic [31:0] nidx;    // Merkle node index: LMS node number (2^h bit set), SLH tree index
        logic [31:0] leaf;    // leaf index: LMS q, SLH idx_leaf (key-pair address)
        logic [53:0] tree;    // SLH idx_tree (tree address); zero for LMS
    } ctrl_t;

endpackage
