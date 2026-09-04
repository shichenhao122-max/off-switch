// Top-level testbench: security_block with CRYPTO_TYPE=2 (SLH-DSA).
//
// The TRNG seed is held loaded so the published nonce equals the seed
// exactly, letting the pre-signed license vectors (generated over that same
// value by tools/gen_slh_vectors.py) verify against the live nonce. The seed
// is released once the license stream starts, so the post-acceptance nonce
// rotates to a fresh value.
//
//   T1  fail-secure reset      allowance 0, enabled 0
//   T2  workload blocked       gated result is 0
//   T3  nonce published        nonce_ready, nonce == seed
//   T4  tampered license       rejected: allowance 0, same nonce retained
//   T5  genuine license        accepted: allowance > 0, nonce rotated
//   T6  workload unblocked     8-bit add passes through
//   T7  replay after rotation  the spent license is rejected against the
//                              rotated nonce (no second increment)
//   T8/T9  2-of-2 signers      second DUT with NUM_SIGNERS=2: signer-0 license
//                              holds the nonce with allowance unchanged, the
//                              signer-1 license (vectors slh128s_s1) completes
//                              the round and increments

module tb (
    input logic clk,
    input logic rst_n
);
    import arith_pkg::*;
    import slh_pkg::*;

    localparam int unsigned NUM_BEATS = SLH_SIG_ELEMS;
    localparam int unsigned VERIFY_TIMEOUT = 3_000_000;

    // Must match the message gen_slh_vectors.py signed (see vectors meta.json)
    logic [255:0] msg_mem [0:0];
    logic [SLH_BEAT_W-1:0] beats    [0:NUM_BEATS-1];
    logic [SLH_BEAT_W-1:0] beats_s1 [0:NUM_BEATS-1];

    initial begin
        $readmemh("tb/vectors/slh128s/license_beats.hex", beats);
        $readmemh("tb/vectors/slh128s/message.hex", msg_mem);
        $readmemh("tb/vectors/slh128s_s1/license_beats.hex", beats_s1);
    end

    // -------------------------------------------------------------------------
    // DUT
    // -------------------------------------------------------------------------

    logic                  license_valid = 1'b0;
    wire                   license_ready;
    logic [SLH_BEAT_W-1:0] license_data  = '0;
    logic                  workload_valid = 1'b0;
    logic [7:0]            workload_a = '0, workload_b = '0;
    logic [WIDTH-1:0]      trng_seed = '0;
    logic                  trng_load_seed = 1'b0;
    wire  [WIDTH-1:0]      nonce;
    wire                   nonce_ready;
    wire  [7:0]            workload_result;
    wire                   result_valid;
    wire  [63:0]           allowance;
    wire                   enabled;

    security_block #(
        .CRYPTO_TYPE (2),
        .NUM_SIGNERS (1)
    ) u_dut (
        .clk             (clk),
        .rst_n           (rst_n),
        .license_valid   (license_valid),
        .license_ready   (license_ready),
        .license_data    (license_data),
        .workload_valid  (workload_valid),
        .workload_a      (workload_a),
        .workload_b      (workload_b),
        .trng_seed       (trng_seed),
        .trng_load_seed  (trng_load_seed),
        .nonce           (nonce),
        .nonce_ready     (nonce_ready),
        .workload_result (workload_result),
        .result_valid    (result_valid),
        .allowance       (allowance),
        .enabled         (enabled)
    );

    // -------------------------------------------------------------------------
    // Second DUT: 2-of-2 signers (exercises SLH_KEYS[1] and signer rotation)
    // -------------------------------------------------------------------------

    logic                  license2_valid = 1'b0;
    wire                   license2_ready;
    logic [SLH_BEAT_W-1:0] license2_data  = '0;
    logic [WIDTH-1:0]      trng2_seed = '0;
    logic                  trng2_load = 1'b0;
    wire  [WIDTH-1:0]      nonce2;
    wire                   nonce2_ready;
    wire  [63:0]           allowance2;
    wire                   enabled2;

    security_block #(
        .CRYPTO_TYPE (2),
        .NUM_SIGNERS (2)
    ) u_dut2 (
        .clk             (clk),
        .rst_n           (rst_n),
        .license_valid   (license2_valid),
        .license_ready   (license2_ready),
        .license_data    (license2_data),
        .workload_valid  (1'b0),
        .workload_a      (8'b0),
        .workload_b      (8'b0),
        .trng_seed       (trng2_seed),
        .trng_load_seed  (trng2_load),
        .nonce           (nonce2),
        .nonce_ready     (nonce2_ready),
        /* verilator lint_off PINCONNECTEMPTY */
        .workload_result (),
        .result_valid    (),
        /* verilator lint_on PINCONNECTEMPTY */
        .allowance       (allowance2),
        .enabled         (enabled2)
    );

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    int unsigned n_pass = 0, n_fail = 0;

    task automatic check(input string name, input bit ok);
        if (ok) begin n_pass++; $display("PASS  [%s]", name); end
        else    begin n_fail++; $display("FAIL  [%s]", name); end
    endtask

    // Stream one full license; release the TRNG seed as the stream starts.
    task automatic send_license(input int tamper_beat, input int tamper_bit);
        int unsigned sent = 0;
        int unsigned guard = 0;
        logic [SLH_BEAT_W-1:0] beat;
        trng_load_seed = 1'b0;
        while (sent < NUM_BEATS && guard < VERIFY_TIMEOUT) begin
            beat = beats[sent];
            if (int'(sent) == tamper_beat) beat = beat ^ (128'h1 << tamper_bit);
            license_valid = 1'b1;
            license_data  = beat;
            @(posedge clk);
            if (license_valid && license_ready) sent++;
            @(negedge clk);
            guard++;
        end
        license_valid = 1'b0;
        if (sent != NUM_BEATS) $fatal(1, "license stream stalled at %0d/%0d", sent, NUM_BEATS);
    endtask

    // Wait for the verification cycle to end (nonce_ready rising again)
    task automatic wait_cycle_done();
        int unsigned guard = 0;
        @(negedge clk);
        while (!nonce_ready && guard < VERIFY_TIMEOUT) begin
            @(negedge clk);
            guard++;
        end
        if (!nonce_ready) $fatal(1, "verification did not complete");
    endtask

    task automatic send_license2(input bit use_s1);
        int unsigned sent = 0;
        int unsigned guard = 0;
        while (sent < NUM_BEATS && guard < VERIFY_TIMEOUT) begin
            license2_valid = 1'b1;
            license2_data  = use_s1 ? beats_s1[sent] : beats[sent];
            @(posedge clk);
            if (license2_valid && license2_ready) sent++;
            @(negedge clk);
            guard++;
        end
        license2_valid = 1'b0;
        if (sent != NUM_BEATS) $fatal(1, "dut2 license stream stalled at %0d/%0d", sent, NUM_BEATS);
    endtask

    task automatic wait_cycle_done2();
        int unsigned guard = 0;
        @(negedge clk);
        while (!nonce2_ready && guard < VERIFY_TIMEOUT) begin
            @(negedge clk);
            guard++;
        end
        if (!nonce2_ready) $fatal(1, "dut2 verification did not complete");
    endtask

    // -------------------------------------------------------------------------
    // Test sequence
    // -------------------------------------------------------------------------

    logic [255:0] first_nonce;
    logic [63:0]  allow_save;

    initial begin
        int unsigned guard;

        wait (rst_n === 1'b0);
        // Hold the seeds: the TRNG counters stay equal to the signed message
        trng_seed      = msg_mem[0];
        trng_load_seed = 1'b1;
        trng2_seed     = msg_mem[0];
        trng2_load     = 1'b1;   // held for the whole 2-of-2 round
        wait (rst_n === 1'b1);

        @(negedge clk);
        check("T1 fail-secure reset", (allowance == '0) && !enabled);

        workload_valid = 1'b1;
        workload_a = 8'd50; workload_b = 8'd30;
        @(negedge clk); @(negedge clk);
        check("T2 workload blocked", result_valid && (workload_result == '0));
        workload_valid = 1'b0;

        guard = 0;
        while (!nonce_ready && guard < 300) begin @(negedge clk); guard++; end
        check("T3 nonce published", nonce_ready && (nonce == msg_mem[0]));
        first_nonce = nonce;

        // T4: tampered license — rejected, allowance unchanged, nonce retained
        // (a rejected round never requests a new nonce, so no seed games are
        // needed for the retention check).
        send_license(20, 7);
        wait_cycle_done();
        check("T4 tampered license rejected",
              (allowance == '0) && (nonce == first_nonce));

        // T5: genuine license — accepted; seed released so the nonce rotates
        send_license(-1, 0);
        wait_cycle_done();
        check("T5 genuine license accepted",
              (allowance != '0) && enabled && (nonce != first_nonce));

        workload_valid = 1'b1;
        workload_a = 8'd100; workload_b = 8'd26;
        @(negedge clk); @(negedge clk);
        check("T6 workload unblocked", result_valid && (workload_result == 8'd126));
        workload_valid = 1'b0;

        // T7: replay — the spent license is for the old nonce; against the
        // rotated one it must fail, and the allowance must only have decayed.
        allow_save = allowance;
        send_license(-1, 0);
        wait_cycle_done();
        check("T7 replay after rotation rejected",
              (allowance <= allow_save) && nonce_ready);

        // T8/T9: 2-of-2 signer round on the second DUT (same nonce, both
        // signers' licenses; increments only after the last signer).
        begin : dual_signer
            int unsigned guard = 0;
            while (!nonce2_ready && guard < 300) begin @(negedge clk); guard++; end
            if (nonce2 != msg_mem[0]) $fatal(1, "dut2 nonce != seed");
            send_license2(1'b0);           // signer 0
            wait_cycle_done2();
            check("T8 signer-0 of 2 held", (allowance2 == '0) && (nonce2 == msg_mem[0]));
            send_license2(1'b1);           // signer 1 (SLH_KEYS[1])
            wait_cycle_done2();
            check("T9 signer-1 of 2 incremented", (allowance2 != '0) && enabled2);
        end

        $display("----------------------------------------");
        $display("tb_top_slh: %0d passed, %0d failed", n_pass, n_fail);
        if (n_fail != 0) $fatal(1, "tb_top_slh FAILED");
        $finish;
    end

endmodule
