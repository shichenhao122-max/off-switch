// Review stress TB: zero-gap back-to-back verifications on slh_verify.
//
// valid is held high continuously across StDone -> StIdle boundaries, so the
// R beat of run N+1 is presented in the same cycle window where run N
// finishes. Runs alternate vector sets (different digit patterns) and include
// a tampered run sandwiched between genuine ones, to expose any state carried
// across runs (blk1, fors_phase, level, step, nidx, T bank/carry/state).

module tb (
    input logic clk,
    input logic rst_n
);
    import slh_pkg::*;

    localparam int unsigned NUM_BEATS = SLH_SIG_ELEMS;  // 491
    localparam int unsigned NUM_RUNS  = 4;
    localparam int unsigned TIMEOUT   = 3_000_000;

    logic [SLH_BEAT_W-1:0] beats_a [0:NUM_BEATS-1];
    logic [SLH_BEAT_W-1:0] beats_b [0:NUM_BEATS-1];
    logic [255:0] msg_a_mem [0:0];
    logic [255:0] msg_b_mem [0:0];

    initial begin
        $readmemh("tb/vectors/slh128s/license_beats.hex", beats_a);
        $readmemh("tb/vectors/slh128s/message.hex", msg_a_mem);
        $readmemh("tb/vectors/slh128s_edge15/license_beats.hex", beats_b);
        $readmemh("tb/vectors/slh128s_edge15/message.hex", msg_b_mem);
    end

    logic [255:0]          message;
    logic                  valid;
    wire                   ready;
    logic [SLH_BEAT_W-1:0] data;
    wire                   verify_done;
    wire                   verif_passed;

    hbsv_verify #(
        .SCH (hbsv_ctrl_pkg::SCHEME_SLH)
    ) u_dut (
        .clk          (clk),
        .rst_n        (rst_n),
        .message      (message),
        .key_ctx      (SLH_KEYS[0].seed),
        .root         (SLH_KEYS[0].root),
        .midstate     (SLH_KEYS[0].midstate),
        .valid        (valid),
        .ready        (ready),
        .data         (data),
        .verify_done  (verify_done),
        .verif_passed (verif_passed)
    );

    // Run schedule: 0 = set A genuine, 1 = set B genuine (different digits),
    // 2 = set A tampered mid-stream (expect reject), 3 = set A genuine again.
    function automatic logic [SLH_BEAT_W-1:0] beat_of(int run, int idx);
        logic [SLH_BEAT_W-1:0] b;
        b = (run == 1) ? beats_b[idx] : beats_a[idx];
        if (run == 2 && idx == 250) b = b ^ (128'h1 << 41);
        return b;
    endfunction

    function automatic logic [255:0] msg_of(int run);
        return (run == 1) ? msg_b_mem[0] : msg_a_mem[0];
    endfunction

    int unsigned run_i, beat_i, cycles;
    int unsigned dones;
    bit exp [0:NUM_RUNS-1];
    int unsigned n_fail = 0;

    initial begin
        exp[0] = 1'b1; exp[1] = 1'b1; exp[2] = 1'b0; exp[3] = 1'b1;
        valid = 1'b0;
        data  = '0;
        message = '0;
        run_i = 0; beat_i = 0; cycles = 0; dones = 0;

        wait (rst_n === 1'b0);
        wait (rst_n === 1'b1);
        repeat (2) @(negedge clk);

        message = msg_of(0);
        // Drive with valid pinned high until all runs' beats are gone.
        while (dones < NUM_RUNS && cycles < TIMEOUT) begin
            if (run_i < NUM_RUNS) begin
                valid = 1'b1;
                data  = beat_of(run_i, beat_i);
            end else begin
                valid = 1'b0;
                data  = '0;
            end
            @(posedge clk);
            if (valid && ready) begin
                beat_i++;
                if (beat_i == NUM_BEATS) begin
                    beat_i = 0;
                    run_i++;
                    // message for the next run may switch as soon as the
                    // previous run's stream is fully consumed (H_msg long done)
                    if (run_i < NUM_RUNS) message = msg_of(run_i);
                end
            end
            if (verify_done) begin
                if (verif_passed !== exp[dones]) begin
                    $display("FAIL  run %0d: verif_passed=%0d expected %0d",
                             dones, verif_passed, exp[dones]);
                    n_fail++;
                end else begin
                    $display("PASS  run %0d: verif_passed=%0d (cycle %0d)",
                             dones, verif_passed, cycles);
                end
                dones++;
            end
            @(negedge clk);
            cycles++;
        end

        if (dones != NUM_RUNS) begin
            $display("FAIL  timeout: %0d/%0d runs done, run_i=%0d beat_i=%0d",
                     dones, NUM_RUNS, run_i, beat_i);
            n_fail++;
        end
        $display("----------------------------------------");
        $display("tb_slh_b2b: %0d failures", n_fail);
        if (n_fail != 0) $fatal(1, "tb_slh_b2b FAILED");
        $finish;
    end

endmodule
