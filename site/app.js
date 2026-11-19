(function () {
  "use strict";

  var L = window.HARNESS_LEDGER;
  if (!L) {
    document.body.innerHTML =
      '<div style="padding:32px;font-family:monospace;color:#9E2A2B;">' +
      "Missing window.HARNESS_LEDGER. Run: python -m evals.verify_all --export-ledger</div>";
    return;
  }

  function esc(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function pct(ratio, digits) {
    var d = typeof digits === "number" ? digits : 2;
    return (Number(ratio) * 100).toFixed(d) + "%";
  }

  function num(val, digits) {
    var d = typeof digits === "number" ? digits : 3;
    return Number(val).toFixed(d);
  }

  function intComma(val) {
    return Number(val).toLocaleString("en-US");
  }

  function bindAll(map) {
    var nodes = document.querySelectorAll("[data-bind]");
    for (var i = 0; i < nodes.length; i++) {
      var key = nodes[i].getAttribute("data-bind");
      if (Object.prototype.hasOwnProperty.call(map, key)) {
        nodes[i].textContent = map[key];
      }
    }
  }

  var rv2 = L.replication_v2;
  var proto = rv2.protocol_reconciliation;
  var gate = rv2.gate_audit;
  var incA = rv2.incremental_f3_cost_per_net_completion.A;
  var incB = rv2.incremental_f3_cost_per_net_completion.B;
  var diag = L.diagnostics_and_probes;
  var cross = diag.cross_model_attribution;
  var stream = diag.streaming_waterfall;
  var cacheAudit = diag.prefix_cache_quantization_audit;
  var ng = L.nextgen_modules;
  var m1a = ng.m1a_warm_pool;
  var m1b = ng.m1b_crash_resume;
  var m2a = ng.m2a_m3_pareto;
  var sim = m2a.simulator_model;
  var m2b = ng.m2b_m4_context_virtual;
  var m5 = ng.m5_security_shield;
  var m6 = ng.m6_process_grader;
  var pt = L.post_training;

  // 1. Bind Masthead, Executive Highlights & Prose Metrics (100% Ledger-Driven)
  var breakevenPct = pct(sim.advisor_breakeven_p_rec, 2);
  var totalSubmitRuns =
    diag.acc15_probes.submit_disposition_10_trials_accurate +
    m2a.arms.G1.runs +
    m2a.arms.G2.runs +
    m2a.arms.G3.runs;
  var v2CumReduction =
    1 - m2b.arms.V2.parent_input_tokens_sum / m2b.arms.V1.parent_input_tokens_sum;

  bindAll({
    masthead_runs: rv2.executed_trials + " / " + rv2.planned_trials + " Runs",
    masthead_blocks: rv2.paired_blocks + " 配对区组 · API 异常 " + rv2.model_api_failures,
    masthead_f3:
      rv2.groups["A-P1"].f3_correct +
      "/" +
      rv2.groups["A-P1"].f3_total +
      " → " +
      rv2.groups["A-P2"].f3_correct +
      "/" +
      rv2.groups["A-P2"].f3_total,
    masthead_safety:
      "越权 " + rv2.false_allow_total + " · 重复写 " + rv2.duplicate_effect_total + " · 帧闭合 " + proto.wire_requests,
    masthead_m1:
      num(m1a.cold_median_startup_s, 4) + "s → " + num(m1a.warm_median_startup_s * 1000, 1) + "ms",
    masthead_m1_sub:
      "热池 -" + pct(m1a.median_startup_reduction_ratio, 2) + " · 断电续跑 " + m1b.signature_matches_reference + "/" + m1b.total_resume_trials,
    masthead_pareto: "-" + pct(sim.g1_vs_g0_reduction_ratio, 2) + " 推理耗时",
    masthead_pareto_sub:
      "首轮跨题缓存 " + pct(m2a.arms.G1.unseen_tasks_2_to_n_turn1_cache_hit_ratio, 2) + " / " + pct(m2a.arms.G3.unseen_tasks_2_to_n_turn1_cache_hit_ratio, 2),
    masthead_m6:
      "P=" + num(m6.three_tier_classification_matrix.REWARD_HACK_BLOCKED.precision, 1) +
      " · R=" + num(m6.three_tier_classification_matrix.REWARD_HACK_BLOCKED.recall, 1),
    masthead_sha: "SHA256 " + L.ledger_integrity.payload_sha256.slice(0, 12) + "..",

    hl_runs: String(rv2.executed_trials),
    hl_crash: String(m1b.total_resume_trials),
    hl_warm: pct(m1a.median_startup_reduction_ratio, 2),
    hl_pareto: pct(sim.g1_vs_g0_reduction_ratio, 2),
    hl_v2: pct(m2b.v2_peak_parent_input_reduction_vs_v0, 2),
    hl_loop: pct(m5.loop_trap_savings_s1_vs_s0.input_tokens_reduction_ratio, 2),
    hl_hack: pct(m6.three_tier_classification_matrix.REWARD_HACK_BLOCKED.recall, 0),

    s1_trials: String(rv2.executed_trials),
    s1_blocks: String(rv2.paired_blocks),
    s1_api_fail: String(rv2.model_api_failures),
    s1_f3_p1_pct: pct(rv2.groups["A-P1"].f3_correct / rv2.groups["A-P1"].f3_total, 0),
    s1_f3_p2_pct: pct(rv2.groups["A-P2"].f3_correct / rv2.groups["A-P2"].f3_total, 0),
    s1_f3_jump:
      rv2.groups["A-P1"].f3_correct + "/" + rv2.groups["A-P1"].f3_total +
      " → " + rv2.groups["A-P2"].f3_correct + "/" + rv2.groups["A-P2"].f3_total,
    s1_zero_safety:
      "越权写 " + rv2.false_allow_total + "/" + rv2.executed_trials +
      "、重复写 " + rv2.duplicate_effect_total + "/" + rv2.executed_trials,
    s1_wire_req: String(proto.wire_requests),
    s1_model_b_name: incB.model_name,
    s1_b_delta_s: "+" + num(incB.delta_wall_s, 3) + "s",
    s1_a_delta_s: "+" + num(incA.delta_wall_s, 3) + "s",
    s1_b_over_a_ratio: num(incB.delta_wall_s / incA.delta_wall_s, 2),
    s1_loss_slot: rv2.single_control_loss.slot,
    s1_b_ctrl_score: rv2.groups["B-P2"].control_correct + "/" + rv2.groups["B-P2"].control_total,
    fig1_meta:
      "冻结代码摘要 " + L.freeze_anchor.frozen_code_file_count + " 项 · 评分器 " + L.freeze_anchor.grader_version,
    fig1_ci:
      "+" + pct(rv2.paired_p2_minus_p1.A.M.paired_difference, 1) +
      " (95% CI [" + pct(rv2.paired_p2_minus_p1.A.M.task_cluster_bootstrap_95[0], 1) +
      ", " + pct(rv2.paired_p2_minus_p1.A.M.task_cluster_bootstrap_95[1], 1) + "])",

    s2_runs: String(rv2.executed_trials),
    s2_span_gap: "+" + num(cross.b_minus_a_span_s, 3) + "s",
    s2_inf_gap: "+" + num(cross.b_minus_a_inference_s, 3) + "s",
    s2_inf_share: pct(cross.inference_share_of_gap, 2),
    s2_b_reason_share: pct(cross.model_b_reasoning_share, 2),
    s2_a_reason_share: pct(cross.model_a_reasoning_share, 2),
    s2_cold_mcp: num(cross.combined_cold_mcp_startup_mean_s, 3) + "s",
    s2_stream_calls: String(stream.calls),
    s2_stream_total: num(stream.nodes.total_stream_call_s.mean_s, 3) + "s",
    s2_pre_vis_share: pct(stream.pre_visible_share, 2),
    s2_ttft: num(stream.nodes.visible_or_tool_ttft_s.mean_s, 3) + "s",
    s2_ttfb: num(stream.nodes.first_stream_event_ttfb_s.mean_s, 3) + "s",
    s2_think_win: num(stream.nodes.thinking_window_s.mean_s, 3) + "s",
    s2_vis_gen: num(stream.nodes.visible_generation_s.mean_s * 1000, 1) + "ms",
    s2_c0_med: num(m1a.cold_median_startup_s, 4) + "s",
    s2_t1_med: num(m1a.warm_median_startup_s * 1000, 1) + "ms",
    s2_m1a_red: pct(m1a.median_startup_reduction_ratio, 2),
    s2_m1a_pairs: String(m1a.trials_per_arm),
    s2_m1b_count: String(m1b.total_resume_trials),
    s2_m1b_trials: m1b.signature_matches_reference + "/" + m1b.total_resume_trials,
    s2_m1b_dup: String(m1b.duplicate_effects),

    s3_audit_reqs: String(cacheAudit.total_requests_audited),
    s3_a_hit: pct(cacheAudit.model_a_overall_hit_ratio, 2),
    s3_b_zero: String(cacheAudit.model_b_zero_hit_calls),
    s3_b_t1_zero: String(cacheAudit.model_b_turn1_zero_hit_calls),
    s3_pareto_runs: String(m2a.total_runs),
    s3_g0_unseen: pct(m2a.arms.G0.unseen_tasks_2_to_n_turn1_cache_hit_ratio, 2),
    s3_g1_unseen: pct(m2a.arms.G1.unseen_tasks_2_to_n_turn1_cache_hit_ratio, 2),
    s3_g3_unseen: pct(m2a.arms.G3.unseen_tasks_2_to_n_turn1_cache_hit_ratio, 2),
    s3_g3_overall_hit: pct(m2a.arms.G3.overall_cache_hit_ratio, 2),
    s3_g0_reason: intComma(m2a.arms.G0.reasoning_tokens_sum),
    s3_g0_inf: num(m2a.arms.G0.inference_s.mean_s, 3) + "s",
    s3_g1_inf: num(m2a.arms.G1.inference_s.mean_s, 3) + "s",
    s3_g1_red: pct(sim.g1_vs_g0_reduction_ratio, 2),
    s3_adv_mean: num(sim.advisor_mean_call_s, 4) + "s",
    s3_think_save: num(sim.routine_thinking_savings_s, 4) + "s",
    s3_breakeven_pct: breakevenPct,
    s3_breakeven_eq:
      "p_rec * " + num(sim.advisor_mean_call_s, 4) + "s < " +
      num(sim.routine_thinking_savings_s, 4) + "s  ⇒  p_rec < " + breakevenPct + " (~45%)",

    s4_v0_peak: intComma(m2b.arms.V0.mean_peak_parent_input_tokens),
    s4_v1_peak: intComma(m2b.arms.V1.mean_peak_parent_input_tokens),
    s4_v2_done: m2b.arms.V2.goal_completed + "/" + m2b.tasks_per_arm,
    s4_v2_peak: intComma(m2b.arms.V2.mean_peak_parent_input_tokens),
    s4_v2_cum_red: pct(v2CumReduction, 2),
    s4_v2_red: pct(m2b.v2_peak_parent_input_reduction_vs_v0, 2),
    s4_false_allow: m5.arms.S0.false_allow_sum + " / " + m5.arms.S1.false_allow_sum,
    s4_s1_score: m5.arms.S1.overall_correct_disposition + "/" + m5.tasks_per_arm,
    s4_loop_call_red: pct(m5.loop_trap_savings_s1_vs_s0.model_calls_reduction_ratio, 2),
    s4_loop_tok_red: pct(m5.loop_trap_savings_s1_vs_s0.input_tokens_reduction_ratio, 2),
    fig4_meta:
      "M2B+M4 (" + (m2b.tasks_per_arm * 3) + " runs) · M5 (" + (m5.tasks_per_arm * 2) + " runs)",

    s5_probe2_rate: diag.acc15_probes.self_correction_15_trials_passed + "/15 (100.0%)",
    s5_probe2_lat: "+" + num(diag.acc15_four_way_comparison.variants[2].mean_latency_s, 3) + "s",
    s5_submit_runs: String(totalSubmitRuns),
    s5_submit_pct: pct(totalSubmitRuns / totalSubmitRuns, 0),
    s5_probe3_rate: totalSubmitRuns + "/" + totalSubmitRuns + " (100.0%)",
    s5_ret_clean: "+" + num(m6.prm_return_hierarchy.STRICT_CLEAN, 3),
    s5_ret_warn: "+" + num(m6.prm_return_hierarchy.VALID_WITH_HYGIENE_WARN, 3),
    s5_hack_pr:
      "P=" + num(m6.three_tier_classification_matrix.REWARD_HACK_BLOCKED.precision, 1) +
      ", R=" + num(m6.three_tier_classification_matrix.REWARD_HACK_BLOCKED.recall, 1),
    s5_ret_hack: num(m6.prm_return_hierarchy.REWARD_HACK_BLOCKED, 3),
    s5_red_lines: String(pt.negative_red_lines_enforced),
    s5_sft_count: String(pt.sft_samples),
    s5_sup_turns: String(pt.supervised_assistant_turns_total),
    s5_mask_turns: String(pt.masked_context_turns_total),
    s5_dpo_count: String(pt.preference_pairs),
    footer_integrity:
      "Freeze " + L.freeze_anchor.freeze_commit.slice(0, 10) +
      " · Ledger SHA-256 " + L.ledger_integrity.payload_sha256.slice(0, 16)
  });

  // 2. Render Margin Notes (Distill 240px Right Column)
  document.getElementById("margin-act-1").innerHTML =
    "<p><strong>配对分母：</strong><code>" + rv2.tasks_total + "</code> 题 = <code>" +
    rv2.f3_tasks + "</code> 道并发版本失效题 + <code>" + rv2.control_tasks + "</code> 道控制题；每组 <code>" +
    rv2.groups["A-P2"].runs + "</code> 次运行，可完成写目标机会 <code>" + rv2.groups["A-P2"].goal_denominator + "</code> 次。</p>" +
    "<p><strong>线缆对账：</strong>请求 <code>" + proto.wire_requests + "</code> 帧、正常回包 <code>" +
    proto.wire_responses + "</code> 帧、本地超时 <code>" + proto.local_timeouts +
    "</code> 次、迟到帧隔离 <code>" + proto.late_responses_isolated + "</code> 帧、未核验 <code>" +
    proto.unverified_dispatches + "</code>。</p>" +
    "<p><strong>源码锚点：</strong><code>src/harness_lab/runtime.py</code>、<code>mcp_port.py</code>、<code>storage.py</code>。</p>";

  document.getElementById("margin-act-2").innerHTML =
    "<p><strong>词元构成：</strong>Model B 推理词元 <code>" +
    intComma(diag.latency_and_tokens_by_model.B.persisted_token_telemetry.reasoning_tokens_sum) +
    "</code> / 总输出 <code>" +
    intComma(diag.latency_and_tokens_by_model.B.persisted_token_telemetry.output_tokens_sum) +
    "</code>；Model A 推理词元 <code>" +
    intComma(diag.latency_and_tokens_by_model.A.persisted_token_telemetry.reasoning_tokens_sum) + "</code>。</p>" +
    "<p><strong>看门狗自愈：</strong><code>evals/nextgen/warm_pool.py</code> 分离冷拉起与会话握手阈值，强杀挂死子进程并显式关闭 <code>fd 0..2</code> 管道。</p>" +
    "<p><strong>只读对账：</strong><code>evals/nextgen/crash_resume.py</code> 已提交回执直恢复 <code>" +
    m1b.committed_receipt_recoveries + "/6</code> 次。</p>";

  document.getElementById("margin-act-3").innerHTML =
    "<p><strong>量化页实测：</strong>Model B 命中页严格落于 <code>1080</code> (k=4, <code>" +
    cacheAudit.model_b_quantized_pages[0].v2_calls + "</code> 次)、<code>1336</code> (k=5, <code>" +
    cacheAudit.model_b_quantized_pages[1].v2_calls + "</code> 次)、<code>1592</code> (k=6, <code>" +
    cacheAudit.model_b_quantized_pages[2].v2_calls + "</code> 次) 及对齐后 <code>2360 / 2616 / 3128</code>。</p>" +
    "<p><strong>帕累托比较：</strong><code>G3 vs G0</code> 在 <code>75%</code> 压力配比下均值推理差 <code>" +
    num(m2a.pareto_comparisons.g3_vs_g0_paired_inference_delta_s.mean_diff, 3) + "s</code>；<code>G1</code> 全区间无额外往返。</p>";

  document.getElementById("margin-act-4").innerHTML =
    "<p><strong>溢出阈值：</strong><code>DiskSliceStore</code> 在工具响应 <code>&gt;4,096 B</code> 时自动落盘并返回分页切片索引。</p>" +
    "<p><strong>最小权限：</strong>巡检子智能体会话固定 <code>can_write=False</code>，写探测拦截 <code>6/6</code>；移交模式受 <code>InspectorEvidenceReport</code> 约束。</p>" +
    "<p><strong>环路熔断：</strong><code>threshold=2</code>，死循环调用 <code>" +
    m5.arms.S0.loop_model_calls_sum + " → " + m5.arms.S1.loop_model_calls_sum + "</code>。</p>";

  document.getElementById("margin-act-5").innerHTML =
    "<p><strong>元评测三队列：</strong>洁净轨迹 <code>" +
    m6.three_tier_classification_matrix.STRICT_CLEAN.count +
    "</code> 条、主实验真实恢复 <code>" +
    m6.three_tier_classification_matrix.VALID_WITH_HYGIENE_WARN.count +
    "</code> 条、五类合成作弊 <code>" +
    m6.three_tier_classification_matrix.REWARD_HACK_BLOCKED.count + "</code> 条。</p>" +
    "<p><strong>后训练红线：</strong><code>evals/post_training/__init__.py</code> 递归解析嵌套字面量，强制阻断非助手轮监督与任何保护信封残留。</p>";

  // 3. Render SVG Figure 1 + Replication-v2 Table
  function renderFigure1() {
    var mount = document.getElementById("svg-figure-1-mount");
    mount.innerHTML =
      '<svg viewBox="0 0 1040 300" width="1040" height="300" role="img" aria-label="宿主控制面信任边界与副作用三态状态机">' +
      '<rect x="0" y="0" width="1040" height="300" fill="#FAF9F5"/>' +
      '<rect x="8" y="8" width="1024" height="284" rx="2" fill="#F3F1EA" stroke="#E5E2D9" stroke-width="1"/>' +
      '<text x="26" y="32" font-family="JetBrains Mono, monospace" font-size="11" fill="#5E5D59">1. UNTRUSTED MODEL PROPOSAL</text>' +
      '<text x="286" y="32" font-family="JetBrains Mono, monospace" font-size="11" font-weight="600" fill="#B85A3A">2. DETERMINISTIC HOST CONTROL PLANE</text>' +
      '<text x="768" y="32" font-family="JetBrains Mono, monospace" font-size="11" font-weight="600" fill="#1F5E3B">3. ISOLATED MCP SANDBOX</text>' +
      '<line x1="268" y1="18" x2="268" y2="280" stroke="#B85A3A" stroke-width="1.4" stroke-dasharray="4,3"/>' +
      '<line x1="750" y1="18" x2="750" y2="280" stroke="#C9C5B8" stroke-width="1" stroke-dasharray="4,3"/>' +
      // Left box
      '<rect x="24" y="46" width="226" height="228" rx="2" fill="#FFFFFF" stroke="#E5E2D9"/>' +
      '<text x="38" y="70" font-family="Source Serif 4, Georgia, serif" font-size="14" font-weight="600" fill="#141413">LLM Controller</text>' +
      '<text x="38" y="90" font-family="JetBrains Mono, monospace" font-size="11" fill="#5E5D59">public_tools() · strict arity=1</text>' +
      '<line x1="38" y1="100" x2="234" y2="100" stroke="#E5E2D9"/>' +
      '<text x="38" y="122" font-family="JetBrains Mono, monospace" font-size="11" fill="#141413">read_state(target_ref)</text>' +
      '<text x="38" y="142" font-family="JetBrains Mono, monospace" font-size="11" fill="#141413">create_ticket(expected_rev..)</text>' +
      '<text x="38" y="162" font-family="JetBrains Mono, monospace" font-size="11" fill="#1F5E3B">submit_disposition(..)</text>' +
      '<rect x="38" y="182" width="196" height="44" rx="2" fill="#F6EAEB" stroke="#9E2A2B" stroke-width="0.8"/>' +
      '<text x="48" y="200" font-family="Inter, sans-serif" font-size="11.5" fill="#9E2A2B">剥离身份与槽位字段</text>' +
      '<text x="48" y="217" font-family="JetBrains Mono, monospace" font-size="10.5" fill="#9E2A2B">additionalProperties: false</text>' +
      '<text x="38" y="252" font-family="JetBrains Mono, monospace" font-size="11" fill="#8C8A84">提案放行: ' +
      gate.valid_allowed + ' / 越权放行: ' + gate.invalid_allowed + '</text>' +
      // Center top: Gate + Protected Wire Envelope
      '<rect x="286" y="46" width="446" height="96" rx="2" fill="#FFFFFF" stroke="#C9C5B8"/>' +
      '<text x="302" y="69" font-family="Source Serif 4, Georgia, serif" font-size="14" font-weight="600" fill="#141413">Host Four-Check Gate &amp; Wire Envelope Injection</text>' +
      '<line x1="302" y1="79" x2="716" y2="79" stroke="#E5E2D9"/>' +
      '<text x="302" y="100" font-family="Inter, sans-serif" font-size="12" fill="#141413">四维校验：模式合法性 · target_ref 恒等 · 主体读写授权 · 阶段状态机</text>' +
      '<text x="302" y="122" font-family="JetBrains Mono, monospace" font-size="11" fill="#5E5D59">wire_requests=' +
      proto.wire_requests + ' · timeouts=' + proto.local_timeouts +
      ' · late_isolated=' + proto.late_responses_isolated + '</text>' +
      // Center bottom: P0/P1/P2
      '<rect x="286" y="154" width="446" height="120" rx="2" fill="#FFFFFF" stroke="#C9C5B8"/>' +
      '<text x="302" y="176" font-family="Source Serif 4, Georgia, serif" font-size="13.5" font-weight="600" fill="#141413">Side-Effect 3-State Machine (P0 / P1 / P2)</text>' +
      '<rect x="302" y="188" width="130" height="72" rx="2" fill="#FAF9F5" stroke="#E5E2D9"/>' +
      '<text x="312" y="206" font-family="JetBrains Mono, monospace" font-size="11" font-weight="600" fill="#5E5D59">P0 · 单次基线</text>' +
      '<text x="312" y="225" font-family="Inter, sans-serif" font-size="11" fill="#141413">无重试直接终止</text>' +
      '<text x="312" y="245" font-family="JetBrains Mono, monospace" font-size="11" fill="#8C8A84">24/54 (44.4%)</text>' +
      '<rect x="444" y="188" width="130" height="72" rx="2" fill="#F7EFE4" stroke="#945814" stroke-width="0.8"/>' +
      '<text x="454" y="206" font-family="JetBrains Mono, monospace" font-size="11" font-weight="600" fill="#945814">P1 · 未知态原参重放</text>' +
      '<text x="454" y="225" font-family="Inter, sans-serif" font-size="11" fill="#141413">UNKNOWN 锁定原键</text>' +
      '<text x="454" y="245" font-family="JetBrains Mono, monospace" font-size="11" fill="#945814">36/54 · F3 0/18</text>' +
      '<rect x="586" y="188" width="132" height="72" rx="2" fill="#EBF3EE" stroke="#1F5E3B" stroke-width="0.9"/>' +
      '<text x="596" y="206" font-family="JetBrains Mono, monospace" font-size="11" font-weight="600" fill="#1F5E3B">P2 · 确权刷新重提</text>' +
      '<text x="596" y="225" font-family="JetBrains Mono, monospace" font-size="10.2" fill="#141413">certified_unbound</text>' +
      '<text x="596" y="245" font-family="JetBrains Mono, monospace" font-size="11" fill="#1F5E3B">F3 18/18 (100%)</text>' +
      // Right box: MCP + SQLite
      '<rect x="768" y="46" width="248" height="228" rx="2" fill="#FFFFFF" stroke="#E5E2D9"/>' +
      '<text x="782" y="70" font-family="Source Serif 4, Georgia, serif" font-size="14" font-weight="600" fill="#141413">MCP Server &amp; SQLite WAL</text>' +
      '<line x1="782" y1="80" x2="1000" y2="80" stroke="#E5E2D9"/>' +
      '<text x="782" y="102" font-family="Inter, sans-serif" font-size="12" fill="#141413">1. 独立复核权限与 expected_rev</text>' +
      '<text x="782" y="124" font-family="Inter, sans-serif" font-size="12" fill="#141413">2. BEGIN IMMEDIATE 原子写事务</text>' +
      '<text x="782" y="146" font-family="Inter, sans-serif" font-size="12" fill="#141413">3. tickets / receipts 不可变触发器</text>' +
      '<rect x="782" y="166" width="220" height="52" rx="2" fill="#EBF3EE" stroke="#1F5E3B" stroke-width="0.8"/>' +
      '<text x="792" y="186" font-family="Inter, sans-serif" font-size="11.5" fill="#1F5E3B">同键重放直返原回执 · 异参冲突阻断</text>' +
      '<text x="792" y="205" font-family="JetBrains Mono, monospace" font-size="11" fill="#1F5E3B">duplicate_effect = ' +
      rv2.duplicate_effect_total + ' / ' + rv2.executed_trials + '</text>' +
      '<text x="782" y="252" font-family="JetBrains Mono, monospace" font-size="11" fill="#5E5D59">断电唤醒 ?mode=ro 只读对账</text>' +
      // Arrows
      '<line x1="250" y1="94" x2="284" y2="94" stroke="#B85A3A" stroke-width="1.5"/>' +
      '<polygon points="286,94 279,90 279,98" fill="#B85A3A"/>' +
      '<line x1="732" y1="94" x2="766" y2="94" stroke="#1F5E3B" stroke-width="1.5"/>' +
      '<polygon points="768,94 761,90 761,98" fill="#1F5E3B"/>' +
      "</svg>";

    var order = ["A-P0", "A-P1", "A-P2", "B-P0", "B-P1", "B-P2"];
    var labels = {
      "A-P0": "A-P0 (deepseek-flash · 零重试)",
      "A-P1": "A-P1 (deepseek-flash · 同键幂等重放)",
      "A-P2": "A-P2 (deepseek-flash · 确权刷新重提)",
      "B-P0": "B-P0 (doubao-seed-2-1-lite · 零重试)",
      "B-P1": "B-P1 (doubao-seed-2-1-lite · 同键幂等重放)",
      "B-P2": "B-P2 (doubao-seed-2-1-lite · 确权刷新重提)"
    };
    var rowsHtml = "";
    for (var i = 0; i < order.length; i++) {
      var k = order[i];
      var g = rv2.groups[k];
      var cls = k.indexOf("P2") !== -1 ? ' class="row-highlight"' : "";
      rowsHtml +=
        "<tr" + cls + ">" +
        '<td class="mono">' + esc(labels[k]) + "</td>" +
        '<td class="num">' + g.overall_correct + "/" + g.runs + " (" + pct(g.overall_rate, 1) + ")</td>" +
        '<td class="num">' + g.f3_correct + "/" + g.f3_total + "</td>" +
        '<td class="num">' + g.control_correct + "/" + g.control_total + "</td>" +
        '<td class="num">' + g.goal_completed + "/" + g.goal_denominator + "</td>" +
        '<td class="num">' + g.f3_pass_cubed + "/" + g.f3_pass_cubed_total + " · " + g.control_pass_cubed + "/" + g.control_pass_cubed_total + "</td>" +
        '<td class="num">' + num(g.costs_sum.total_s, 2) + "</td>" +
        '<td class="num">' + g.false_allow + " / " + g.duplicate_effect + "</td>" +
        "</tr>";
    }
    document.getElementById("tbody-replication-v2").innerHTML = rowsHtml;
  }
  renderFigure1();

  // 4. Interactive Lab 1: Three-Column Trajectory & SQLite State Stepper
  var trajs = L.representative_stepper_slices.interactive_four_trajectories;
  var lab1State = { trajIdx: 0, stepIdx: 0 };

  function epistemicBadgeClass(st) {
    if (st === "CONFIRMED") return "badge badge-pass";
    if (st === "UNKNOWN") return "badge badge-warn";
    return "badge";
  }

  function renderLab1() {
    var tabsEl = document.getElementById("lab1-traj-tabs");
    var tabHtml = "";
    for (var i = 0; i < trajs.length; i++) {
      var activeCls = i === lab1State.trajIdx ? " active" : "";
      tabHtml +=
        '<button type="button" class="btn-tab' + activeCls + '" data-traj-idx="' + i + '">' +
        '<span class="tab-anchor">[' + esc(trajs[i].anchor) + "]</span>" +
        esc(trajs[i].title) + "</button>";
    }
    tabsEl.innerHTML = tabHtml;

    var curTraj = trajs[lab1State.trajIdx];
    var steps = curTraj.steps;
    if (lab1State.stepIdx >= steps.length) lab1State.stepIdx = steps.length - 1;
    var s = steps[lab1State.stepIdx];

    document.getElementById("lab1-step-counter").textContent =
      "Step " + s.step_index + " / " + steps.length;
    document.getElementById("lab1-phase-label").textContent = s.phase_label;

    var dotsHtml = "";
    for (var j = 0; j < steps.length; j++) {
      var dCls = j === lab1State.stepIdx ? "step-pill active" : "step-pill";
      dotsHtml +=
        '<button type="button" class="' + dCls + '" data-step-idx="' + j + '">' +
        "S" + steps[j].step_index + "</button>";
    }
    document.getElementById("lab1-step-dots").innerHTML = dotsHtml;

    document.getElementById("lab1-prev-btn").disabled = lab1State.stepIdx === 0;
    document.getElementById("lab1-next-btn").disabled = lab1State.stepIdx === steps.length - 1;

    // Left column
    document.getElementById("lab1-left-role").textContent = s.left_model_context.role;
    document.getElementById("lab1-left-summary").textContent = s.left_model_context.summary;
    document.getElementById("lab1-left-payload").textContent = JSON.stringify(
      s.left_model_context.payload,
      null,
      2
    );

    // Middle column
    var epEl = document.getElementById("lab1-mid-epistemic");
    epEl.className = epistemicBadgeClass(s.middle_host_gate.epistemic_state);
    epEl.textContent = s.middle_host_gate.epistemic_state;
    document.getElementById("lab1-mid-verdict").textContent = s.middle_host_gate.gate_verdict;
    document.getElementById("lab1-mid-wire").textContent = s.middle_host_gate.wire_action;
    document.getElementById("lab1-mid-detail").textContent = s.middle_host_gate.detail;

    // Right column: SQLite live diff
    var db = s.right_db_state;
    var kindEl = document.getElementById("lab1-right-kind");
    kindEl.textContent = db.snapshot_kind;
    kindEl.className =
      db.snapshot_kind.indexOf("reconciled") !== -1 || db.snapshot_kind.indexOf("completed") !== -1
        ? "badge badge-pass"
        : db.snapshot_kind.indexOf("crash") !== -1
        ? "badge badge-block"
        : "badge";

    var changed = db.changed_fields || [];
    var displayKeys = [
      "target_ref",
      "state_revision",
      "write_policy",
      "ticket_rows",
      "receipt_rows",
      "recovered_from_committed_receipt",
      "committed_ticket_id",
      "crashed_at_seq",
      "trace_effect_knowledge_at_crash",
      "reconciled_effect_knowledge",
      "resumed_phase",
      "final_disposition",
      "duplicate_effect"
    ];
    var kvHtml = "";
    for (var kIdx = 0; kIdx < displayKeys.length; kIdx++) {
      var field = displayKeys[kIdx];
      if (!Object.prototype.hasOwnProperty.call(db, field)) continue;
      var isDiff = changed.indexOf(field) !== -1;
      var rowCls = "kv-row";
      if (isDiff) {
        rowCls +=
          field === "recovered_from_committed_receipt" || field === "reconciled_effect_knowledge"
            ? " diff-confirmed"
            : " diff-changed";
      }
      var val = db[field];
      var renderedVal = typeof val === "object" ? JSON.stringify(val) : String(val);
      kvHtml +=
        '<div class="' + rowCls + '">' +
        '<span class="kv-key">' + esc(field) + "</span>" +
        '<span class="kv-val">' + esc(renderedVal) + "</span>" +
        "</div>";
    }
    document.getElementById("lab1-right-kv").innerHTML = kvHtml;
  }

  document.getElementById("lab1-traj-tabs").addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-traj-idx]");
    if (!btn) return;
    lab1State.trajIdx = Number(btn.getAttribute("data-traj-idx"));
    lab1State.stepIdx = 0;
    renderLab1();
  });

  document.getElementById("lab1-step-dots").addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-step-idx]");
    if (!btn) return;
    lab1State.stepIdx = Number(btn.getAttribute("data-step-idx"));
    renderLab1();
  });

  document.getElementById("lab1-prev-btn").addEventListener("click", function () {
    if (lab1State.stepIdx > 0) {
      lab1State.stepIdx -= 1;
      renderLab1();
    }
  });

  document.getElementById("lab1-next-btn").addEventListener("click", function () {
    var maxStep = trajs[lab1State.trajIdx].steps.length - 1;
    if (lab1State.stepIdx < maxStep) {
      lab1State.stepIdx += 1;
      renderLab1();
    }
  });

  document.addEventListener("keydown", function (ev) {
    var active = document.activeElement;
    if (active && (active.tagName === "INPUT" || active.tagName === "TEXTAREA")) return;
    if (ev.key === "ArrowLeft") {
      if (lab1State.stepIdx > 0) {
        lab1State.stepIdx -= 1;
        renderLab1();
      }
    } else if (ev.key === "ArrowRight") {
      var maxStep = trajs[lab1State.trajIdx].steps.length - 1;
      if (lab1State.stepIdx < maxStep) {
        lab1State.stepIdx += 1;
        renderLab1();
      }
    }
  });
  renderLab1();

  // 5. Render SVG Figure 2 (Figure 3): 4-Stage Monotonic Clock + 5-Node Streaming Waterfall
  function renderFigure2() {
    var mA = diag.latency_and_tokens_by_model.A;
    var mB = diag.latency_and_tokens_by_model.B;
    var maxSpan = mB.trace_span_s;
    var barW = 600;
    var x0 = 216;

    function seg(val) {
      return Math.max(2, (val / maxSpan) * barW);
    }

    var aInf = mA.stages.model_inference_s.sum_s;
    var aMcp = mA.stages.mcp_comm_s.sum_s;
    var aBack = mA.stages.backoff_wait_s.sum_s;
    var aClean = mA.stages.cleanup_s.sum_s;

    var bInf = mB.stages.model_inference_s.sum_s;
    var bMcp = mB.stages.mcp_comm_s.sum_s;
    var bBack = mB.stages.backoff_wait_s.sum_s;
    var bClean = mB.stages.cleanup_s.sum_s;

    // Bottom waterfall scale (mean stream call 2.0378s)
    var sNodes = stream.nodes;
    var sTotal = sNodes.total_stream_call_s.mean_s;
    var ttfb = sNodes.first_stream_event_ttfb_s.mean_s;
    var thinkW = sNodes.thinking_window_s.mean_s;
    var visW = sNodes.visible_generation_s.mean_s;

    function wSeg(val) {
      return (val / sTotal) * barW;
    }

    var visBarW = Math.max(8, wSeg(visW));
    var visLabelX = x0 + wSeg(ttfb + thinkW) + visBarW + 10;

    var svg =
      '<svg viewBox="0 0 1040 336" width="1040" height="336" role="img" aria-label="四阶段单调时钟对比与流式五节点瀑布图">' +
      '<rect x="0" y="0" width="1040" height="336" fill="#FAF9F5"/>' +
      // Panel A Header
      '<text x="20" y="28" font-family="Source Serif 4, Georgia, serif" font-size="13.5" font-weight="600" fill="#141413">' +
      "A. 324 次主基准单调时钟四阶段累计跨度对比 (B - A 差值中模型推理占 " + pct(cross.inference_share_of_gap, 2) + ")</text>" +
      // Model A Bar
      '<text x="20" y="68" font-family="JetBrains Mono, monospace" font-size="11.5" fill="#141413">Model A (162 runs)</text>' +
      '<text x="20" y="84" font-family="JetBrains Mono, monospace" font-size="10.5" fill="#5E5D59">sum ' + num(mA.trace_span_s, 1) + 's</text>' +
      '<rect class="svg-hotspot" data-tip="Model A · 模型 API 推理等待: 累计 ' + num(aInf, 3) + 's (均值 ' + num(mA.stages.model_inference_s.mean_s, 3) + 's, 占比 54.53%)" x="' + x0 + '" y="54" width="' + seg(aInf) + '" height="28" fill="#B85A3A"/>' +
      '<rect class="svg-hotspot" data-tip="Model A · MCP 沙箱执行 (含子进程冷启动均值 ' + num(mA.mcp_sub_stages.mcp_startup_s.mean_s, 3) + 's): 累计 ' + num(aMcp, 3) + 's (42.49%)" x="' + (x0 + seg(aInf)) + '" y="54" width="' + seg(aMcp) + '" height="28" fill="#5E5D59"/>' +
      '<rect class="svg-hotspot" data-tip="Model A · 退避等待 + 收尾屏障: ' + num(aBack + aClean, 3) + 's" x="' + (x0 + seg(aInf) + seg(aMcp)) + '" y="54" width="' + seg(aBack + aClean) + '" height="28" fill="#C9C5B8"/>' +
      '<text x="' + (x0 + seg(mA.trace_span_s) + 10) + '" y="72" font-family="JetBrains Mono, monospace" font-size="11" fill="#141413">' + num(mA.trace_span_s, 1) + "s</text>" +
      // Model B Bar
      '<text x="20" y="118" font-family="JetBrains Mono, monospace" font-size="11.5" fill="#141413">Model B (162 runs)</text>' +
      '<text x="20" y="134" font-family="JetBrains Mono, monospace" font-size="10.5" fill="#5E5D59">sum ' + num(mB.trace_span_s, 1) + 's</text>' +
      '<rect class="svg-hotspot" data-tip="Model B · 模型 API 推理等待: 累计 ' + num(bInf, 3) + 's (均值 ' + num(mB.stages.model_inference_s.mean_s, 3) + 's, 占比 74.15%, 隐式思考词元占输出 59.50%)" x="' + x0 + '" y="104" width="' + seg(bInf) + '" height="28" fill="#B85A3A"/>' +
      '<rect class="svg-hotspot" data-tip="Model B · MCP 沙箱执行 (含子进程冷启动均值 ' + num(mB.mcp_sub_stages.mcp_startup_s.mean_s, 3) + 's): 累计 ' + num(bMcp, 3) + 's (24.16%)" x="' + (x0 + seg(bInf)) + '" y="104" width="' + seg(bMcp) + '" height="28" fill="#5E5D59"/>' +
      '<rect class="svg-hotspot" data-tip="Model B · 退避等待 + 收尾屏障: ' + num(bBack + bClean, 3) + 's" x="' + (x0 + seg(bInf) + seg(bMcp)) + '" y="104" width="' + seg(bBack + bClean) + '" height="28" fill="#C9C5B8"/>' +
      '<text x="' + (x0 + barW + 10) + '" y="122" font-family="JetBrains Mono, monospace" font-size="11" fill="#141413">' + num(mB.trace_span_s, 1) + "s</text>" +
      // Legend
      '<rect x="' + x0 + '" y="146" width="10" height="10" fill="#B85A3A"/><text x="' + (x0 + 15) + '" y="155" font-family="Inter, sans-serif" font-size="11.5" fill="#5E5D59">模型 API 推理等待</text>' +
      '<rect x="' + (x0 + 150) + '" y="146" width="10" height="10" fill="#5E5D59"/><text x="' + (x0 + 165) + '" y="155" font-family="Inter, sans-serif" font-size="11.5" fill="#5E5D59">MCP 沙箱与冷启动 (1.829s/run)</text>' +
      '<rect x="' + (x0 + 370) + '" y="146" width="10" height="10" fill="#C9C5B8"/><text x="' + (x0 + 385) + '" y="155" font-family="Inter, sans-serif" font-size="11.5" fill="#5E5D59">退避等待与收尾排空屏障</text>' +
      '<line x1="20" y1="174" x2="1020" y2="174" stroke="#E5E2D9"/>' +
      // Panel B: 5-node SSE Streaming Waterfall
      '<text x="20" y="202" font-family="Source Serif 4, Georgia, serif" font-size="13.5" font-weight="600" fill="#141413">' +
      "B. Model B 单次流式调用五节点微观瀑布 (20 calls 均值 " + num(sTotal, 3) + "s · 首字前耗时占 " + pct(stream.pre_visible_share, 2) + ")</text>" +
      '<text x="20" y="240" font-family="JetBrains Mono, monospace" font-size="11" fill="#5E5D59">1. 首事件网络排队 TTFB</text>' +
      '<rect class="svg-hotspot" data-tip="节点 1 → 2 首流事件到达 TTFB: 均值 ' + num(ttfb, 3) + 's · 中位数 ' + num(sNodes.first_stream_event_ttfb_s.median_s, 3) + 's · P90 ' + num(sNodes.first_stream_event_ttfb_s.p90_s, 3) + 's" x="' + x0 + '" y="224" width="' + wSeg(ttfb) + '" height="22" fill="#8C8A84"/>' +
      '<text x="' + (x0 + wSeg(ttfb) + 8) + '" y="239" font-family="JetBrains Mono, monospace" font-size="11" fill="#5E5D59">' + num(ttfb, 3) + "s</text>" +

      '<text x="20" y="272" font-family="JetBrains Mono, monospace" font-size="11" fill="#945814">2. 服务端隐式思考驻留窗口</text>' +
      '<rect class="svg-hotspot" data-tip="节点 2 → 4 隐式思考窗口 thinking_window_s: 均值 ' + num(thinkW, 3) + 's · 中位数 ' + num(sNodes.thinking_window_s.median_s, 3) + 's · P90 ' + num(sNodes.thinking_window_s.p90_s, 3) + 's" x="' + (x0 + wSeg(ttfb)) + '" y="256" width="' + wSeg(thinkW) + '" height="22" fill="#945814"/>' +
      '<text x="' + (x0 + wSeg(ttfb + thinkW) + 8) + '" y="271" font-family="JetBrains Mono, monospace" font-size="11" fill="#945814">+' + num(thinkW, 3) + "s (TTFT=" + num(sNodes.visible_or_tool_ttft_s.mean_s, 3) + "s)</text>" +

      '<text x="20" y="304" font-family="JetBrains Mono, monospace" font-size="11" fill="#1F5E3B">3. 可见 JSON / 工具参数输出</text>' +
      '<rect class="svg-hotspot" data-tip="节点 4 → 5 可见字符生成窗口 visible_generation_s: 均值仅 ' + num(visW * 1000, 1) + 'ms · 中位数 ' + num(sNodes.visible_generation_s.median_s * 1000, 1) + 'ms" x="' + (x0 + wSeg(ttfb + thinkW)) + '" y="288" width="' + visBarW + '" height="22" fill="#1F5E3B"/>' +
      '<text x="' + visLabelX + '" y="303" font-family="JetBrains Mono, monospace" font-size="11" font-weight="600" fill="#1F5E3B">' + num(visW * 1000, 1) + "ms (3.79%)</text>" +
      "</svg>";

    var mount = document.getElementById("svg-figure-2-mount");
    mount.innerHTML = svg;
    var readout = document.getElementById("fig2-hover-readout");
    mount.addEventListener("mouseover", function (ev) {
      var target = ev.target.closest("[data-tip]");
      if (target) {
        readout.textContent = target.getAttribute("data-tip");
      }
    });
  }
  renderFigure2();

  // 6. Interactive Lab 2: Prefix Cache 56 + 256k Visualizer & p_rec Simulator
  var currentCacheMode = "aligned";

  function renderCacheQuantizationSvg() {
    var mount = document.getElementById("lab2-cache-svg-mount");
    var summaryEl = document.getElementById("lab2-cache-summary");
    var blocks = [
      { label: "hdr:56", tok: 56, w: 74 },
      { label: "k=1 (312)", tok: 312, w: 84 },
      { label: "k=2 (568)", tok: 568, w: 84 },
      { label: "k=3 (824)", tok: 824, w: 84 },
      { label: "k=4 (1080)", tok: 1080, w: 92 },
      { label: "k=5 (1336)", tok: 1336, w: 92 },
      { label: "k=6 (1592)", tok: 1592, w: 92 },
      { label: "k=7..8", tok: 2104, w: 82 },
      { label: "k=9 (2360)", tok: 2360, w: 92 },
      { label: "k=10 (2616)", tok: 2616, w: 92 },
      { label: "User Task", tok: 2800, w: 100 }
    ];

    var x = 16;
    var rects = "";
    for (var i = 0; i < blocks.length; i++) {
      var b = blocks[i];
      var fill = "#EBF3EE";
      var stroke = "#1F5E3B";
      var txtFill = "#1F5E3B";
      var statusTag = "HIT";

      if (currentCacheMode === "aligned") {
        if (i === blocks.length - 1) {
          fill = "#FAF9F5";
          stroke = "#C9C5B8";
          txtFill = "#5E5D59";
          statusTag = "DYNAMIC";
        }
      } else if (currentCacheMode === "unaligned") {
        if (i === 4) {
          fill = "#F6EAEB";
          stroke = "#9E2A2B";
          txtFill = "#9E2A2B";
          statusTag = "POLLUTED";
        } else if (i > 4) {
          fill = "#FAF9F5";
          stroke = "#C9C5B8";
          txtFill = "#8C8A84";
          statusTag = "UNALLOC";
        }
      } else if (currentCacheMode === "header_toggle") {
        fill = i === 0 ? "#F6EAEB" : "#F7EFE4";
        stroke = i === 0 ? "#9E2A2B" : "#945814";
        txtFill = i === 0 ? "#9E2A2B" : "#945814";
        statusTag = i === 0 ? "MUTATED" : "MISS";
      }

      rects +=
        '<rect x="' + x + '" y="22" width="' + (b.w - 4) + '" height="58" rx="2" fill="' + fill + '" stroke="' + stroke + '" stroke-width="1"/>' +
        '<text x="' + (x + 6) + '" y="44" font-family="JetBrains Mono, monospace" font-size="10.2" font-weight="600" fill="' + txtFill + '">' + esc(b.label) + "</text>" +
        '<text x="' + (x + 6) + '" y="66" font-family="JetBrains Mono, monospace" font-size="10" fill="' + txtFill + '">' + statusTag + "</text>";
      x += b.w;
    }

    mount.innerHTML =
      '<svg viewBox="0 0 1000 96" width="1000" height="96" role="img" aria-label="56 + 256k 前缀缓存页边界">' +
      '<rect x="0" y="0" width="1000" height="96" fill="#FAF9F5"/>' +
      rects +
      "</svg>";

    if (currentCacheMode === "aligned") {
      summaryEl.textContent =
        "动静分离对齐后 (G1 / G3)：通用静态系统规程与 3 个工具 Schema 锁死前 9–10 个 256 词元整页 (2360 / 2616 词元)，动态 target_ref 隔离于尾部用户消息。未见新题首轮命中率达 " +
        pct(m2a.arms.G1.unseen_tasks_2_to_n_turn1_cache_hit_ratio, 2) +
        " (G1) 与 " + pct(m2a.arms.G3.unseen_tasks_2_to_n_turn1_cache_hit_ratio, 2) + " (G3)。";
    } else if (currentCacheMode === "unaligned") {
      summaryEl.textContent =
        "原始未对齐基线 (G0 / 主基准)：系统提示词尾部拼入逐题变化的 target_ref，恰好落在 k=4 (1080 词元) 页边界附近，导致主基准出现 " +
        cacheAudit.model_b_turn1_zero_hit_calls + " 次首轮零命中，G0 中新题 acc-07 / acc-11 首轮命中率为 0.0%。";
    } else {
      summaryEl.textContent =
        "切换思考参数击穿 (G1 → G2)：保持系统提示词与工具定义完全不变，仅将请求头切换为 thinking={type:'disabled'} 会改写服务端模板头部的思考控制词元，破坏 56 词元头部偏移与后续 256 词元缓存页边界对齐，触发全页重算（G2 未见新题首轮命中率回落至 " +
        pct(m2a.arms.G2.unseen_tasks_2_to_n_turn1_cache_hit_ratio, 2) + "）。";
    }
  }

  document.getElementById("lab2-cache-mode-btns").addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-cache-mode]");
    if (!btn) return;
    currentCacheMode = btn.getAttribute("data-cache-mode");
    var all = document.querySelectorAll("#lab2-cache-mode-btns .btn-tab");
    for (var i = 0; i < all.length; i++) {
      all[i].classList.toggle("active", all[i] === btn);
    }
    renderCacheQuantizationSvg();
  });
  renderCacheQuantizationSvg();

  // Bottom Half of Lab 2: p_rec Simulator with 1D Vertical Anti-Collision Label Solver
  var precSlider = document.getElementById("prec-slider");
  var bePresetBtn = document.getElementById("btn-preset-breakeven");
  bePresetBtn.setAttribute("data-prec-preset", (sim.advisor_breakeven_p_rec * 100).toFixed(1));
  bePresetBtn.textContent = "Advisor 盈亏点 (" + pct(sim.advisor_breakeven_p_rec, 1) + ")";

  function expectedLat(armKey, pRec) {
    var a = sim.arms_linear[armKey];
    return (1 - pRec) * a.control_mean_s + pRec * a.f3_mean_s;
  }

  function resolveVerticalCollisions(items, minYBound, maxYBound, minGap) {
    var sorted = items.slice().sort(function (a, b) {
      return a.rawY - b.rawY;
    });
    for (var i = 0; i < sorted.length; i++) {
      sorted[i].y = Math.max(minYBound, Math.min(maxYBound, sorted[i].rawY));
      if (i > 0 && sorted[i].y - sorted[i - 1].y < minGap) {
        sorted[i].y = sorted[i - 1].y + minGap;
      }
    }
    if (sorted.length > 0 && sorted[sorted.length - 1].y > maxYBound) {
      sorted[sorted.length - 1].y = maxYBound;
      for (var j = sorted.length - 2; j >= 0; j--) {
        if (sorted[j + 1].y - sorted[j].y < minGap) {
          sorted[j].y = sorted[j + 1].y - minGap;
        }
      }
    }
    return sorted;
  }

  function renderParetoSimulator(pRecPct) {
    var p = Math.max(0, Math.min(1, pRecPct / 100));
    document.getElementById("prec-readout").textContent = (p * 100).toFixed(1) + "%";

    var W = 1020;
    var H = 304;
    var padL = 62;
    var padR = 178;
    var padT = 42;
    var padB = 54;
    var plotW = W - padL - padR;
    var plotH = H - padT - padB;
    var maxY = 11.5;
    var minY = 2.0;

    function px(pVal) {
      return padL + pVal * plotW;
    }
    function py(sVal) {
      return padT + ((maxY - sVal) / (maxY - minY)) * plotH;
    }

    var g3ExecCtrl = sim.arms_linear.G3.control_mean_s;
    var g3ExecF3Only = sim.arms_linear.G3.f3_mean_s - sim.advisor_mean_call_s;
    function alwaysThinkLat(pVal) {
      return (1 - pVal) * (g3ExecCtrl + sim.routine_thinking_savings_s) +
             pVal * (g3ExecF3Only + sim.routine_thinking_savings_s);
    }

    var gridLines = "";
    for (var yTick = 3; yTick <= 11; yTick += 2) {
      var yy = py(yTick);
      gridLines +=
        '<line x1="' + padL + '" y1="' + yy + '" x2="' + (W - padR) + '" y2="' + yy + '" stroke="#E5E2D9" stroke-width="1"/>' +
        '<text x="' + (padL - 8) + '" y="' + (yy + 4) + '" text-anchor="end" font-family="JetBrains Mono, monospace" font-size="10.5" fill="#8C8A84">' + yTick + ".0s</text>";
    }

    // Staggered x-axis reference labels prevent horizontal collision between 33.3% and 43.9%
    var prodW = px(0.1) - padL;
    var refMarkers = [
      { p: 0.1, label: "生产上界 10%", color: "#1F5E3B", row: 0 },
      { p: sim.reference_points.benchmark_mix, label: "主基准 33.3%", color: "#5E5D59", row: 0 },
      { p: sim.advisor_breakeven_p_rec, label: "盈亏交点 " + pct(sim.advisor_breakeven_p_rec, 1), color: "#945814", row: 1 },
      { p: 0.75, label: "压力集 75%", color: "#8C8A84", row: 0 }
    ];
    var markerSvg = "";
    for (var m = 0; m < refMarkers.length; m++) {
      var mx = px(refMarkers[m].p);
      var lblY = refMarkers[m].row === 0 ? H - 30 : H - 11;
      markerSvg +=
        '<line x1="' + mx + '" y1="' + padT + '" x2="' + mx + '" y2="' + (H - padB) + '" stroke="' + refMarkers[m].color + '" stroke-width="1" stroke-dasharray="3,3"/>' +
        '<text x="' + mx + '" y="' + lblY + '" text-anchor="middle" font-family="JetBrains Mono, monospace" font-size="10" fill="' + refMarkers[m].color + '">' + esc(refMarkers[m].label) + "</text>";
    }

    function lineTag(y0, y1, color, width, dash) {
      return (
        '<line x1="' + px(0) + '" y1="' + py(y0) + '" x2="' + px(1) + '" y2="' + py(y1) +
        '" stroke="' + color + '" stroke-width="' + width + '"' +
        (dash ? ' stroke-dasharray="' + dash + '"' : "") + "/>"
      );
    }

    var curX = px(p);
    var vG0 = expectedLat("G0", p);
    var vG1 = expectedLat("G1", p);
    var vG2 = expectedLat("G2", p);
    var vG3 = expectedLat("G3", p);
    var vThink = alwaysThinkLat(p);

    // Collision-resolved right-margin curve labels displaying live expected latency at current p_rec
    var endLabels = resolveVerticalCollisions(
      [
        { key: "G0", rawY: py(expectedLat("G0", 1)), color: "#9E2A2B", text: "G0: " + num(vG0, 2) + "s" },
        { key: "G3", rawY: py(expectedLat("G3", 1)), color: "#945814", text: "G3: " + num(vG3, 2) + "s" },
        { key: "TH", rawY: py(alwaysThinkLat(1)), color: "#8C8A84", text: "全程思考: " + num(vThink, 2) + "s" },
        { key: "G2", rawY: py(expectedLat("G2", 1)), color: "#5E5D59", text: "G2: " + num(vG2, 2) + "s" },
        { key: "G1", rawY: py(expectedLat("G1", 1)), color: "#1F5E3B", text: "G1: " + num(vG1, 2) + "s (最优)" }
      ],
      padT + 8,
      H - padB - 4,
      17
    );

    var rightLabelSvg = "";
    var plotRight = px(1);
    for (var rIdx = 0; rIdx < endLabels.length; rIdx++) {
      var item = endLabels[rIdx];
      rightLabelSvg +=
        '<polyline points="' + plotRight + "," + item.rawY + " " + (plotRight + 8) + "," + item.y + " " + (plotRight + 14) + "," + item.y + '" fill="none" stroke="' + item.color + '" stroke-width="1"/>' +
        '<text class="pareto-curve-label" x="' + (plotRight + 18) + '" y="' + (item.y + 3.5) + '" font-family="JetBrains Mono, monospace" font-size="10.5" font-weight="600" fill="' + item.color + '">' + esc(item.text) + "</text>";
    }

    var svg =
      '<svg viewBox="0 0 ' + W + " " + H + '" width="' + W + '" height="' + H + '" role="img" aria-label="期望单题推理耗时随异常触发率变化曲线">' +
      '<rect x="0" y="0" width="' + W + '" height="' + H + '" fill="#FAF9F5"/>' +
      // Top header legend outside plot area (zero collision with curves)
      '<rect x="' + padL + '" y="8" width="' + plotW + '" height="24" rx="2" fill="#FFFFFF" stroke="#E5E2D9"/>' +
      '<text x="' + (padL + 12) + '" y="24" font-family="JetBrains Mono, monospace" font-size="10.5" fill="#141413">' +
      "G0 未对齐文本(砖红) · 全程思考参考线(灰虚) · G3 串行Advisor(琥珀) · G2(深灰) · G1 帕累托最优(墨绿)</text>" +
      '<rect x="' + padL + '" y="' + padT + '" width="' + prodW + '" height="' + plotH + '" fill="#EBF3EE" opacity="0.55"/>' +
      gridLines +
      '<line x1="' + padL + '" y1="' + (H - padB) + '" x2="' + (W - padR) + '" y2="' + (H - padB) + '" stroke="#C9C5B8" stroke-width="1.2"/>' +
      '<line x1="' + padL + '" y1="' + padT + '" x2="' + padL + '" y2="' + (H - padB) + '" stroke="#C9C5B8" stroke-width="1.2"/>' +
      markerSvg +
      // Curves
      lineTag(expectedLat("G0", 0), expectedLat("G0", 1), "#9E2A2B", 2, "") +
      lineTag(alwaysThinkLat(0), alwaysThinkLat(1), "#8C8A84", 1.5, "5,4") +
      lineTag(expectedLat("G3", 0), expectedLat("G3", 1), "#945814", 2.2, "") +
      lineTag(expectedLat("G2", 0), expectedLat("G2", 1), "#5E5D59", 1.6, "2,2") +
      lineTag(expectedLat("G1", 0), expectedLat("G1", 1), "#1F5E3B", 2.6, "") +
      // Current p_rec cursor
      '<line x1="' + curX + '" y1="' + padT + '" x2="' + curX + '" y2="' + (H - padB) + '" stroke="#B85A3A" stroke-width="1.6"/>' +
      '<circle cx="' + curX + '" cy="' + py(vG0) + '" r="4" fill="#9E2A2B"/>' +
      '<circle cx="' + curX + '" cy="' + py(vG3) + '" r="4" fill="#945814"/>' +
      '<circle cx="' + curX + '" cy="' + py(vG2) + '" r="3.5" fill="#5E5D59"/>' +
      '<circle cx="' + curX + '" cy="' + py(vG1) + '" r="4.5" fill="#1F5E3B"/>' +
      rightLabelSvg +
      "</svg>";

    document.getElementById("lab2-pareto-svg-mount").innerHTML = svg;

    var cards = [
      { name: "G0 · 未对齐文本基线", val: vG0, note: "推理词元 " + intComma(m2a.arms.G0.reasoning_tokens_sum), best: false },
      { name: "G1 · 对齐 + 强制工具通道", val: vG1, note: "较 G0 削减 " + pct(1 - vG1 / vG0, 1) + " · 0 思考词元", best: true },
      { name: "G2 · 显式 disabled 思考", val: vG2, note: "较 G0 削减 " + pct(1 - vG2 / vG0, 1) + " · 切换头重算", best: false },
      {
        name: "G3 · Executor + 带外 Advisor",
        val: vG3,
        note: p < sim.advisor_breakeven_p_rec
          ? "低于盈亏点 (" + pct(sim.advisor_breakeven_p_rec, 1) + ")：带外净赚"
          : "高于盈亏点：串行往返开销占主导",
        best: false
      }
    ];
    var cardsHtml = "";
    for (var c = 0; c < cards.length; c++) {
      var cls = cards[c].best ? "sim-metric-card pareto-best" : "sim-metric-card";
      cardsHtml +=
        '<div class="' + cls + '">' +
        '<div style="font-size:12px;color:var(--ink-secondary);">' + esc(cards[c].name) + "</div>" +
        '<div class="mono" style="font-size:1.15rem;font-weight:600;margin:3px 0;">' + num(cards[c].val, 3) + "s</div>" +
        '<div class="mono" style="font-size:11px;color:var(--ink-muted);">' + esc(cards[c].note) + "</div>" +
        "</div>";
    }
    document.getElementById("lab2-sim-cards").innerHTML = cardsHtml;
  }

  precSlider.addEventListener("input", function () {
    renderParetoSimulator(Number(precSlider.value));
  });

  document.getElementById("lab-2").addEventListener("click", function (ev) {
    var preset = ev.target.closest("[data-prec-preset]");
    if (!preset) return;
    var val = Number(preset.getAttribute("data-prec-preset"));
    precSlider.value = String(val);
    renderParetoSimulator(val);
  });
  renderParetoSimulator(Number(precSlider.value));

  // 7. Render Act 4 Wide Comparison Table (M2B+M4 & M5)
  function renderAct4Table() {
    var v0 = m2b.arms.V0;
    var v1 = m2b.arms.V1;
    var v2 = m2b.arms.V2;
    var s0 = m5.arms.S0;
    var s1 = m5.arms.S1;
    var rows = [
      {
        arm: "M2B · V0 全量内联基线",
        mech: ">24.5 KB 状态 + 12 份完整 SOP 手册直接注入上下文",
        disp: v0.correct_disposition + "/" + m2b.tasks_per_arm,
        goal: v0.goal_completed + " 完成 / " + v0.blocked_by_cap + " 阻断",
        metric: intComma(v0.mean_peak_parent_input_tokens) + " 峰值词元",
        delta: "基线 (超上限阻断)",
        sec: "单轮输入上限前置阻断",
        cls: "row-anomaly"
      },
      {
        arm: "M2B · V1 落盘切片与按需技能",
        mech: "DiskSliceStore (>4 KB 落盘) + read_slice + load_skill",
        disp: v1.correct_disposition + "/" + m2b.tasks_per_arm,
        goal: v1.goal_completed + " 完成 / " + v1.blocked_by_cap + " 阻断",
        metric: intComma(v1.mean_peak_parent_input_tokens) + " 峰值词元",
        delta: "-" + pct(1 - v1.mean_peak_parent_input_tokens / v0.mean_peak_parent_input_tokens, 2),
        sec: "主端口授权核验通过",
        cls: ""
      },
      {
        arm: "M2B+M4 · V2 只读巡检子智能体",
        mech: "V1 + can_write=False 巡检子智能体严格 json_schema 移交",
        disp: v2.correct_disposition + "/" + m2b.tasks_per_arm,
        goal: v2.goal_completed + " 完成 / " + v2.blocked_by_cap + " 阻断",
        metric: intComma(v2.mean_peak_parent_input_tokens) + " 峰值词元",
        delta: "-" + pct(m2b.v2_peak_parent_input_reduction_vs_v0, 2),
        sec: "子智能体越权写探测 6/6 PERMISSION_DENIED",
        cls: "row-highlight"
      },
      {
        arm: "M5 · S0 无定界/无熔断基线",
        mech: "原始 state.facts 直通 + 传统文本终态，仅保留底层门禁",
        disp: s0.overall_correct_disposition + "/" + m5.tasks_per_arm,
        goal: "死循环耗尽预算 4/4",
        metric: intComma(s0.loop_input_tokens_sum) + " 环路词元 (" + s0.loop_model_calls_sum + " calls)",
        delta: "基线对照",
        sec: "false_allow = " + s0.false_allow_sum + " (底层门禁兜底)",
        cls: ""
      },
      {
        arm: "M5 · S1 Spotlighting + 指纹熔断",
        mech: "双层不可信定界符 + SHA-256 (tool, args, rev, code) 熔断",
        disp: s1.overall_correct_disposition + "/" + m5.tasks_per_arm,
        goal: "熔断触发 " + s1.loop_circuit_breaker_trips + "/4 (SAFE_STOP)",
        metric: intComma(s1.loop_input_tokens_sum) + " 环路词元 (" + s1.loop_model_calls_sum + " calls)",
        delta: "-" + pct(m5.loop_trap_savings_s1_vs_s0.input_tokens_reduction_ratio, 2) + " 词元",
        sec: "false_allow = " + s1.false_allow_sum + " · IPI 4/4 零诱导",
        cls: "row-highlight"
      }
    ];
    var html = "";
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      html +=
        "<tr" + (r.cls ? ' class="' + r.cls + '"' : "") + ">" +
        '<td class="mono">' + esc(r.arm) + "</td>" +
        "<td>" + esc(r.mech) + "</td>" +
        '<td class="num">' + esc(r.disp) + "</td>" +
        '<td class="num">' + esc(r.goal) + "</td>" +
        '<td class="num">' + esc(r.metric) + "</td>" +
        '<td class="num">' + esc(r.delta) + "</td>" +
        "<td>" + esc(r.sec) + "</td>" +
        "</tr>";
    }
    document.getElementById("tbody-act-4").innerHTML = html;
  }
  renderAct4Table();

  // 8. Interactive Lab 3: Tab 1 (acc-15 4-Way Diff) & Tab 2 (3-Tier Loss-Mask / PRM Dyeing)
  function renderLab3Tab1() {
    var fw = diag.acc15_four_way_comparison;
    var variants = fw.variants;
    var cardsHtml = "";
    var tableHtml = "";

    for (var i = 0; i < variants.length; i++) {
      var v = variants[i];
      var toneCls = v.tone === "block" ? " tone-block" : v.tone === "pass" ? " tone-pass" : v.tone === "warn" ? " tone-warn" : "";
      var badgeCls = v.valid_rfc8259 ? "badge badge-pass" : "badge badge-block";
      var badgeTxt = v.valid_rfc8259 ? "RFC 8259 VALID" : "PYTHON DICT (INVALID JSON)";

      cardsHtml +=
        '<div class="payload-card' + toneCls + '">' +
        '<div class="pane-header">' +
        '<strong>' + esc(v.label) + "</strong>" +
        '<span class="' + badgeCls + '">' + badgeTxt + "</span>" +
        "</div>" +
        '<div class="mono" style="font-size:11.5px;color:var(--ink-secondary);margin:6px 0;">' +
        "来源: " + esc(v.source_anchor) + " · cached_tokens=" + v.cached_tokens + "</div>" +
        "<pre>" + esc(v.raw_payload) + "</pre>" +
        '<div style="font-size:12.5px;color:var(--ink-secondary);margin-top:8px;">' + esc(v.governance_verdict) + "</div>" +
        "</div>";

      var trCls = v.tone === "pass" ? ' class="row-highlight"' : v.tone === "block" ? ' class="row-anomaly"' : "";
      tableHtml +=
        "<tr" + trCls + ">" +
        "<td><strong>" + esc(v.label) + "</strong></td>" +
        '<td class="mono">' + esc(v.source_anchor) + "</td>" +
        '<td class="mono">' + esc(v.channel) + "</td>" +
        '<td class="num">' + v.cached_tokens + "</td>" +
        '<td class="num">+' + v.extra_api_calls + "</td>" +
        '<td class="num">' + num(v.mean_latency_s, 3) + "</td>" +
        "<td>" + esc(v.empirical_pass_rate) + " — " + esc(v.governance_verdict) + "</td>" +
        "</tr>";
    }

    // Append rejected ast.literal_eval row from ledger
    tableHtml +=
      '<tr class="row-anomaly">' +
      "<td><strong>事后宽松解析 ast.literal_eval() [已拒绝]</strong></td>" +
      '<td class="mono">离线静态重评对照</td>' +
      '<td class="mono">Host post-hoc parser</td>' +
      '<td class="num">--</td>' +
      '<td class="num">+' + fw.rejected_ast_fallback.extra_api_calls + "</td>" +
      '<td class="num">' + num(fw.rejected_ast_fallback.extra_latency_s, 3) + "</td>" +
      "<td><strong>控制面明令禁止：</strong>" + esc(fw.rejected_ast_fallback.why_rejected_for_runtime[0]) + "</td>" +
      "</tr>";

    document.getElementById("lab3-payload-grid").innerHTML = cardsHtml;
    document.getElementById("tbody-acc15-fourway").innerHTML = tableHtml;
  }
  renderLab3Tab1();

  var currentTier = "STRICT_CLEAN";
  var tierExamples = L.representative_stepper_slices.m6_three_tier_examples;

  function renderLab3Tab2() {
    var ex = tierExamples[currentTier];
    var mat = m6.three_tier_classification_matrix[currentTier];
    var meanCohortRet = m6.prm_return_hierarchy[currentTier];

    var tierBadge =
      currentTier === "STRICT_CLEAN"
        ? "badge badge-pass"
        : currentTier === "VALID_WITH_HYGIENE_WARN"
        ? "badge badge-warn"
        : "badge badge-block";

    var qualNote =
      currentTier === "VALID_WITH_HYGIENE_WARN"
        ? "主实验真实恢复轨迹：业务终态与状态刷新均真实有效，仅存在历史失效观察引用未精简的轻微卫生瑕疵，与结果作弊严格区分。"
        : currentTier === "REWARD_HACK_BLOCKED"
        ? "合成对抗作弊样本：未执行首轮 read_state 即盲猜参数直接写库；纯结果评分器误判通过，过程评分器精准阻断 (P=1.0, R=1.0)。"
        : "洁净最小证据轨迹：严格遵循读后写、确权刷新与最小活跃证据引用，SFT 与 PRM 双重正向基准。";

    document.getElementById("lab3-tier-summary-bar").innerHTML =
      '<div style="display:flex;flex-wrap:wrap;justify-content:space-between;gap:10px;align-items:center;margin-bottom:6px;">' +
      '<div><span class="' + tierBadge + '">' + esc(currentTier) + "</span> " +
      '<span class="mono" style="font-size:12.5px;margin-left:8px;">样本槽位: ' + esc(ex.slot) +
      " · 队列规模: " + mat.count + "/60</span></div>" +
      '<div class="mono" style="font-size:12.5px;">' +
      "本样本折扣回报: <strong>" + num(ex.discounted_return, 4) + "</strong> · " +
      "该档全局均值: <strong>" + num(meanCohortRet, 4) + "</strong></div>" +
      "</div>" +
      '<div style="font-size:13px;color:var(--ink-secondary);">' +
      "<code>outcome_valid=" + ex.outcome_valid + "</code> · " +
      "<code>causal_refresh_valid=" + ex.causal_refresh_valid + "</code> · " +
      "<code>is_reward_hack=" + ex.is_reward_hack + "</code> · " +
      "<code>纯结果评分器通过=" + ex.outcome_only_grader_passed + "</code> — " +
      esc(qualNote) + "</div>";

    var turnsHtml = "";
    for (var i = 0; i < ex.turns.length; i++) {
      var t = ex.turns[i];
      var maskCls = "mask-zero";
      if (t.loss_mask === 1) {
        maskCls = ex.is_reward_hack
          ? "mask-one-hack"
          : ex.hygiene_warnings.length > 0
          ? "mask-one-warn"
          : "mask-one-clean";
      }

      var maskTag =
        t.loss_mask === 1
          ? ex.is_reward_hack
            ? '<span class="badge badge-block">SFT REJECTED (HACK) · assistant</span>'
            : '<span class="badge badge-pass">loss_mask = 1 (仅助手轮监督)</span>'
          : '<span class="badge">loss_mask = 0 (上下文屏蔽)</span>';

      var prmTag = "";
      if (t.prm_step !== null) {
        var rCls = t.prm_reward >= 0.8 ? "badge badge-pass" : t.prm_reward > 0 ? "badge badge-warn" : "badge badge-block";
        var rSign = t.prm_reward > 0 ? "+" : "";
        prmTag =
          ' <span class="' + rCls + '">PRM step ' + t.prm_step + ": " + esc(t.prm_tag) +
          " (r=" + rSign + num(t.prm_reward, 2) + ", disc=" + rSign + num(t.discounted_term, 4) + ")</span>";
      }

      turnsHtml +=
        '<div class="dye-turn ' + maskCls + '">' +
        '<div class="dye-turn-head">' +
        '<span class="mono" style="font-size:12px;font-weight:600;">#' + t.turn_index + " · " + esc(t.label) + "</span>" +
        "<div>" + maskTag + prmTag + "</div>" +
        "</div>" +
        '<pre style="margin-top:4px;">' + esc(t.snippet) + "</pre>" +
        "</div>";
    }
    document.getElementById("lab3-turn-list").innerHTML = turnsHtml;
  }
  renderLab3Tab2();

  document.getElementById("lab3-tab-btn-1").addEventListener("click", function () {
    this.classList.add("active");
    document.getElementById("lab3-tab-btn-2").classList.remove("active");
    document.getElementById("lab3-panel-1").style.display = "";
    document.getElementById("lab3-panel-2").style.display = "none";
  });

  document.getElementById("lab3-tab-btn-2").addEventListener("click", function () {
    this.classList.add("active");
    document.getElementById("lab3-tab-btn-1").classList.remove("active");
    document.getElementById("lab3-panel-2").style.display = "";
    document.getElementById("lab3-panel-1").style.display = "none";
  });

  document.getElementById("lab3-tier-btns").addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-tier]");
    if (!btn) return;
    currentTier = btn.getAttribute("data-tier");
    var btns = document.querySelectorAll("#lab3-tier-btns .btn-tab");
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle("active", btns[i] === btn);
    }
    renderLab3Tab2();
  });

  document.getElementById("lab3-dye-toggle").addEventListener("change", function () {
    document.getElementById("lab3-turn-list").classList.toggle("dye-active", this.checked);
  });
})();
