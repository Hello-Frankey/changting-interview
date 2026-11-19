#!/usr/bin/env node

// OctoBus service package：把 Python 能力层暴露成 gRPC / Connect RPC / MCP。
//
// 这一层的职责只有三件事：
//   1. 参数转换（camelCase ↔ snake_case）
//   2. 调用 Python CLI 并解析 JSON
//   3. 把错误映射出去
//
// **这里不含任何判断逻辑。** 判定全部在 Python 侧读 knowledge/*.yaml 完成。
// 这样做的原因是：知识要能被消融、被审计，就不能散落在两种语言里。

import { execFileSync } from "node:child_process";
import path from "node:path";

import { defineService, runServiceMain } from "@chaitin-ai/octobus-sdk";

const PREFIX = "retest.v1.RetestService";

function pick(obj, camel, snake) {
  if (!obj) return undefined;
  return obj[camel] !== undefined ? obj[camel] : obj[snake];
}

function bridge(config, args) {
  if (!config || !config.repoRoot) {
    throw new Error("instance config.repoRoot is required");
  }
  const python = config.python || "python3";
  const cli = path.join(config.repoRoot, "tools", "retest_cli.py");
  let stdout;
  try {
    stdout = execFileSync(python, [cli, ...args], {
      cwd: config.repoRoot,
      encoding: "utf8",
      timeout: config.timeoutMs || 120000,
      maxBuffer: 8 * 1024 * 1024,
      env: { ...process.env, PYTHONPATH: config.repoRoot },
    });
  } catch (err) {
    const detail = err.stderr ? String(err.stderr).slice(0, 500) : "";
    throw new Error(`capability call failed: ${err.message} ${detail}`);
  }

  let parsed;
  try {
    parsed = JSON.parse(stdout);
  } catch (err) {
    throw new Error(`capability returned non-JSON: ${stdout.slice(0, 200)}`);
  }
  if (parsed.error) {
    throw new Error(parsed.error);
  }
  return parsed;
}

function toTicket(t) {
  return {
    caseId: t.case_id,
    lab: t.lab,
    asset: t.asset,
    vulnType: t.vuln_type,
    title: t.title,
    endpoint: t.endpoint,
    fixNote: t.fix_note,
    reportedVersion: t.reported_version,
  };
}

function toEvidence(e) {
  return {
    id: e.id,
    kind: e.kind,
    endpoint: e.endpoint,
    label: e.label,
    status: e.status ?? 0,
    count: e.count ?? 0,
    exploited: Boolean(e.exploited),
    blocked: Boolean(e.blocked),
    sha256: e.sha256 ?? "",
    bodyHead: e.body_head ?? "",
  };
}

const service = defineService({
  handlers: {
    [`${PREFIX}/ListTickets`]: (ctx) => {
      const data = bridge(ctx.config, ["tickets", "--lab", ctx.request.lab || "all"]);
      const tickets = (data.tickets || []).map(toTicket);
      return { tickets, count: tickets.length };
    },

    [`${PREFIX}/CollectEvidence`]: (ctx) => {
      const caseId = pick(ctx.request, "caseId", "case_id");
      const data = bridge(ctx.config, ["evidence", "--case", caseId]);
      const evidence = (data.evidence || []).map(toEvidence);
      return { evidence, count: evidence.length };
    },

    [`${PREFIX}/ComputeSignals`]: (ctx) => {
      const caseId = pick(ctx.request, "caseId", "case_id");
      const data = bridge(ctx.config, ["signals", "--case", caseId]);
      const signals = {};
      for (const [key, value] of Object.entries(data.signals || {})) {
        signals[key] = String(value);
      }
      return { signals };
    },

    [`${PREFIX}/Judge`]: (ctx) => {
      const caseId = pick(ctx.request, "caseId", "case_id");
      const d = bridge(ctx.config, ["judge", "--case", caseId]);
      return {
        verdict: d.verdict,
        pattern: d.pattern,
        ruleId: d.rule_id,
        confidence: d.confidence,
        humanReview: d.human_review,
        explanation: d.explanation,
        evidenceIds: d.evidence_ids || [],
        failureModes: d.failure_modes || [],
      };
    },

    [`${PREFIX}/ValidateReport`]: (ctx) => {
      const caseId = pick(ctx.request, "caseId", "case_id");
      const evidenceIds = pick(ctx.request, "evidenceIds", "evidence_ids") || [];
      const args = [
        "validate",
        "--case", caseId,
        "--verdict", ctx.request.verdict,
        "--pattern", ctx.request.pattern,
        "--evidence-ids", evidenceIds.join(","),
        "--explanation", ctx.request.explanation || "",
      ];
      const d = bridge(ctx.config, args);
      return {
        accepted: Boolean(d.accepted),
        violations: d.violations || [],
        toolVerdict: d.tool_verdict,
      };
    },
  },
});

runServiceMain(service);
