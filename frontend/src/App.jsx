import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  ClipboardCheck,
  Database,
  FileJson,
  FileText,
  Gavel,
  Play,
  RefreshCcw,
  ShieldCheck,
  ShieldX,
  SlidersHorizontal,
  TerminalSquare
} from "lucide-react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:4000";
const API_ERROR = "Backend API failed. No backend audit was created.";

const sampleAction = {
  requestId: "ui-finance-refund-85000",
  agentRole: "FINANCE_AGENT",
  department: "FINANCE",
  declaredIntent: "issue_refund",
  userPrompt: "Create refund for enterprise customer amount INR 85000 due to billing reversal.",
  proposedTool: "finance.refund.create",
  toolParams: {
    amount: 85000,
    currency: "INR"
  },
  dataSensitivity: "financial"
};

const pages = [
  { id: "action", label: "Action Gate", icon: ShieldCheck },
  { id: "attacks", label: "Attack Simulator", icon: Play },
  { id: "audit", label: "Audit Evidence", icon: FileText },
  { id: "policies", label: "Policy Viewer", icon: ClipboardCheck },
  { id: "review", label: "Human Review", icon: Gavel }
];

async function api(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {})
    },
    ...options
  });

  if (!response.ok) {
    throw new Error(API_ERROR);
  }

  return response.json();
}

function cx(...classes) {
  return classes.filter(Boolean).join(" ");
}

function toneFor(value) {
  if (value === "ALLOW" || value === "EXECUTED" || value === "approved" || value === true) {
    return "border-emerald-400/30 bg-emerald-400/10 text-emerald-200";
  }

  if (value === "DENY" || value === "BLOCKED" || value === "rejected" || value === "denied" || value === false) {
    return "border-red-400/30 bg-red-400/10 text-red-200";
  }

  if (value === "HUMAN_REVIEW" || value === "PENDING_HUMAN_REVIEW" || value === "pending") {
    return "border-amber-400/30 bg-amber-400/10 text-amber-200";
  }

  return "border-slate-500/40 bg-slate-800 text-slate-300";
}

function StatusPill({ value, label }) {
  const displayValue = value === true || value === false ? String(value) : value || "unknown";

  return (
    <span
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold",
        toneFor(value)
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {label ? <span className="text-slate-400">{label}:</span> : null}
      <span>{displayValue}</span>
    </span>
  );
}

function ErrorBox({ message }) {
  if (!message) return null;
  return (
    <div className="rounded-md border border-red-400/30 bg-red-950/50 px-4 py-3 text-sm font-semibold text-red-100">
      {message}
    </div>
  );
}

function SectionTitle({ eyebrow, title, children }) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        {eyebrow ? <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-300">{eyebrow}</p> : null}
        <h2 className="mt-1 text-xl font-semibold text-white">{title}</h2>
      </div>
      {children}
    </div>
  );
}

function Card({ children, className = "" }) {
  return <section className={cx("rounded-lg border border-slate-700/80 bg-slate-900/80 shadow-panel", className)}>{children}</section>;
}

function Info({ label, value }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 break-words text-sm font-medium text-slate-100">{value ?? "none"}</dd>
    </div>
  );
}

function JsonBlock({ value, title = "Raw JSON", defaultOpen = false }) {
  return (
    <details className="rounded-md border border-slate-700 bg-slate-950/70" open={defaultOpen}>
      <summary className="flex cursor-pointer items-center gap-2 px-3 py-2 text-xs font-semibold uppercase tracking-wide text-slate-300">
        <FileJson size={14} />
        {title}
      </summary>
      <pre className="max-h-[320px] overflow-auto border-t border-slate-800 p-3 text-xs leading-5 text-slate-300">
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  );
}

function PrimaryButton({ children, className = "", ...props }) {
  return (
    <button
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-md border border-cyan-300/30 bg-cyan-300 px-3.5 py-2 text-sm font-semibold text-slate-950 shadow-sm transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60",
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

function SecondaryButton({ children, className = "", ...props }) {
  return (
    <button
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-md border border-slate-700 bg-slate-900 px-3.5 py-2 text-sm font-semibold text-slate-100 transition hover:border-slate-500 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-60",
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

// ─── Lobster Trap Analysis Panel ─────────────────────────────────────────────
// Renders the real Lobster Trap DPI output stored in each audit entry.
// Only visible when lobsterTrapAnalysis is present in the result object.
// AgentShield's ALLOW/DENY/HUMAN_REVIEW decision is always shown separately above.
// ─────────────────────────────────────────────────────────────────────────────
function LobsterTrapPanel({ lta }) {
  if (!lta) return null;

  const unavailable = lta.lt_status !== "ok";

  const activeSignals = lta.lt_signals
    ? Object.entries(lta.lt_signals)
        .filter(([key, val]) => {
          if (Array.isArray(val)) return val.length > 0;
          return val === true;
        })
        .map(([key]) => key.replace(/^contains_/, "").replace(/_/g, " "))
    : [];

  const ltActionColor =
    lta.lt_action === "DENY"
      ? "text-red-300"
      : lta.lt_action === "ALLOW"
      ? "text-emerald-300"
      : "text-amber-300";

  return (
    <div className="mt-4 rounded-md border border-violet-500/20 bg-violet-950/30">
      <div className="flex items-center gap-2 border-b border-violet-500/20 px-4 py-2.5">
        <span className="text-base leading-none">🦞</span>
        <span className="text-xs font-semibold uppercase tracking-wide text-violet-300">
          Lobster Trap DPI Pre-screen
        </span>
        <span className="ml-auto rounded border border-violet-500/30 bg-violet-900/40 px-1.5 py-0.5 text-xs font-medium text-violet-400">
          Veea / veeainc/lobstertrap
        </span>
      </div>

      {unavailable ? (
        <div className="px-4 py-3 text-xs text-slate-400">
          Lobster Trap:{" "}
          <span className="font-semibold text-slate-300">
            {lta.lt_status === "unavailable" ? "binary not found" : lta.lt_status}
          </span>
          {lta.lt_reason ? ` — ${lta.lt_reason}` : ""}
        </div>
      ) : (
        <div className="grid gap-4 px-4 py-3 sm:grid-cols-2">
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Intent category</dt>
            <dd className="mt-1 text-sm font-medium text-slate-100">{lta.lt_intent_category ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">LT risk score</dt>
            <dd className="mt-1 text-sm font-medium text-slate-100">
              {lta.lt_risk_score !== undefined ? lta.lt_risk_score.toFixed(3) : "—"}
            </dd>
          </div>
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">LT policy action</dt>
            <dd className={`mt-1 text-sm font-semibold ${ltActionColor}`}>{lta.lt_action ?? "—"}</dd>
          </div>
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Matched rule</dt>
            <dd className="mt-1 text-sm font-medium text-slate-100">{lta.lt_rule ?? "none"}</dd>
          </div>
          {lta.lt_deny_message ? (
            <div className="sm:col-span-2">
              <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">LT block message</dt>
              <dd className="mt-1 text-sm font-medium text-red-300">{lta.lt_deny_message}</dd>
            </div>
          ) : null}
          {activeSignals.length > 0 ? (
            <div className="sm:col-span-2">
              <dt className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-500">
                DPI signals detected
              </dt>
              <dd className="flex flex-wrap gap-1.5">
                {activeSignals.map((sig) => (
                  <span
                    key={sig}
                    className="inline-flex items-center rounded border border-violet-500/30 bg-violet-900/50 px-2 py-0.5 text-xs font-medium text-violet-200"
                  >
                    {sig}
                  </span>
                ))}
              </dd>
            </div>
          ) : (
            <div className="sm:col-span-2">
              <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">DPI signals</dt>
              <dd className="mt-1 text-xs text-slate-400">No threat signals detected</dd>
            </div>
          )}
          <div className="sm:col-span-2">
            <dt className="text-xs font-semibold uppercase tracking-wide text-slate-500">Token count</dt>
            <dd className="mt-1 text-xs text-slate-400">{lta.lt_token_count ?? "—"} tokens estimated</dd>
          </div>
        </div>
      )}
    </div>
  );
}
// ─────────────────────────────────────────────────────────────────────────────

function ResultPanel({ result, compact = false }) {
  if (!result) {
    return (
      <Card className="p-5">
        <div className="flex items-start gap-3 text-slate-400">
          <TerminalSquare className="mt-0.5 text-slate-500" size={18} />
          <div>
            <h3 className="font-semibold text-slate-200">Decision Summary</h3>
            <p className="mt-1 text-sm">Submit an action to receive a backend policy decision.</p>
          </div>
        </div>
      </Card>
    );
  }

  return (
    <Card className="overflow-hidden">
      <div className="border-b border-slate-800 bg-slate-950/40 p-5">
        <div className="flex flex-wrap items-center gap-2">
          <StatusPill value={result.decision} label="Decision" />
          <StatusPill value={result.executionStatus} label="Execution" />
          <StatusPill value={result.auditSavedToBackend} label="Audit saved" />
        </div>
        <p className="mt-4 text-sm leading-6 text-slate-300">{result.explanation}</p>
        <LobsterTrapPanel lta={result.lobsterTrapAnalysis} />
      </div>

      <div className="p-5">
        <dl className={cx("grid gap-4", compact ? "sm:grid-cols-2 xl:grid-cols-4" : "sm:grid-cols-2")}>
          <Info label="Policy" value={result.policyTriggered} />
          <Info label="Risk score" value={result.riskScore} />
          <Info label="Review status" value={result.reviewStatus} />
          <Info label="Audit id" value={result.id} />
        </dl>
      </div>
    </Card>
  );
}

function ActionGate() {
  const [payload, setPayload] = useState(JSON.stringify(sampleAction, null, 2));
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submitAction() {
    setBusy(true);
    setError("");
    setResult(null);

    try {
      const parsed = JSON.parse(payload);
      const data = await api("/api/action-gate", {
        method: "POST",
        body: JSON.stringify(parsed)
      });
      setResult(data);
    } catch (err) {
      setError(err instanceof SyntaxError ? "Payload must be valid JSON." : API_ERROR);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <SectionTitle eyebrow="Policy enforcement" title="Evaluate proposed tool actions before execution">
        <PrimaryButton onClick={submitAction} disabled={busy}>
          <ShieldCheck size={16} />
          Analyze Action
        </PrimaryButton>
      </SectionTitle>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_430px]">
        <Card className="overflow-hidden">
          <div className="border-b border-slate-800 bg-slate-950/40 px-5 py-4">
            <h3 className="font-semibold text-white">Proposed Action</h3>
            <p className="mt-1 text-sm text-slate-400">JSON payload sent directly to the backend action gate.</p>
          </div>
          <div className="p-5">
            <textarea
              className="min-h-[460px] w-full resize-y rounded-md border border-slate-700 bg-slate-950 p-4 font-mono text-sm leading-6 text-slate-100 outline-none transition focus:border-cyan-300/70 focus:ring-2 focus:ring-cyan-300/20"
              value={payload}
              onChange={(event) => setPayload(event.target.value)}
              spellCheck="false"
            />
          </div>
        </Card>

        <div className="space-y-4">
          <ErrorBox message={error} />
          <ResultPanel result={result} />
          {result ? <JsonBlock value={result} title="Backend response JSON" /> : null}
        </div>
      </div>
    </div>
  );
}

function AttackSimulator({ onAuditChanged }) {
  const [presets, setPresets] = useState([]);
  const [selected, setSelected] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api("/api/attack-presets")
      .then((data) => {
        setPresets(data);
        setSelected(data[0]?.id || "");
      })
      .catch(() => setError(API_ERROR));
  }, []);

  async function runAttack() {
    if (!selected) return;
    setBusy(true);
    setError("");
    setResult(null);

    try {
      const data = await api("/api/run-attack", {
        method: "POST",
        body: JSON.stringify({ presetId: selected })
      });
      setResult(data);
      onAuditChanged();
    } catch (_err) {
      setError(API_ERROR);
    } finally {
      setBusy(false);
    }
  }

  const activePreset = presets.find((preset) => preset.id === selected);

  return (
    <div>
      <SectionTitle eyebrow="Backend test cases" title="Run known attack and policy scenarios">
        <PrimaryButton onClick={runAttack} disabled={busy || !selected}>
          <Play size={16} />
          Run Selected Preset
        </PrimaryButton>
      </SectionTitle>

      <div className="grid gap-5 lg:grid-cols-[380px_minmax(0,1fr)]">
        <Card className="p-4">
          <div className="mb-4 rounded-md border border-cyan-300/20 bg-cyan-300/10 p-3 text-sm text-cyan-100">
            Presets are loaded from the backend and executed through <span className="font-semibold">/api/run-attack</span>.
          </div>
          <div className="grid gap-3">
            {presets.map((preset) => {
              const active = preset.id === selected;
              return (
                <button
                  key={preset.id}
                  className={cx(
                    "rounded-md border p-4 text-left transition",
                    active
                      ? "border-cyan-300/60 bg-cyan-300/10"
                      : "border-slate-700 bg-slate-950/40 hover:border-slate-500"
                  )}
                  onClick={() => setSelected(preset.id)}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h3 className="font-semibold text-white">{preset.name}</h3>
                      <p className="mt-1 text-xs uppercase tracking-wide text-slate-500">{preset.id}</p>
                    </div>
                    <ChevronRight className={active ? "text-cyan-300" : "text-slate-600"} size={18} />
                  </div>
                  <p className="mt-3 line-clamp-2 text-sm text-slate-400">{preset.payload?.userPrompt}</p>
                </button>
              );
            })}
          </div>
        </Card>

        <div className="space-y-4">
          <ErrorBox message={error} />
          {activePreset ? (
            <Card className="p-5">
              <div className="mb-4 flex flex-wrap items-center gap-2">
                <StatusPill value={activePreset.payload?.department} label="Department" />
                <StatusPill value={activePreset.payload?.dataSensitivity} label="Sensitivity" />
              </div>
              <dl className="grid gap-4 sm:grid-cols-2">
                <Info label="Agent" value={activePreset.payload?.agentRole} />
                <Info label="Tool action" value={activePreset.payload?.proposedTool} />
                <Info label="Declared intent" value={activePreset.payload?.declaredIntent} />
                <Info label="Request id" value={activePreset.payload?.requestId} />
              </dl>
              <p className="mt-4 rounded-md border border-slate-800 bg-slate-950/60 p-3 text-sm leading-6 text-slate-300">
                {activePreset.payload?.userPrompt}
              </p>
              <div className="mt-4">
                <JsonBlock value={activePreset.payload} title="Preset payload from backend" />
              </div>
            </Card>
          ) : null}
          <ResultPanel result={result} compact />
        </div>
      </div>
    </div>
  );
}

function AuditTable({ rows, onSelect, selectedId }) {
  if (!rows.length) {
    return <Card className="p-5 text-sm text-slate-400">No backend audit rows found.</Card>;
  }

  return (
    <div className="overflow-hidden rounded-lg border border-slate-700/80 bg-slate-900/80">
      <div className="overflow-x-auto">
        <table className="min-w-full border-collapse text-left text-sm">
          <thead className="bg-slate-950/70 text-xs uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-4 py-3">Time</th>
              <th className="px-4 py-3">Agent</th>
              <th className="px-4 py-3">Tool</th>
              <th className="px-4 py-3">Decision</th>
              <th className="px-4 py-3">Execution</th>
              <th className="px-4 py-3">Review</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {rows.map((row) => (
              <tr
                key={row.id}
                className={cx(
                  "cursor-pointer transition hover:bg-slate-800/70",
                  selectedId === row.id ? "bg-cyan-300/10 ring-1 ring-inset ring-cyan-300/30" : "bg-transparent"
                )}
                onClick={() => onSelect(row.id)}
              >
                <td className="whitespace-nowrap px-4 py-4 text-slate-400">{new Date(row.timestamp).toLocaleString()}</td>
                <td className="px-4 py-4 font-medium text-slate-100">{row.agentRole}</td>
                <td className="px-4 py-4 font-mono text-xs text-slate-300">{row.proposedTool}</td>
                <td className="px-4 py-4">
                  <StatusPill value={row.decision} />
                </td>
                <td className="px-4 py-4">
                  <StatusPill value={row.executionStatus} />
                </td>
                <td className="px-4 py-4 text-slate-300">{row.reviewStatus}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function ForensicsPanel({ selected }) {
  if (!selected) {
    return (
      <Card className="p-5">
        <p className="text-sm text-slate-400">Select an audit row to view full backend forensics.</p>
      </Card>
    );
  }

  return (
    <Card className="overflow-hidden">
      <div className="border-b border-slate-800 bg-slate-950/40 p-5">
        <h3 className="font-semibold text-white">Forensics</h3>
        <p className="mt-1 text-sm text-slate-400">{selected.id}</p>
      </div>
      <div className="space-y-5 p-5">
        <div>
          <h4 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Request</h4>
          <dl className="grid gap-3 sm:grid-cols-2">
            <Info label="Request id" value={selected.requestId} />
            <Info label="Timestamp" value={new Date(selected.timestamp).toLocaleString()} />
            <Info label="Agent" value={selected.agentRole} />
            <Info label="Department" value={selected.department} />
          </dl>
          <p className="mt-3 rounded-md border border-slate-800 bg-slate-950/60 p-3 text-sm leading-6 text-slate-300">
            {selected.userPrompt}
          </p>
        </div>

        <div>
          <h4 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Tool Action</h4>
          <dl className="grid gap-3 sm:grid-cols-2">
            <Info label="Tool" value={selected.proposedTool} />
            <Info label="Data sensitivity" value={selected.dataSensitivity} />
            <Info label="Declared intent" value={selected.declaredIntent} />
            <Info label="Detected intent" value={selected.detectedIntent} />
          </dl>
        </div>

        <div>
          <h4 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Decision</h4>
          <div className="flex flex-wrap gap-2">
            <StatusPill value={selected.decision} label="Decision" />
            <StatusPill value={selected.executionStatus} label="Execution" />
            <StatusPill value={selected.reviewStatus} label="Review" />
          </div>
          <p className="mt-3 text-sm leading-6 text-slate-300">{selected.explanation}</p>
        </div>

        <div>
          <h4 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Risk Breakdown</h4>
          <dl className="grid gap-3 sm:grid-cols-2">
            <Info label="Risk score" value={selected.riskScore} />
            <Info label="Policy" value={selected.policyTriggered} />
            {Object.entries(selected.riskBreakdown || {}).map(([key, value]) => (
              <Info key={key} label={key} value={value} />
            ))}
          </dl>
        </div>

        <div>
          <h4 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Lobster Trap DPI</h4>
          <LobsterTrapPanel lta={selected.lobsterTrapAnalysis} />
        </div>

        <div>
          <h4 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Audit Metadata</h4>
          <dl className="grid gap-3 sm:grid-cols-2">
            <Info label="Audit saved" value={String(selected.auditSavedToBackend)} />
            <Info label="Source" value={selected.source} />
            <Info label="Reasoning source" value={selected.reasoningSource} />
            <Info label="Threat types" value={(selected.threatTypes || []).join(", ") || "none"} />
          </dl>
        </div>

        <div>
          <h4 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">
            Lobster Trap DPI Analysis
          </h4>
          <LobsterTrapPanel lta={selected.lobsterTrapAnalysis} />
        </div>

        <JsonBlock value={selected} title="Full backend audit JSON" />
      </div>
    </Card>
  );
}

function AuditEvidence({ refreshKey }) {
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function loadAudit() {
    setBusy(true);
    setError("");

    try {
      const data = await api("/api/audit");
      setRows(data);
      setSelected((current) => {
        if (!current) return data[0] || null;
        return data.find((row) => row.id === current.id) || current;
      });
    } catch (_err) {
      setError(API_ERROR);
    } finally {
      setBusy(false);
    }
  }

  async function selectAudit(id) {
    setError("");
    try {
      const data = await api(`/api/audit/${id}`);
      setSelected(data);
    } catch (_err) {
      setError(API_ERROR);
    }
  }

  useEffect(() => {
    loadAudit();
  }, [refreshKey]);

  return (
    <div>
      <SectionTitle eyebrow="Backend evidence" title="Audit trail and decision forensics">
        <SecondaryButton onClick={loadAudit} disabled={busy}>
          <RefreshCcw size={16} />
          Refresh
        </SecondaryButton>
      </SectionTitle>
      <ErrorBox message={error} />
      <div className="mt-4 grid gap-5 xl:grid-cols-[minmax(0,1fr)_460px]">
        <AuditTable rows={rows} onSelect={selectAudit} selectedId={selected?.id} />
        <ForensicsPanel selected={selected} />
      </div>
    </div>
  );
}

function policyAction(policy) {
  if (policy.code?.includes("DENIED") || policy.code?.startsWith("BLOCK")) return "Deny";
  if (policy.code?.includes("REVIEW")) return "Human review";
  return "Allow";
}

function PolicyViewer() {
  const [policies, setPolicies] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api("/api/policies")
      .then(setPolicies)
      .catch(() => setError(API_ERROR));
  }, []);

  return (
    <section>
      <SectionTitle eyebrow="Policy source" title="Deterministic action firewall policies" />
      <ErrorBox message={error} />
      <div className="mt-4 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {policies.map((policy) => (
          <Card key={policy.code} className="p-5">
            <div className="mb-4 flex items-start justify-between gap-3">
              <div className="rounded-md border border-slate-700 bg-slate-950/60 p-2 text-cyan-300">
                <SlidersHorizontal size={18} />
              </div>
              <StatusPill value={policyAction(policy)} />
            </div>
            <p className="font-mono text-sm font-semibold text-white">{policy.code}</p>
            <p className="mt-3 text-sm leading-6 text-slate-300">{policy.description}</p>
          </Card>
        ))}
      </div>
    </section>
  );
}

function promptSummary(prompt) {
  if (!prompt) return "none";
  return prompt.length > 150 ? `${prompt.slice(0, 150)}...` : prompt;
}

function HumanReview({ refreshKey, onAuditChanged }) {
  const [rows, setRows] = useState([]);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState("");

  async function loadPending() {
    setError("");
    try {
      const data = await api("/api/audit");
      setRows(data.filter((row) => row.reviewStatus === "pending"));
    } catch (_err) {
      setError(API_ERROR);
    }
  }

  async function review(row, reviewDecision) {
    setBusyId(row.id);
    setError("");

    try {
      await api(`/api/review/${row.id}`, {
        method: "PATCH",
        body: JSON.stringify({
          reviewDecision,
          reviewer: "AgentShield reviewer",
          notes: `${reviewDecision} from Human Review UI`
        })
      });
      await loadPending();
      onAuditChanged();
    } catch (_err) {
      setError(API_ERROR);
    } finally {
      setBusyId("");
    }
  }

  useEffect(() => {
    loadPending();
  }, [refreshKey]);

  return (
    <section>
      <SectionTitle eyebrow="Approval queue" title="Human review">
        <div className="flex items-center gap-3">
          <div className="rounded-full border border-amber-400/30 bg-amber-400/10 px-3 py-1.5 text-sm font-semibold text-amber-100">
            {rows.length} pending
          </div>
          <SecondaryButton onClick={loadPending}>
            <RefreshCcw size={16} />
            Refresh
          </SecondaryButton>
        </div>
      </SectionTitle>
      <ErrorBox message={error} />
      <div className="mt-4 grid gap-4">
        {rows.length ? (
          rows.map((row) => (
            <Card key={row.id} className="p-5">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="min-w-0 flex-1">
                  <div className="mb-3 flex flex-wrap gap-2">
                    <StatusPill value={row.decision} />
                    <StatusPill value={row.executionStatus} />
                    <StatusPill value={row.auditSavedToBackend} label="Audit saved" />
                  </div>
                  <h3 className="font-mono text-sm font-semibold text-white">{row.proposedTool}</h3>
                  <p className="mt-2 text-sm leading-6 text-slate-300">{promptSummary(row.userPrompt)}</p>
                </div>
                <div className="flex gap-2">
                  <PrimaryButton
                    className="bg-emerald-300 hover:bg-emerald-200"
                    disabled={busyId === row.id}
                    onClick={() => review(row, "approved")}
                  >
                    <CheckCircle2 size={16} />
                    Approve
                  </PrimaryButton>
                  <button
                    className="inline-flex items-center justify-center gap-2 rounded-md border border-red-400/30 bg-red-500 px-3.5 py-2 text-sm font-semibold text-white transition hover:bg-red-400 disabled:cursor-not-allowed disabled:opacity-60"
                    disabled={busyId === row.id}
                    onClick={() => review(row, "rejected")}
                  >
                    <ShieldX size={16} />
                    Reject
                  </button>
                </div>
              </div>

              <dl className="mt-5 grid gap-4 border-t border-slate-800 pt-5 text-sm md:grid-cols-5">
                <Info label="Policy" value={row.policyTriggered} />
                <Info label="Risk score" value={row.riskScore} />
                <Info label="Reason" value={row.explanation} />
                <Info label="Department" value={row.department} />
                <Info label="Audit id" value={row.id} />
              </dl>
            </Card>
          ))
        ) : (
          <Card className="p-6">
            <div className="flex items-start gap-3 text-slate-400">
              <CheckCircle2 className="mt-0.5 text-emerald-300" size={20} />
              <div>
                <h3 className="font-semibold text-slate-100">No pending backend review rows</h3>
                <p className="mt-1 text-sm">Queue is sourced from backend audit rows where reviewStatus is pending.</p>
              </div>
            </div>
          </Card>
        )}
      </div>
    </section>
  );
}

export default function App() {
  const [page, setPage] = useState("action");
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState("");
  const [refreshKey, setRefreshKey] = useState(0);

  function markAuditChanged() {
    setRefreshKey((value) => value + 1);
  }

  useEffect(() => {
    api("/api/health")
      .then(setHealth)
      .catch(() => setHealthError(API_ERROR));
  }, []);

  const activeTitle = useMemo(() => pages.find((item) => item.id === page)?.label, [page]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-950/95">
        <div className="mx-auto max-w-7xl px-4 py-5">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div className="max-w-3xl">
              <div className="flex items-center gap-3">
                <div className="rounded-md border border-cyan-300/30 bg-cyan-300/10 p-2 text-cyan-300">
                  <ShieldCheck size={22} />
                </div>
                <div>
                  <p className="text-xl font-semibold tracking-tight text-white">AgentShield</p>
                  <p className="text-sm font-medium text-cyan-200">Action Firewall for Enterprise AI Agents</p>
                </div>
              </div>
              <p className="mt-4 text-sm leading-6 text-slate-400">
                Intercepts unsafe tool calls before your AI agent can execute them.
              </p>
            </div>
            <div className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-semibold text-slate-300">
              {health ? (
                <span className="inline-flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-emerald-300" />
                  Backend {health.status} · 🦞 LT{" "}
                  {health.lobsterTrap?.status === "ready" ? (
                    <span className="text-violet-300">ready</span>
                  ) : (
                    <span className="text-slate-400">unavailable</span>
                  )}
                </span>
              ) : (
                <span className="inline-flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-red-300" />
                  {healthError || "Checking backend"}
                </span>
              )}
            </div>
          </div>

          <nav className="mt-5 flex flex-nowrap gap-2 overflow-x-auto pb-1">
            {pages.map((item) => {
              const Icon = item.icon;
              const active = item.id === page;
              return (
                <button
                  key={item.id}
                  className={cx(
                    "inline-flex shrink-0 items-center gap-2 rounded-md border px-3 py-2 text-sm font-semibold transition",
                    active
                      ? "border-cyan-300/60 bg-cyan-300 text-slate-950"
                      : "border-slate-700 bg-slate-900 text-slate-300 hover:border-slate-500 hover:bg-slate-800"
                  )}
                  onClick={() => setPage(item.id)}
                >
                  <Icon size={16} />
                  {item.label}
                </button>
              );
            })}
          </nav>
        </div>
      </header>

      <main className="mx-auto max-w-7xl px-4 py-6">
        <div className="sr-only">{activeTitle}</div>
        {page === "action" ? <ActionGate /> : null}
        {page === "attacks" ? <AttackSimulator onAuditChanged={markAuditChanged} /> : null}
        {page === "audit" ? <AuditEvidence refreshKey={refreshKey} /> : null}
        {page === "policies" ? <PolicyViewer /> : null}
        {page === "review" ? <HumanReview refreshKey={refreshKey} onAuditChanged={markAuditChanged} /> : null}
      </main>
    </div>
  );
}
