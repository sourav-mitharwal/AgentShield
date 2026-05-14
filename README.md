# AgentShield — Action Firewall for Enterprise AI Agents

> **Track 1 — Agent Security & AI Governance** · lablab.ai TechEx Intelligent Enterprise Solutions Hackathon  
> Powered by **Veea / Lobster Trap**

AgentShield intercepts unsafe AI agent tool calls before they execute. Every action is evaluated against deterministic enterprise policy rules, enriched with real-time deep prompt inspection from Lobster Trap (Veea), and persisted in a tamper-evident audit trail. High-risk actions are routed to a Human Review queue.

---

## Live Deployment

| Component | URL |
|---|---|
| Frontend | https://agent-shield-1.vercel.app |
| Backend API | https://agentshield-api-3oc2.onrender.com |
| Health check | https://agentshield-api-3oc2.onrender.com/api/health |
| GitHub | https://github.com/sourav-mitharwal/AgentShield |

---

## Lobster Trap Integration (Veea)

AgentShield integrates **Lobster Trap** — Veea's open-source deep prompt inspection (DPI) engine — as a mandatory pre-screen layer on every action submitted to the Action Gate.

### What is Lobster Trap?

[Lobster Trap](https://github.com/veeainc/lobstertrap) is a Go-based security middleware that performs sub-millisecond deep prompt inspection using compiled regex patterns — no LLM calls, no external dependencies. It extracts structured metadata from any prompt text and evaluates it against configurable policy rules.

### How it is integrated in AgentShield

For every action submitted to `POST /api/action-gate` or `POST /api/run-attack`, AgentShield runs:

```
./bin/lobstertrap inspect --policy ./bin/lt_policy.yaml "<userPrompt>"
```

as a child process (`execFile`) **before** AgentShield's deterministic policy engine runs.

**Binary source:** Built from the official `veeainc/lobstertrap` GitHub repository source using:
```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o lobstertrap .
```
Committed to `bin/lobstertrap` (3.9 MB static ELF binary, MIT license permits redistribution).

**Policy file:** `bin/lt_policy.yaml` is the official `configs/default_policy.yaml` from the Lobster Trap repo.

### What Lobster Trap returns (real stdout/stderr format)

**stdout** — JSON PromptMetadata:
```json
{
  "intent_category": "general",
  "intent_confidence": 0.5,
  "risk_score": 0.35,
  "contains_obfuscation": true,
  "contains_sensitive_paths": false,
  "contains_credentials": false,
  "token_count": 17
}
```

**stderr** — Human-readable policy decision:
```
=== Policy Decision ===
  Action:  DENY
  Rule:    block_obfuscation_evasion
  Message: [LOBSTER TRAP] Blocked: obfuscation/evasion technique detected.
```

AgentShield parses both and stores the full analysis as `lobsterTrapAnalysis` in every audit entry.

### What each layer does

| Layer | Responsibility |
|---|---|
| **Lobster Trap** | DPI pre-screen: intent classification, risk scoring, 15+ boolean threat signals, matched ingress rule |
| **AgentShield** | Enterprise workflow: role/department policy, high-value finance thresholds, HUMAN_REVIEW routing, audit persistence, human review queue |

AgentShield makes the final ALLOW / DENY / HUMAN_REVIEW decision. Lobster Trap provides DPI enrichment signals. In the current MVP, AgentShield's deterministic rules are the policy authority — exactly as Veea's track description intends: *"Lobster Trap is the floor, not the ceiling."*

### Graceful degradation

If `bin/lobstertrap` is not found at runtime, AgentShield sets `lt_status: "unavailable"` in the audit entry and continues normally. The app never crashes due to LT failure.

### Real DPI results across the 6 demo scenarios

| Scenario | AgentShield | LT Action | LT Rule | LT Risk |
|---|---|---|---|---|
| Safe HR Summary | ALLOW | ALLOW | none | 0.000 |
| Salary External Email | DENY | ALLOW | none | 0.022 |
| Prompt Injection | DENY | **DENY** | block_obfuscation_evasion | 0.350 |
| API Key Extraction | DENY | **DENY** | block_sensitive_paths | 0.250 |
| Finance 85,000 Refund | HUMAN_REVIEW | ALLOW | none | 0.000 |
| Safe CRM Summary | ALLOW | ALLOW | none | 0.000 |

---

## Architecture

```
User / Attack Simulator
        |
        v
POST /api/action-gate
        |
        v
+------------------------------------------+
|  LOBSTER TRAP PRE-SCREEN (Veea)          |
|  ./bin/lobstertrap inspect               |
|  - intent_category, risk_score           |
|  - 15 DPI boolean signals                |
|  - matched ingress rule + action         |
|  Time: <5ms  No LLM  No network         |
|  Failure: graceful skip                  |
+------------------------------------------+
        |
        v
+------------------------------------------+
|  AGENTSHIELD POLICY ENGINE               |
|  Deterministic rule evaluation:          |
|  - agent role + department               |
|  - declared vs detected intent           |
|  - tool params (amount, destination)     |
|  - data sensitivity classification       |
|  Output: ALLOW / DENY / HUMAN_REVIEW     |
+------------------------------------------+
        |
        v
+------------------------------------------+
|  AUDIT ENTRY (persisted)                 |
|  All policy fields +                     |
|  lobsterTrapAnalysis: {                  |
|    lt_status, lt_intent_category,        |
|    lt_risk_score, lt_action,             |
|    lt_rule, lt_signals (15 booleans)     |
|  }                                       |
+------------------------------------------+
        |
        v
   Human Review Queue (if HUMAN_REVIEW)
   Audit Evidence UI (LT panel visible)
   Action Gate UI (LT pre-screen panel)
```

---

## Demo Scenarios

| # | Scenario | Decision | Policy |
|---|---|---|---|
| 1 | Safe HR internal summary | ALLOW | SAFE_INTERNAL_SUMMARY_ALLOWED |
| 2 | Salary data to external email | DENY | HR_SALARY_EXPORT_DENIED |
| 3 | Prompt injection attempt | DENY | BLOCK_PROMPT_INJECTION |
| 4 | .env / API key extraction | DENY | BLOCK_CREDENTIAL_ACCESS |
| 5 | Finance refund 85,000 | HUMAN_REVIEW | FINANCE_HIGH_VALUE_REVIEW |
| 6 | Safe CRM internal summary | ALLOW | SAFE_INTERNAL_SUMMARY_ALLOWED |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Tailwind CSS |
| Backend | Node.js, Express |
| DPI Engine | Lobster Trap (Veea, veeainc/lobstertrap, MIT) |
| Policy engine | Deterministic rule engine (AgentShield) |
| Audit persistence | JSON file, backend-authoritative |
| Frontend deploy | Vercel |
| Backend deploy | Render (linux/amd64) |

---

## Running Locally

```bash
# Backend
npm install
node src/server.js
# http://localhost:4000

# Frontend
cd frontend && npm install && npm run dev
# http://localhost:5173
```

The Lobster Trap binary (`bin/lobstertrap`) and policy (`bin/lt_policy.yaml`) are committed and work on any linux/amd64 host. The binary is statically linked — no Go runtime required.

---

## Redeployment

**Backend (Render):**
- Push to GitHub -> Render auto-redeploys
- `bin/lobstertrap` and `bin/lt_policy.yaml` are committed and available at runtime
- `GET /api/health` shows `lobsterTrap.status: "ready"` when binary is present

**Frontend (Vercel):**
- Push to GitHub -> Vercel auto-redeploys
- No new environment variables required
