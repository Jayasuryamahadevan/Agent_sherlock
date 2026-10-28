"""Command-line entry point: run one of the three pipelines.

Examples (PowerShell):
  python -m diagnostic_intelligence.cli --pipeline automatic_execution "My laptop is slow"
  python -m diagnostic_intelligence.cli --pipeline auto_resolution --allow-changes "No internet"
  python -m diagnostic_intelligence.cli --pipeline whitelist_approval --allow-changes "Printing stopped"
  python -m diagnostic_intelligence.cli --simulate dns_cache_stale --pipeline auto_resolution --reasoning rules "x"
"""

from __future__ import annotations

import argparse
import json
import sys

from diagnostic_intelligence.agent.llm import OllamaClient
from diagnostic_intelligence.agent.models import ReasoningMode, SessionReport
from diagnostic_intelligence.agent.pipelines import PIPELINES
from diagnostic_intelligence.agent.reasoning import AIReasoner
from diagnostic_intelligence.agent.runtime import RuntimeConfig, make_pipeline, make_reasoner
from diagnostic_intelligence.remediation.approval import ConsoleApprovalProvider, ScriptedApprovalProvider
from diagnostic_intelligence.simulation.host import SCENARIOS


def format_report(report: SessionReport) -> str:
    lines = [
        "",
        f"Pipeline : {report.pipeline['name']}  (system changes: {report.pipeline['system_changes']})",
        f"Reasoning: {report.reasoning_mode.value}" + (f" ({report.reasoning_model})" if report.reasoning_model else ""),
        f"Status   : {report.status.value}",
        f"Result   : {report.headline}",
    ]
    if report.diagnosis:
        lines.append("\nDiagnosis:")
        for hypothesis in report.diagnosis:
            lines.append(f"  - {hypothesis.title} [{hypothesis.confidence.value}] ({hypothesis.cause_id})")
            lines.append(f"    {hypothesis.explanation}")
            for observation in hypothesis.observations:
                lines.append(f"    evidence: {observation.evidence_id} {observation.field} = {observation.value}")
    lines.append(f"\nUncertainty: {report.uncertainty}")
    if report.recommendation:
        rec = report.recommendation
        lines.append(f"\nRecommended (not executed): {rec['title']} {rec['parameters'] or ''} - {rec['rationale']}")
    for attempt in report.actions:
        verdict = attempt.verification.verdict.value if attempt.verification else "n/a"
        lines.append(f"\nAction {attempt.attempt_number}: {attempt.decision.action_id} {attempt.decision.parameters or ''}")
        lines.append(f"  {attempt.outcome} (verification: {verdict})")
        for detail in (attempt.verification.details if attempt.verification else []):
            lines.append(f"    {detail}")
    for refused in report.refused_proposals:
        lines.append(f"\nRefused: {refused.decision.action_id} - {'; '.join(refused.decision.reasons)}")
    if report.rule_cross_check:
        ids = [f["cause_id"] for f in report.rule_cross_check.findings] or ["(none)"]
        lines.append(f"\nRule cross-check: {', '.join(ids)}; agrees with AI: {report.rule_cross_check.agrees_with_reasoner}")
    if report.clarification_question:
        lines.append(f"\nQuestion: {report.clarification_question}")
    for warning in report.warnings[:10]:
        lines.append(f"warning: {warning}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="diagnostic_intelligence.cli", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("complaint", help="Describe the Windows problem in plain language.")
    parser.add_argument("--pipeline", choices=sorted(PIPELINES), required=True)
    parser.add_argument("--reasoning", choices=[m.value for m in ReasoningMode], default="ai",
                        help="'ai' uses the language model (default). 'rules' is an explicit offline mode.")
    parser.add_argument("--allow-changes", action="store_true",
                        help="Allow real system changes (otherwise actions report 'disabled').")
    parser.add_argument("--simulate", choices=sorted(SCENARIOS), help="Use a simulated host instead of this machine.")
    parser.add_argument("--auto-approve", choices=["yes", "no"], help="Non-interactive approval (testing only).")
    parser.add_argument("--audit-dir", default="audit_logs")
    parser.add_argument("--json", action="store_true", help="Print the full JSON report.")
    args = parser.parse_args(argv)

    config = RuntimeConfig(
        backend="simulated" if args.simulate else "windows",
        scenario=args.simulate or "dns_cache_stale",
        reasoning=ReasoningMode(args.reasoning),
        allow_system_changes=args.allow_changes,
        audit_dir=args.audit_dir,
    )
    if config.reasoning == ReasoningMode.AI:
        client = OllamaClient()
        ok, detail = client.health()
        print(detail)
        if not ok:
            print("Cannot run in AI mode. Start Ollama, or choose --reasoning rules explicitly.", file=sys.stderr)
            return 2
    provider = (ScriptedApprovalProvider(args.auto_approve == "yes", "cli-auto") if args.auto_approve
                else ConsoleApprovalProvider())
    pipeline, _ = make_pipeline(args.pipeline, config, reasoner=make_reasoner(config.reasoning),
                                approval_provider=provider)
    session = pipeline.start(args.complaint)
    report = pipeline.report(session)
    print(report.model_dump_json(indent=2) if args.json else format_report(report))
    return 0 if report.status.value not in {"error", "reasoning_unavailable"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
