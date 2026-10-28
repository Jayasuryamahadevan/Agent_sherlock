from diagnostic_intelligence.agent.pipelines import build_pipeline
from diagnostic_intelligence.agent.reasoning import AIReasoner, RuleReasoner
from diagnostic_intelligence.remediation.approval import ScriptedApprovalProvider
from diagnostic_intelligence.simulation import SimulatedActionBackend, SimulatedEvidenceCollector, build_scenario
from tests.fakes import EvidenceDrivenLLM


def run(pipeline_id, scenario, *, llm=None, rules=False, approve=None, provider=None, complaint=None, tweak=None):
    host = build_scenario(scenario)
    if tweak:
        tweak(host)
    reasoner = RuleReasoner() if rules else AIReasoner(llm or EvidenceDrivenLLM())
    if provider is None and approve is not None:
        provider = ScriptedApprovalProvider(approve)
    pipeline = build_pipeline(
        pipeline_id,
        reasoner=reasoner,
        collector=SimulatedEvidenceCollector(host),
        backend=SimulatedActionBackend(host),
        approval_provider=provider,
    )
    session = pipeline.start(complaint or host.sample_complaint)
    return pipeline, session, pipeline.report(session), host
