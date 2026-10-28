"""Simulated Windows host for safe, repeatable pipeline testing and demos."""

from diagnostic_intelligence.simulation.host import (
    SCENARIOS,
    SimulatedActionBackend,
    SimulatedEvidenceCollector,
    SimulatedHost,
    build_scenario,
)

__all__ = ["SCENARIOS", "SimulatedActionBackend", "SimulatedEvidenceCollector", "SimulatedHost", "build_scenario"]
