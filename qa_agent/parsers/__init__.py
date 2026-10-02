"""Pure functions translating raw tool output into unified findings.

Parsers never touch the network or spawn processes: given a parsed JSON
document they return a list of :class:`~qa_agent.models.finding.Finding`. That
makes them testable against recorded fixtures, which is how the project reaches
its coverage target without needing Docker or a live scanner in CI.
"""
