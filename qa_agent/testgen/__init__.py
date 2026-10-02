"""LLM-planned, agent-compiled, sandbox-executed browser tests.

The model proposes user flows as a restricted JSON plan (dsl.py). The agent
validates the plan, compiles it into a Playwright script itself (compiler.py),
and runs that script in a separate process with a timeout (runner.py). The
model never writes code that gets executed.
"""
