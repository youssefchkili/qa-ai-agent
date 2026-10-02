"""The local LLM layer.

Everything the model does goes through :class:`~qa_agent.llm.client.LLMClient`,
which enforces the rules that keep the model honest: temperature 0 with a fixed
seed, strict JSON replies, a hard context budget, and an audit record of every
prompt and response.
"""
