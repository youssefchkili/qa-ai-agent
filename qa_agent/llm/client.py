"""The one gateway between the pipeline and the local model.

Four rules are enforced here so that no caller can forget them:

1. **Determinism.** ``temperature=0`` *and* a fixed ``seed``. On this machine
   that combination returned byte-identical answers to identical prompts,
   which phase 3's run-to-run consistency metric depends on.
2. **Strict JSON.** Ollama's JSON mode is requested, the reply is parsed
   defensively, and a reply that still is not JSON is sent back once with the
   parse error. After that the call fails loudly; it never loops.
3. **A hard context budget.** Ollama silently drops the *start* of a prompt
   that exceeds the context window - the system prompt with all its rules
   goes first. The client estimates the size up front and refuses to send an
   oversized prompt, so callers split their batch instead.
4. **Auditability.** Every attempt, prompt and response is appended to the
   run's ``llm.jsonl``, so any sentence the model contributed to a report can
   be traced to the exact exchange that produced it.

The backend is the OpenAI Python client pointed at Ollama, so moving to vLLM
later is a configuration change.
"""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

from qa_agent.config import Settings
from qa_agent.llm.json_utils import extract_json
from qa_agent.llm.prompts import JSON_REPAIR
from qa_agent.logging_setup import get_logger

log = get_logger(__name__)

# Deliberately pessimistic: code, paths and JSON tokenise densely, and
# over-estimating only costs a smaller batch, while under-estimating costs a
# silently truncated prompt.
CHARS_PER_TOKEN = 3.0


class LLMError(RuntimeError):
    """Base class for every failure of the LLM layer."""


class LLMUnavailable(LLMError):
    """The model server could not be reached or rejected the request."""


class PromptTooLarge(LLMError):
    """The prompt plus the reply would not fit in the context window."""


class InvalidJSONReply(LLMError):
    """The model did not produce valid JSON, even after a repair attempt."""


def estimate_tokens(text: str) -> int:
    """Conservative token count for *text*."""
    return math.ceil(len(text) / CHARS_PER_TOKEN)


@dataclass(frozen=True)
class LLMReply:
    """A parsed reply plus the accounting needed for the audit trail."""

    data: Any
    raw: str
    attempts: int
    prompt_tokens: int
    completion_tokens: int
    duration_s: float


class LLMClient:
    """Sends strict-JSON prompts to the local model and records every exchange."""

    def __init__(
        self,
        settings: Settings,
        *,
        log_path: Path | None = None,
        backend: Any = None,
    ) -> None:
        self.settings = settings
        self.model = settings.llm_model
        self._log_path = log_path
        if backend is None:
            from openai import OpenAI

            backend = OpenAI(
                base_url=settings.llm_base_url,
                api_key=settings.llm_api_key,
                timeout=float(settings.llm_timeout_s),
                # Retries are handled here, visibly, not hidden in the SDK.
                max_retries=0,
            )
        self._backend = backend

    # ------------------------------------------------------------------ public
    def check_available(self) -> tuple[bool, str]:
        """Is the server up, and is the configured model already pulled?"""
        url = self.settings.ollama_host.rstrip("/") + "/api/tags"
        try:
            response = httpx.get(url, timeout=5.0)
            response.raise_for_status()
            names = {m.get("name", "") for m in response.json().get("models", [])}
        except Exception as exc:  # noqa: BLE001 - any failure means "not usable"
            return False, f"Ollama is not reachable at {self.settings.ollama_host} ({exc})"
        if self.model not in names and f"{self.model}:latest" not in names:
            return False, f"model '{self.model}' is not pulled (run: ollama pull {self.model})"
        return True, ""

    def fits(self, system: str, user: str, max_tokens: int | None = None) -> bool:
        """Whether this prompt and its reply fit inside the context window."""
        reply_budget = max_tokens or self.settings.llm_max_output_tokens
        needed = estimate_tokens(system) + estimate_tokens(user) + reply_budget
        return needed <= self.settings.llm_context_tokens

    def complete_json(
        self,
        *,
        system: str,
        user: str,
        purpose: str,
        max_tokens: int | None = None,
    ) -> LLMReply:
        """Ask the model for a JSON object and return it parsed.

        Raises :class:`PromptTooLarge` before sending anything that would be
        truncated, :class:`LLMUnavailable` on transport errors, and
        :class:`InvalidJSONReply` once the repair attempt is exhausted.
        """
        reply_budget = max_tokens or self.settings.llm_max_output_tokens
        if not self.fits(system, user, reply_budget):
            needed = estimate_tokens(system) + estimate_tokens(user) + reply_budget
            raise PromptTooLarge(
                f"{purpose}: ~{needed} tokens needed, context is "
                f"{self.settings.llm_context_tokens}"
            )

        messages: list[dict[str, str]] = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        started = time.perf_counter()
        prompt_total = completion_total = 0
        last_error = ""

        for attempt in range(1, self.settings.llm_json_retries + 2):
            call_started = time.perf_counter()
            raw, prompt_tokens, completion_tokens = self._call(messages, reply_budget)
            prompt_total += prompt_tokens
            completion_total += completion_tokens
            elapsed = time.perf_counter() - call_started

            try:
                data = extract_json(raw)
                last_error = "" if isinstance(data, dict) else (
                    "expected a JSON object at the top level"
                )
            except ValueError as exc:
                data, last_error = None, str(exc)

            if last_error:
                self._audit(
                    purpose, attempt, messages, raw,
                    prompt_tokens, completion_tokens, elapsed, last_error,
                )
                # Show the model its own reply and the exact parse error.
                messages = [
                    *messages,
                    {"role": "assistant", "content": raw},
                    {"role": "user", "content": JSON_REPAIR.format(error=last_error)},
                ]
                continue

            self._audit(
                purpose, attempt, messages, raw, prompt_tokens, completion_tokens, elapsed, ""
            )
            if prompt_tokens + reply_budget > self.settings.llm_context_tokens:
                log.warning(
                    "%s: prompt used %d tokens; the context may have been truncated",
                    purpose,
                    prompt_tokens,
                )
            return LLMReply(
                data=data,
                raw=raw,
                attempts=attempt,
                prompt_tokens=prompt_total,
                completion_tokens=completion_total,
                duration_s=round(time.perf_counter() - started, 2),
            )

        raise InvalidJSONReply(f"{purpose}: no valid JSON after repair ({last_error})")

    # ----------------------------------------------------------------- private
    def _call(self, messages: list[dict[str, str]], max_tokens: int) -> tuple[str, int, int]:
        try:
            response = self._backend.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self.settings.llm_temperature,
                seed=self.settings.llm_seed,
                max_tokens=max_tokens,
                # Ollama's JSON mode constrains decoding to valid JSON.
                response_format={"type": "json_object"},
            )
        except Exception as exc:  # normalised into one error type for every caller
            raise LLMUnavailable(f"the model call failed: {exc}") from exc

        content = (response.choices[0].message.content or "") if response.choices else ""
        usage = getattr(response, "usage", None)
        return (
            content,
            int(getattr(usage, "prompt_tokens", 0) or 0),
            int(getattr(usage, "completion_tokens", 0) or 0),
        )

    def _audit(
        self,
        purpose: str,
        attempt: int,
        messages: list[dict[str, str]],
        response: str,
        prompt_tokens: int,
        completion_tokens: int,
        duration_s: float,
        error: str,
    ) -> None:
        """Append one exchange to llm.jsonl. Auditing must never break a run."""
        if self._log_path is None:
            return
        record = {
            "ts": datetime.now(UTC).isoformat(),
            "purpose": purpose,
            "model": self.model,
            "attempt": attempt,
            "temperature": self.settings.llm_temperature,
            "seed": self.settings.llm_seed,
            "messages": messages,
            "response": response,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "duration_s": round(duration_s, 3),
            "error": error,
        }
        try:
            self._log_path.parent.mkdir(parents=True, exist_ok=True)
            with self._log_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            log.warning("could not write LLM audit record to %s", self._log_path)
