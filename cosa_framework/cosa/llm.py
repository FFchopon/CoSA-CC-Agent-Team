"""LLM client abstraction for the CoSA pipeline and targets.

A single, dependency-free (stdlib ``urllib``) client that speaks the
OpenAI-compatible ``/chat/completions`` API, so it works with OpenAI, DeepSeek, or
any third-party base URL. Nothing here touches the network until ``complete`` is
called; constructing a client and building prompts is offline.

Every call is appended to ``transcript`` (system/user/response/model) for
auditability and evidence. The API key is resolved lazily at call time and never
written into the transcript.

For offline tests, :class:`FakeLLMClient` implements the same interface with canned
responses and makes no network request.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclasses.dataclass
class LLMConfig:
    model: str = "deepseek-v4-flash"
    base_url: str = "https://api.deepseek.com/v1"
    api_key: Optional[str] = None            # explicit key (takes precedence)
    api_key_env: str = "DEEPSEEK_API_KEY"    # else read this environment variable
    api_key_file: Optional[str] = None       # else read this file
    temperature: float = 0.2
    timeout: int = 60
    max_retries: int = 6          # retry on HTTP 429 (rate limit) with backoff
    retry_base: float = 20.0      # base backoff seconds (e.g. RPM=3 -> ~20s/request)
    # Some OpenAI-compatible endpoints reject response_format={"type":"json_object"}
    # (Anthropic's compat layer wants json_schema). Set False to ask for JSON by
    # prompt only; complete_json then parses the returned text (fences tolerated).
    json_response_format: bool = True

    def resolve_key(self) -> str:
        if self.api_key:
            return self.api_key
        if self.api_key_file:
            return Path(self.api_key_file).read_text().strip()
        key = os.environ.get(self.api_key_env)
        if not key:
            raise RuntimeError(
                f"no API key: set {self.api_key_env}, LLMConfig.api_key, or api_key_file")
        return key


def _strip_json(text: str) -> str:
    """Pull a JSON object out of a model response that may wrap it in fences."""
    text = text.strip()
    if "```" in text:
        match = re.search(r"```(?:json)?\s*(.*?)```", text, re.DOTALL)
        if match:
            text = match.group(1).strip()
    first, last = text.find("{"), text.rfind("}")
    if first != -1 and last != -1 and last > first:
        return text[first:last + 1]
    return text


class LLMClient:
    """Interface. ``complete`` returns text; ``complete_json`` returns a dict."""

    def __init__(self) -> None:
        self.transcript: List[Dict[str, Any]] = []

    def complete(self, system: str, user: str) -> str:
        raise NotImplementedError

    def complete_json(self, system: str, user: str) -> Dict[str, Any]:
        raise NotImplementedError

    def _record(self, role: str, system: str, user: str, response: str,
                model: str) -> None:
        self.transcript.append({"agent_role": role, "system": system,
                                "user": user, "response": response, "model": model})


class OpenAICompatClient(LLMClient):
    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        super().__init__()
        self.config = config or LLMConfig()

    def _post(self, system: str, user: str, json_mode: bool, role: str) -> str:
        key = self.config.resolve_key()
        payload: Dict[str, Any] = {
            "model": self.config.model,
            "temperature": self.config.temperature,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        if json_mode and self.config.json_response_format:
            payload["response_format"] = {"type": "json_object"}
        body = json.dumps(payload).encode()
        request = urllib.request.Request(
            self.config.base_url.rstrip("/") + "/chat/completions", data=body,
            headers={"Authorization": "Bearer " + key,
                     "Content-Type": "application/json"}, method="POST")
        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                    data = json.loads(response.read().decode())
                break
            except urllib.error.HTTPError as exc:
                # Retry on rate limit (429) with backoff; honor Retry-After if sent.
                if exc.code == 429 and attempt < self.config.max_retries:
                    ra = exc.headers.get("Retry-After") if exc.headers else None
                    delay = (float(ra) if ra and str(ra).strip().replace(".", "", 1).isdigit()
                             else self.config.retry_base * (1.5 ** attempt))
                    time.sleep(min(delay, 90.0))
                    attempt += 1
                    continue
                detail = exc.read().decode(errors="replace")[:500]
                raise RuntimeError(f"LLM HTTP {exc.code}: {detail}") from exc
            except urllib.error.URLError as exc:
                raise RuntimeError(f"LLM connection failed: {exc.reason}") from exc
        content = data["choices"][0]["message"]["content"]
        self._record(role, system, user, content, self.config.model)
        return content

    def complete(self, system: str, user: str, role: str = "agent") -> str:
        return self._post(system, user, json_mode=False, role=role)

    def complete_json(self, system: str, user: str, role: str = "agent") -> Dict[str, Any]:
        raw = self._post(system, user, json_mode=True, role=role)
        return json.loads(_strip_json(raw))


class FakeLLMClient(LLMClient):
    """Offline client for tests. ``responder(role, system, user) -> str`` returns a
    canned response (JSON text for ``complete_json``). Makes no network request."""

    def __init__(self, responder: Callable[[str, str, str], str]) -> None:
        super().__init__()
        self.responder = responder

    def complete(self, system: str, user: str, role: str = "agent") -> str:
        out = self.responder(role, system, user)
        self._record(role, system, user, out, "fake")
        return out

    def complete_json(self, system: str, user: str, role: str = "agent") -> Dict[str, Any]:
        out = self.responder(role, system, user)
        self._record(role, system, user, out, "fake")
        return json.loads(_strip_json(out))
