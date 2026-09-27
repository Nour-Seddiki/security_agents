"""Anthropic client wiring and the shared request shape.

`anthropic` is imported lazily so that the scanners, dry runs and the test suite work on
an interpreter with nothing installed.

Request shape (claude-api guidance for Claude Opus 5): adaptive thinking,
`output_config.effort`, automatic prompt caching, and the server-side `fallbacks`
parameter so a policy decline is retried on a fallback model instead of just stopping.
Optional features the account or SDK version rejects are dropped once, with a note,
and the run carries on - see `Capabilities`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class LlmError(RuntimeError):
    """Talking to the API failed in a way a retry will not fix."""


def anthropic_module():
    try:
        import anthropic  # noqa: PLC0415 - deliberately lazy
    except ImportError as exc:
        raise LlmError(
            "the `anthropic` package is not installed (pip install -r requirements.txt), "
            "or run with --no-agent / --dry-run"
        ) from exc
    return anthropic


def make_client():
    """Zero-arg client: ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN or an `ant auth login`
    profile, in that order."""
    return anthropic_module().Anthropic()


def credential_source() -> tuple[bool, str]:
    """(have_credentials, description). Reports which source was found, never a value."""
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        if os.environ.get(var, "").strip():
            return True, f"{var} is set"
    if shutil.which("ant"):
        try:
            proc = subprocess.run(["ant", "auth", "status"], capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return False, "no ANTHROPIC_API_KEY, and `ant auth status` could not be run"
        if proc.returncode == 0 and (proc.stdout + proc.stderr).strip():
            return True, "an `ant auth login` profile is active"
        return False, "no ANTHROPIC_API_KEY, and `ant auth status` reports no active profile"
    return False, "no credentials: set ANTHROPIC_API_KEY or run `ant auth login`"


@dataclass
class Capabilities:
    """Optional request features, switched off if this account/SDK rejects them."""

    fallbacks: bool = True
    cache: bool = True
    notes: list[str] = field(default_factory=list)

    def drop(self, feature: str, reason: str) -> None:
        setattr(self, feature, False)
        self.notes.append(f"dropped {feature}: {reason[:200]}")


def unsupported_feature(exc: Exception, caps: Capabilities) -> str | None:
    """Which optional feature a rejected request most likely tripped over, if any."""
    if not (isinstance(exc, TypeError) or type(exc).__name__ in ("BadRequestError", "NotFoundError")):
        return None
    text = str(exc).lower()
    if caps.fallbacks and ("fallback" in text or "beta" in text):
        return "fallbacks"
    if caps.cache and "cache_control" in text:
        return "cache"
    return None


def request_kwargs(agent_cfg, caps: Capabilities) -> dict:
    kwargs: dict = {"model": agent_cfg.model, "max_tokens": agent_cfg.max_tokens}
    if agent_cfg.thinking:
        kwargs["thinking"] = {"type": "adaptive"}  # budget_tokens is rejected by this model
    kwargs["output_config"] = {"effort": agent_cfg.effort}
    if caps.cache:
        kwargs["cache_control"] = {"type": "ephemeral"}  # caches the growing conversation
    if caps.fallbacks:
        kwargs["betas"] = [FALLBACK_BETA]
        kwargs["fallbacks"] = "default"
    return kwargs


def message_text(message) -> str:
    parts = [
        block.text for block in getattr(message, "content", None) or [] if getattr(block, "type", None) == "text"
    ]
    return "\n".join(parts).strip()


def usage_of(message) -> dict[str, int]:
    usage = getattr(message, "usage", None)
    if usage is None:
        return {}
    return {
        key: getattr(usage, key, 0) or 0
        for key in ("input_tokens", "output_tokens", "cache_read_input_tokens", "cache_creation_input_tokens")
    }


def add_usage(total: dict[str, int], new: dict[str, int]) -> dict[str, int]:
    for key, value in new.items():
        total[key] = total.get(key, 0) + value
    return total
