"""Scanner plumbing: every check runs in isolation and its outcome - ok, error or
skipped - is recorded, so that silence is never mistaken for a clean bill of health.

A finding can only be declared fixed when the check that produced it completed against
the same target (see ScanResult.completed); an errored or skipped check proves nothing.
"""

from __future__ import annotations

import time
import traceback
from pathlib import Path
from typing import Callable

from ..models import CheckRun, Finding, ScanResult


class CheckSkipped(Exception):
    """The check does not apply here (nothing to scan, unsupported locally...)."""


class CheckIncomplete(Exception):
    """The check stopped part-way. Its findings so far are real and are kept, but the
    check is recorded as an error so nothing is considered fixed on its evidence."""

    def __init__(self, detail: str, findings: list[Finding]) -> None:
        super().__init__(detail)
        self.findings = findings


def run_check(
    result: ScanResult,
    group: str,
    target: str,
    fn: Callable[..., list[Finding]],
    *args,
    **kwargs,
) -> list[Finding]:
    start = time.monotonic()

    def record(ok: bool, *, skipped: bool = False, detail: str = "", count: int = 0) -> None:
        result.checks.append(
            CheckRun(
                group=group,
                target=target,
                ok=ok,
                skipped=skipped,
                detail=detail,
                findings=count,
                seconds=round(time.monotonic() - start, 2),
            )
        )

    try:
        found = list(fn(*args, **kwargs))
    except CheckSkipped as exc:
        record(False, skipped=True, detail=str(exc))
        return []
    except CheckIncomplete as exc:
        result.findings.extend(exc.findings)
        record(False, detail=str(exc), count=len(exc.findings))
        return list(exc.findings)
    except Exception as exc:  # noqa: BLE001 - one broken check must not sink the scan
        detail = f"{type(exc).__name__}: {exc}"
        if not isinstance(exc, (OSError, RuntimeError, ValueError)):
            # Unexpected: most likely a bug in the check itself, so say where.
            frame = traceback.extract_tb(exc.__traceback__)[-1]
            detail += f" (at {Path(frame.filename).name}:{frame.lineno})"
        record(False, detail=detail)
        return []
    result.findings.extend(found)
    record(True, count=len(found))
    return found
