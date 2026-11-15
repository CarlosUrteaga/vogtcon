# Copyright (c) 2026 Jorge Carlos Urteaga Reyesvera
# SPDX-License-Identifier: Apache-2.0

"""Optional OpenTelemetry API instrumentation; the host owns SDK/exporters."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from opentelemetry import trace

from .models import GovernanceDecision


class TelemetryObserver:
    """Emit optional spans without granting permissions or failing on export.

    The host configures the OpenTelemetry SDK and passes its tracer provider:
    ``observer = TelemetryObserver(provider)``. Keep
    ``with observer.run(run_id, contract_id):`` around the controller's
    checkpoints to connect their spans and JSONL trace identifiers.
    """

    def __init__(self, tracer_provider: trace.TracerProvider | None = None, tracer: Any = None) -> None:
        self.tracer_provider = tracer_provider
        self._tracer = tracer if tracer is not None else trace.get_tracer(
            "governor_contracts", tracer_provider=tracer_provider
        )

    @contextmanager
    def span(self, name: str, **attributes: str | int) -> Iterator[Any]:
        try:
            manager = self._tracer.start_as_current_span(name, attributes=attributes)
            span = manager.__enter__()
        except Exception:
            yield None
            return
        try:
            yield span
        except BaseException as error:
            try:
                manager.__exit__(type(error), error, error.__traceback__)
            except Exception:
                pass
            raise
        else:
            try:
                manager.__exit__(None, None, None)
            except Exception:
                pass

    def run(self, run_id: str, contract_id: str):
        """Keep one run span current while the host drives all phases."""
        return self.span("governor.run", run_id=run_id, contract_id=contract_id)

    @staticmethod
    def record_decision(span: Any, decision: GovernanceDecision) -> None:
        if span is None:
            return
        try:
            if decision.decision is not None:
                span.set_attribute("governor.decision", decision.decision)
            span.set_attribute("governor.violation_rules", [v.rule for v in decision.violations])
        except Exception:
            pass

    @staticmethod
    def current_ids() -> tuple[str | None, str | None]:
        try:
            context = trace.get_current_span().get_span_context()
            if not context.is_valid:
                return None, None
            return f"{context.trace_id:032x}", f"{context.span_id:016x}"
        except Exception:
            return None, None
