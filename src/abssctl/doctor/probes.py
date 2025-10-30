"""Probe registration entry point for the doctor command."""

from __future__ import annotations

from collections.abc import Sequence

from .models import ProbeContext, ProbeDefinition


def collect_probes(context: ProbeContext) -> Sequence[ProbeDefinition]:
    """Return the set of probes that should run for the current context.

    The initial Beta milestone only wires the execution infrastructure. Concrete
    probes will be populated in subsequent tasks.
    """
    # Placeholder: future work will derive probe definitions from context.
    return ()
