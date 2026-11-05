"""Context Library: replayable testing instances from normal task executions.

Slide 8: legitimate task runs are recorded as reusable context instances holding
task/artifact versions, messages, state and trace, checkpoints and references, and
scene tags with rejection reasons. The Dispatcher retrieves candidates by scene tag
and then checks *actual eligibility* for a chosen path (does this context realize
the path's source and sink?) before binding one.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .spec import CandidatePath, ContextInstance


class ContextLibrary:
    def __init__(self) -> None:
        self._instances: Dict[str, ContextInstance] = {}

    def add(self, instance: ContextInstance) -> ContextInstance:
        self._instances[instance.id] = instance
        return instance

    def get(self, context_id: str) -> ContextInstance:
        return self._instances[context_id]

    def retrieve_by_tag(self, tag: str) -> List[ContextInstance]:
        return [c for c in self._instances.values() if tag in c.scene_tags]

    def eligible_for(self, path: CandidatePath) -> List[ContextInstance]:
        """Contexts whose source/sink fields actually realize the path.

        Eligibility is checked against the path's sink (the coordination field the
        attack must corrupt). A context is eligible when it exposes the path's
        source as a modifiable input and its sink field matches the path's sink.
        """
        eligible = []
        for instance in self._instances.values():
            if instance.rejection_reason:
                continue
            if instance.sink_field == path.sink and instance.source_field == path.source:
                eligible.append(instance)
        return eligible

    def bind(self, path: CandidatePath,
             preferred: Optional[str] = None) -> Optional[ContextInstance]:
        if preferred is not None and preferred in self._instances:
            return self._instances[preferred]
        eligible = self.eligible_for(path)
        return eligible[0] if eligible else None
