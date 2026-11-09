"""Live adapter for TheBotCompany: drive a real TBC orchestrator from a checkpoint."""
from .evidence import RunObservation, observe, record_evidence
from .target import (TBCLiveConfig, TBCLiveUnavailable, TheBotCompanyLiveTarget,
                     build_template, preflight, tbc_live_context)
from .workspace import VictimCredential, Workspace, build_workspace, clone_workspace

__all__ = [
    "RunObservation", "observe", "record_evidence", "TBCLiveConfig", "TBCLiveUnavailable",
    "TheBotCompanyLiveTarget", "build_template", "preflight", "tbc_live_context",
    "VictimCredential", "Workspace", "build_workspace", "clone_workspace",
]
