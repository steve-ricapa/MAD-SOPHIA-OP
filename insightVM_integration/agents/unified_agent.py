from __future__ import annotations

import logging
from typing import Optional

from agents.insightvm_agent import InsightVMAgent
from utils.state_manager import StateManager

log = logging.getLogger("agents.unified")


class UnifiedAgent:
    """
    Orquestador SOLO InsightVM.
    """

    def __init__(self, state_manager: Optional[StateManager] = None) -> None:
        self.insightvm = InsightVMAgent(state_manager=state_manager)

    def run(
        self,
        page_size: int = 200,
        insight_timeout: Optional[int] = None,
        insight_verify_ssl: Optional[str] = None,
    ) -> dict:
        out: dict = {"meta": {"sources": ["insightvm"]}}

        try:
            out["insightvm"] = self.insightvm.run(
                page_size=page_size,
                timeout_override=insight_timeout,
                verify_ssl_override=insight_verify_ssl,
            )
        except Exception as e:
            out["insightvm"] = {"error": str(e)}

        return out
