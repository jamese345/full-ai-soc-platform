from src.investigation.evidence_builder import (
    build_investigation_query,
)
from src.rag.retriever import KnowledgeBaseRetriever


class InvestigationRetriever:
    """Retrieve knowledge relevant to a SOC investigation."""

    def __init__(
        self,
        knowledge_base_path: str = "data/knowledge_base",
    ):
        self.retriever = KnowledgeBaseRetriever(
            knowledge_base_path=knowledge_base_path,
        )

    def retrieve_for_investigation(
        self,
        alert: dict,
        detections: list[dict],
        anomaly: dict,
        risk: dict,
        iocs: dict,
        enriched_iocs: dict,
        mitre: list[dict],
        top_k: int = 3,
    ) -> dict:
        """Build an investigation query and retrieve supporting evidence."""

        query = build_investigation_query(
            alert=alert,
            detections=detections,
            anomaly=anomaly,
            risk=risk,
            iocs=iocs,
            enriched_iocs=enriched_iocs,
            mitre=mitre,
        )

        results = self.retriever.retrieve(
            query=query,
            top_k=top_k,
        )

        return {
            "alert_id": alert["alert_id"],
            "query": query,
            "results": results,
            "result_count": len(results),
        }