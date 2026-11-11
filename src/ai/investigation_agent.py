from src.ai.llm import LLMClient
from src.rag.investigation_retriever import InvestigationRetriever


INSUFFICIENT_EVIDENCE = (
    "Insufficient evidence to make a reliable investigation conclusion."
)


class InvestigationAgent:
    def __init__(
        self,
        knowledge_base_path: str = "data/knowledge_base",
        llm_client: LLMClient | None = None,
    ):
        self.retriever = InvestigationRetriever(
            knowledge_base_path=knowledge_base_path,
        )
        self.llm_client = llm_client or LLMClient()

    def build_context(
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
        evidence_pack = self.retriever.retrieve_for_investigation(
            alert=alert,
            detections=detections,
            anomaly=anomaly,
            risk=risk,
            iocs=iocs,
            enriched_iocs=enriched_iocs,
            mitre=mitre,
            top_k=top_k,
        )

        return {
            "alert": alert,
            "detections": detections,
            "anomaly": anomaly,
            "risk": risk,
            "iocs": iocs,
            "enriched_iocs": enriched_iocs,
            "mitre": mitre,
            "rag": evidence_pack,
        }

    def build_prompt(self, context: dict) -> str:
        alert = context["alert"]
        detections = context["detections"]
        anomaly = context["anomaly"]
        risk = context["risk"]
        iocs = context["iocs"]
        enriched_iocs = context["enriched_iocs"]
        mitre = context["mitre"]
        rag = context["rag"]

        prompt_parts = [
            "You are an AI SOC investigation assistant.",
            "",
            "Investigate the alert using ONLY the evidence provided below.",
            "",
            "Do not invent facts.",
            "Do not claim compromise without supporting evidence.",
            "Clearly distinguish observed evidence from inference.",
            "If evidence is insufficient, say so explicitly.",
            "",
            "=== ALERT ===",
            f"Alert ID: {alert['alert_id']}",
            f"Event Type: {alert['event_type']}",
            f"Severity: {alert['severity']}",
            f"Source IP: {alert['src_ip']}",
            f"Description: {alert['description']}",
            "",
            "=== RULE DETECTIONS ===",
        ]

        if detections:
            for detection in detections:
                prompt_parts.append(
                    f"- {detection['detection']} | "
                    f"Severity: {detection['severity']} | "
                    f"Confidence: {detection['confidence']}"
                )
        else:
            prompt_parts.append("- None")

        prompt_parts.extend([
            "",
            "=== MACHINE LEARNING ===",
            f"Classification: {anomaly['classification']}",
            f"Anomaly Score: {anomaly['anomaly_score']}",
            "",
            "=== RISK ===",
            f"Risk Level: {risk['risk_level']}",
            f"Priority: {risk['priority']}",
            f"Confidence: {risk['confidence']}",
            f"Recommended Action: {risk['recommended_action']}",
            "",
            "=== IOCS ===",
        ])

        for category in ("ips", "domains", "urls", "hashes"):
            values = iocs.get(category, [])
            if values:
                prompt_parts.append(
                    f"{category.upper()}: " + ", ".join(values)
                )

        prompt_parts.extend([
            "",
            "=== THREAT INTELLIGENCE ===",
        ])

        for category in ("ips", "domains", "urls", "hashes"):
            for item in enriched_iocs.get(category, []):
                prompt_parts.append(
                    f"- {item['indicator']} | "
                    f"Reputation: {item['reputation']}"
                )

        prompt_parts.extend([
            "",
            "=== MITRE ATT&CK ===",
        ])

        if mitre:
            for mapping in mitre:
                prompt_parts.append(
                    f"- {mapping['technique_id']} | "
                    f"{mapping['name']} | "
                    f"Tactics: {', '.join(mapping['tactics'])}"
                )
        else:
            prompt_parts.append("- None")

        prompt_parts.extend([
            "",
            "=== RETRIEVED KNOWLEDGE ===",
        ])

        if rag["results"]:
            for result in rag["results"]:
                prompt_parts.append(
                    f"[Source: {result['source']} | "
                    f"Score: {result['score']:.4f}]"
                )
                prompt_parts.append(result["text"])
        else:
            prompt_parts.append(INSUFFICIENT_EVIDENCE)

        prompt_parts.extend([
            "",
            "=== REQUIRED OUTPUT ===",
            "Provide:",
            "1. Investigation summary",
            "2. Observed evidence",
            "3. Assessment",
            "4. MITRE ATT&CK context",
            "5. Recommended investigation steps",
            "6. Additional evidence required",
            "",
            "Do not present assumptions as facts.",
        ])

        return "\n".join(prompt_parts)

    def investigate(
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
        context = self.build_context(
            alert=alert,
            detections=detections,
            anomaly=anomaly,
            risk=risk,
            iocs=iocs,
            enriched_iocs=enriched_iocs,
            mitre=mitre,
            top_k=top_k,
        )

        prompt = self.build_prompt(context)

        return {
            "alert_id": alert["alert_id"],
            "status": "READY_FOR_LLM",
            "context": context,
            "prompt": prompt,
            "llm_called": False,
        }

    def investigate_with_llm(
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
        """
        Build a grounded investigation prompt and send it
        to the configured LLM.
        """

        investigation = self.investigate(
            alert=alert,
            detections=detections,
            anomaly=anomaly,
            risk=risk,
            iocs=iocs,
            enriched_iocs=enriched_iocs,
            mitre=mitre,
            top_k=top_k,
        )

        rag_results = investigation["context"]["rag"]["results"]

        if not rag_results:
            return {
                "alert_id": alert["alert_id"],
                "status": "INSUFFICIENT_EVIDENCE",
                "response": INSUFFICIENT_EVIDENCE,
                "model": None,
                "error": "NO_RETRIEVED_EVIDENCE",
                "llm_called": False,
                "prompt": investigation["prompt"],
                "context": investigation["context"],
            }

        llm_result = self.llm_client.generate(
            investigation["prompt"]
        )

        return {
            "alert_id": alert["alert_id"],
            "status": (
                "COMPLETED"
                if llm_result["success"]
                else "LLM_ERROR"
            ),
            "response": llm_result["response"],
            "model": llm_result["model"],
            "error": llm_result["error"],
            "llm_called": True,
            "prompt": investigation["prompt"],
            "context": investigation["context"],
        }