import json
from pathlib import Path


DEFAULT_MITRE_PATH = (
    "data/mitre/enterprise-attack.json"
)


DETECTION_TO_TECHNIQUE = {
    "BRUTE_FORCE": "T1110",
    "SUSPICIOUS_LOGIN": "T1078",
}


class MitreMapper:
    """Map SOC detections to MITRE ATT&CK techniques."""

    def __init__(
        self,
        mitre_path: str = DEFAULT_MITRE_PATH,
    ):
        self.mitre_path = Path(mitre_path)
        self.techniques = {}

    def load(self):
        if not self.mitre_path.exists():
            raise FileNotFoundError(
                f"MITRE ATT&CK dataset not found: "
                f"{self.mitre_path}"
            )

        with self.mitre_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)

        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            external_references = obj.get(
                "external_references",
                [],
            )

            technique_id = None

            for reference in external_references:
                if (
                    reference.get("source_name")
                    == "mitre-attack"
                    and reference.get("external_id")
                ):
                    technique_id = reference[
                        "external_id"
                    ]
                    break

            if technique_id:
                self.techniques[technique_id] = {
                    "technique_id": technique_id,
                    "name": obj.get(
                        "name",
                        "Unknown",
                    ),
                    "description": obj.get(
                        "description",
                        "",
                    ),
                    "tactics": self._extract_tactics(
                        obj
                    ),
                }

    @staticmethod
    def _extract_tactics(obj: dict) -> list[str]:
        tactics = []

        for phase in obj.get(
            "kill_chain_phases",
            [],
        ):
            if (
                phase.get("kill_chain_name")
                == "mitre-attack"
            ):
                tactic = phase.get(
                    "phase_name"
                )

                if tactic:
                    tactics.append(tactic)

        return sorted(set(tactics))

    def get_technique(
        self,
        technique_id: str,
    ) -> dict | None:
        if not self.techniques:
            self.load()

        return self.techniques.get(
            technique_id
        )

    def map_detection(
        self,
        detection: dict,
    ) -> dict | None:
        detection_name = detection.get(
            "detection"
        )

        technique_id = DETECTION_TO_TECHNIQUE.get(
            detection_name
        )

        if not technique_id:
            return None

        technique = self.get_technique(
            technique_id
        )

        if not technique:
            return None

        return {
            "alert_id": detection["alert_id"],
            "detection": detection_name,
            **technique,
        }

    def map_detections(
        self,
        detections: list[dict],
    ) -> list[dict]:
        mappings = []

        for detection in detections:
            mapping = self.map_detection(
                detection
            )

            if mapping:
                mappings.append(mapping)

        return mappings