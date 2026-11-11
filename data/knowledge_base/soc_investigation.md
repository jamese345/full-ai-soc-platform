# SOC Investigation Guidance

## Purpose

This document provides general guidance for investigating security alerts in a Security Operations Center.

The AI investigation agent should use alert evidence, detection results, machine-learning findings, threat intelligence, and MITRE ATT&CK mappings when forming an investigation.

## Investigation Principles

An investigation should:

1. Identify the triggering activity.
2. Review rule-based detections.
3. Review machine-learning anomaly results.
4. Examine extracted indicators of compromise.
5. Review available threat-intelligence context.
6. Map observed behavior to MITRE ATT&CK techniques where supported.
7. Correlate the available evidence.
8. Determine the risk and priority.
9. Explain why the alert requires investigation.
10. Recommend appropriate next steps.

## Evidence Types

### Rule Detection

Rule-based detections provide deterministic evidence that a known suspicious pattern occurred.

Examples include:

- Brute-force activity
- Suspicious login behavior
- Suspicious requests

Rule detections should be considered together with other evidence rather than in isolation.

### Machine-Learning Anomaly

An ML anomaly indicates that observed feature values differ from patterns learned by the anomaly detection model.

An anomaly does not automatically mean malicious activity.

The analyst should correlate an anomaly with:

- Rule detections
- Login behavior
- Source IP information
- Request volume
- Session characteristics
- Threat-intelligence context
- Other available evidence

### IOC Evidence

Indicators of compromise may include:

- IP addresses
- Domains
- URLs
- File hashes

An extracted IOC is not automatically malicious.

A reputation value of `UNKNOWN` means that the available enrichment source did not establish a malicious or benign reputation.

Private or internal IP addresses should normally be investigated using internal telemetry rather than submitted to external reputation services.

### MITRE ATT&CK

MITRE ATT&CK mappings provide a standardized description of adversary behavior.

Mappings should only be made when the observed behavior supports the technique.

Avoid forcing a technique mapping when evidence is insufficient.

## Brute-Force Investigation

When repeated failed authentication attempts are detected, investigate:

- Number of failed attempts
- Source IP
- Target username
- Whether authentication eventually succeeded
- Number of source IPs involved
- Time of activity
- Related authentication events
- Whether the source is internal or external

A successful authentication following repeated failures may increase the importance of the investigation because it can indicate possible credential compromise.

Relevant MITRE ATT&CK technique:

- T1110 — Brute Force

## Suspicious Login Investigation

When failed attempts are followed by a successful login, investigate:

- Account involved
- Source IP
- Number of failed attempts
- Successful authentication time
- Whether the source is expected
- Whether the account normally authenticates from the source
- Related activity after authentication

Potentially relevant MITRE ATT&CK technique:

- T1078 — Valid Accounts

The presence of a successful login does not by itself prove account compromise.

## Suspicious Request Investigation

For suspicious requests, investigate:

- Source IP
- Destination domain
- URL
- Request timing
- Request frequency
- Whether the destination is known or expected
- Related DNS, proxy, firewall, or endpoint telemetry

Do not classify a domain as malicious solely because its name appears in an alert.

Additional threat-intelligence or network evidence should be considered.

## Risk Interpretation

### CRITICAL

Critical alerts generally require immediate escalation and investigation.

Typical supporting evidence may include:

- Multiple high-confidence detections
- Confirmed anomalous behavior
- Successful authentication after brute-force activity
- Multiple corroborating evidence sources
- High-risk attack techniques

### HIGH

High-risk alerts generally require prompt investigation.

### MEDIUM

Medium-risk alerts generally require monitoring, validation, or additional investigation depending on context.

### LOW

Low-risk alerts may be closed when available evidence indicates benign activity and no additional suspicious behavior exists.

## Analyst Reasoning

The investigation agent should distinguish between:

- Observed evidence
- Correlated evidence
- Inference
- Recommendation

The agent should not claim that an attacker compromised an account unless the available evidence supports that conclusion.

When evidence is insufficient, the agent should explicitly state that additional evidence is required.

## Recommended Investigation Questions

The investigation agent should consider:

1. What triggered this alert?
2. What evidence supports the detection?
3. Is there evidence of anomalous behavior?
4. What indicators were extracted?
5. What is known about those indicators?
6. Does the behavior map to MITRE ATT&CK?
7. Are multiple evidence sources corroborating each other?
8. What is the current risk level?
9. What should the SOC analyst investigate next?
10. What evidence would confirm or reject the suspected activity?
