# Phishing

## Overview

Phishing is a social engineering technique used to trick users into revealing sensitive information, opening malicious content, or performing an action that benefits an attacker.

## Common Indicators

Common indicators include:

- Suspicious sender addresses
- Unexpected attachments
- Links to suspicious domains
- Urgent or threatening language
- Requests for credentials or financial information
- Messages impersonating trusted organizations

## SOC Investigation

A SOC analyst should investigate:

1. Sender information
2. URLs and domains
3. Attachments
4. Email headers
5. Recipient information
6. Related messages
7. Whether the recipient interacted with the content

## Recommended Response

Depending on the findings, an analyst may:

- Quarantine malicious messages
- Block malicious domains
- Reset compromised credentials
- Investigate endpoint activity
- Search for additional recipients
- Escalate confirmed compromise

## MITRE ATT&CK

Phishing techniques are associated with:

- T1566 — Phishing