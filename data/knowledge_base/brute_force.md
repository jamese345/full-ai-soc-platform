# Brute Force Attacks

## Overview

A brute force attack is an attempt to gain unauthorized access by repeatedly trying different passwords or authentication credentials.

## Common Indicators

Common indicators include:

- Large numbers of failed login attempts
- Repeated authentication attempts against the same account
- Multiple usernames targeted from one source IP
- Authentication attempts occurring at unusual times
- Successful authentication following many failed attempts

## SOC Investigation

A SOC analyst should investigate:

1. Source IP address
2. Target username or accounts
3. Number of failed attempts
4. Time period of the activity
5. Whether a successful login occurred
6. Geographic or network context
7. Related alerts or events

## Recommended Response

Depending on the severity, an analyst may:

- Block or investigate the source IP
- Reset compromised credentials
- Enable or enforce MFA
- Review authentication logs
- Investigate successful logins following failed attempts
- Escalate confirmed compromise

## MITRE ATT&CK

Brute force activity is associated with:

- T1110 — Brute Force