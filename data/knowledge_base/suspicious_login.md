# Suspicious Login Activity

## Overview

Suspicious login activity can indicate compromised credentials, unauthorized access, or an attack against an authentication system.

## Common Indicators

Common indicators include:

- Login from an unusual geographic location
- Login from an unfamiliar source IP
- Multiple failed attempts before successful authentication
- Login at unusual hours
- Multiple locations within a short period
- Authentication from an unexpected device

## SOC Investigation

A SOC analyst should investigate:

1. Username
2. Source IP
3. Authentication timestamp
4. Previous authentication activity
5. Device information
6. Geographic location
7. Failed authentication attempts
8. Actions performed after authentication

## Recommended Response

If compromise is suspected:

- Validate the login with the user
- Review authentication history
- Reset credentials if necessary
- Revoke active sessions
- Investigate post-authentication activity
- Escalate confirmed incidents