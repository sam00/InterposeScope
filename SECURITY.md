# Security & Authorized Use

This repository contains an offensive security tool designed for authorized
red team testing and endpoint security research.

## Scope

- Authorized red team engagements with written permission
- Purple team exercises on operator-controlled infrastructure
- Security research in controlled lab environments

## Rules

1. Never deploy against systems you do not own or lack explicit written
   authorization to test.
2. Never commit real command-and-control infrastructure (IPs, hostnames,
   keys, payload UUIDs) to version control.
3. All operator configuration belongs in runtime environment variables or
   files excluded by `.gitignore`.

## Responsible use

The tool is read-only by design. It never writes to memory, changes
protections, or modifies any process. Any operation flagged by an EDR
should be validated to ensure it is attributable to this tool and not
to an actual threat actor.

## Reporting

If you discover a vulnerability in this tool itself, please report it
responsibly via a private channel rather than a public issue.
