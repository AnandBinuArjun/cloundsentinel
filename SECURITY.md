# Security Policy — CloudSentinel

## Supported Versions

| Version | Supported |
| :--- | :--- |
| `1.0.x` | Yes |

## Reporting a Vulnerability

If you discover a security vulnerability in CloudSentinel (authentication bypass, cross-tenant data exposure, privilege escalation, SSRF, injection, secret leakage, or container/CI supply-chain weakness), **do not open a public GitHub issue**.

Instead:
1. Report the issue privately via GitHub Security Advisories (if enabled on the repository) or directly to the repository maintainer.
2. Include a clear technical description, affected file paths, safe local reproduction steps (never targeting third-party cloud accounts), and any suggested mitigation.
3. Expect an initial acknowledgment within 72 hours and a coordinated fix timeline based on severity.

## Security Design Guarantees

- **Read-Only Default**: AWS STS and Azure Identity connectors request read-only assessment permissions only; AWS `:root` ARNs and Azure Global Administrator roles are prohibited.
- **No Raw Cloud Credentials in Source or DB**: Never commit `.env`, access keys, or service principal secrets.
- **Safe Remediation Controls**: Live cloud remediation is disabled by default (`CLOUDSENTINEL_LIVE_REMEDIATION_ENABLED=false`) and requires preview, explicit approval, separation of duties (`approver != proposer`), and separate remediation credentials.
- **Isolated Cloud Labs Only**: Never run Terraform lab templates (`infrastructure/terraform/{aws,azure}/`) against production AWS accounts or Azure subscriptions.

See [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) and [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) for complete architecture and STRIDE analysis.
