# Security policy

This repository contains a simulated research harness. Its bundled HMAC key is
deliberately public, deterministic, and restricted to the scripted development
backend. It must never be reused for live-model experiments.

Do not commit API keys, provider credentials, production signing keys,
unredacted live-model responses, or outputs containing sensitive data. The
repository ignores common credential files and the `outputs/live/`,
`outputs/private/`, and `raw_responses/` paths as a final guardrail, not as a
substitute for reviewing changes before every push.

To report a vulnerability, use GitHub's private **Report a vulnerability** form
when available. If it is unavailable, open a non-sensitive issue asking the
maintainers to establish a private channel. Do not place credentials, private
data, or actionable exploit details in a public issue.
