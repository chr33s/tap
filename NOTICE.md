# Notices

This repository is a TypeScript implementation of the agent-recognition and
declared-intent portion of Visa's Trusted Agent Protocol.

The behavioral baseline is the sample at
<https://github.com/visa/trusted-agent-protocol/commit/16d59bdf3f8a542bc538d0962edbb80ea30a02af>.
Those sample programs include the MIT license notice © 2025 Visa in their
source headers. This repository reimplements the protocol. The only copied
program text is `fixtures/pinned-js-verifier.mjs`, which keeps that notice so
interoperability tests can run the pinned JavaScript verifier.

Protocol specification and terms:
<https://developer.visa.com/docs/trusted-agent-protocol/trusted-agent-protocol-specifications>

HTTP Message Signatures: <https://www.rfc-editor.org/rfc/rfc9421.html>

Structured Field Values: <https://www.rfc-editor.org/rfc/rfc8941.html>

Registry approval is local trust policy for this deployment. Activating an
agent or key does not mean Visa has certified that agent.

Effect `4.0.6` (MIT) orchestrates the registry and proxy:
<https://github.com/Effect-TS/effect/releases/tag/effect%404.0.6>

The obsolete Python `sig1` verifier is not implemented.
