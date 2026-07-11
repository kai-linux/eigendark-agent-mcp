# Security controls and prevention map

Security fixes are incomplete until the violated invariant is enforced by an
automated regression gate. This map records the originating design failure, why
the previous pipeline missed it, and the permanent control.

| Invariant | Original cause | Why prior CI missed it | Permanent prevention |
|---|---|---|---|
| MCP protocol behavior comes from the official SDK. | A hand-written JSON-RPC loop implemented obsolete framing and partial lifecycle behavior. | Tests asserted the same custom framing instead of using an independent client. | Official MCP client integration test, newline subprocess smoke test, and bounded transport tests on every supported Python version. |
| Tool inputs match exact schemas. | Schemas were advertised but not enforced, and action arguments were unconstrained. | Happy-path tests called handlers directly and never submitted adversarial values. | Draft 2020-12 validation before every handler plus valid/invalid tests for every action family. |
| Credentials never cross the model boundary. | Credential-delivery tools and credential arguments made bearer values model-visible by design. | Tests explicitly expected raw credentials to be returned. | Credential-name schema scan, output redaction tests, bounded in-memory store tests, and end-to-end secret canaries. |
| Authentication never appears in a URL. | The client used a legacy GET query although the service documents POST state reads. | Mocks checked returned data but did not assert HTTP method, URL, and body separately. | Contract test requires POST, a query-free path, and an internal body token. |
| Authentication cannot follow a redirect. | The default URL opener inherited redirect replay behavior. | No hostile redirect server or request-header assertion existed. | Redirect handler rejects every 3xx; regression tests verify refusal and `unredirected_header` use. |
| Remote content is bounded and untrusted. | Raw remote objects and text were passed to the model without structural limits or a stable trust warning. | CI had no adversarial nesting, size, control-character, or prompt-injection fixtures. | Recursive node/depth/item/string limits, trust notice on every result, DLP checks, and adversarial fixtures. |
| Errors cannot reflect credentials or internals. | Raw HTTP bodies, exception reasons, and validation strings were included in tool errors. | Error tests covered only a small set of field names. | Broad field/value redaction, generic transport/internal failures, encoded-secret tests, and official-client error canaries. |
| Runtime state is bounded and isolated. | A process-global list grew without a cap and accumulated duplicate secrets. | Short tests never exercised eviction or concurrent access. | Locked LRU credential store capped at 32 matches, deduped sensitivity set, and eviction tests. |
| Dependency versions are supported and audited. | Python 3.9 support constrained security-tool upgrades, and dependencies were installed from open ranges. | The matrix checked import/test success only. | Python 3.11 minimum, hash-locked graphs, `pip-audit`, weekly scans, lock drift checks, and Dependabot. |
| Package and registry metadata describe a real artifact. | Metadata was added before the PyPI artifact existed and referenced a retired schema. | CI parsed neither the registry schema nor PyPI availability/version parity. | Current official schema validation, cross-file version script, package build/install smoke, trusted publishing, and post-release PyPI/registry verification. |
| CI workflows are themselves least privilege. | Workflows lacked timeouts, concurrency controls, explicit checkout credential isolation, and workflow static analysis. | The pipeline analyzed application code only. | Read-only defaults, per-job permissions, SHA-pinned actions, `persist-credentials: false`, timeouts, concurrency, CodeQL, zizmor, and scheduled security scans. |
| Container findings cannot silently age. | The container was only started; OS packages were not vulnerability-scanned. | A functional smoke test cannot identify vulnerable base packages. | SHA-pinned Trivy scan, expiring documented exceptions for unfixed base-image findings, weekly rescans, and Docker Dependabot updates. |

Pull requests must keep the test and control in the same change. Disabling a gate
requires a documented risk decision, an owner, and an expiry date.
