# OpenShell Default Network Denial

## Aim

Demonstrate that OpenShell denies an outbound connection, with a fresh
log event identifying the requesting executable and destination.

## Prerequisites

- Linux with Bash, GNU date, awk, grep, cmp, and Git.
- Working OpenShell CLI and gateway.
- An existing Ready sandbox named `sentry-first`.
- `/usr/bin/curl` and CA certificates inside the sandbox.
- A baseline policy denying curl access to `api.github.com:443`.
- No concurrent experiments against this sandbox.

This workshop reuses the tool image from Task 02 and the sandbox used
in Task 03. It does not provision either resource.

The tested CLI version is OpenShell 0.1.4. See `evidence/` for the
recorded CLI version and baseline policy.

## Concepts

A failed curl request alone does not prove policy enforcement.
The corresponding OpenShell denial must identify the executable,
destination, port, and enforcement reason.

OpenShell may stage an unapproved hostname using a synthetic address.
Receiving that address does not establish contact with the external service.

## Manual Experiment

Run the request through OpenShell:

```bash
/usr/bin/openshell sandbox exec sentry-first -- \
  /usr/bin/curl --verbose --connect-timeout 5 --max-time 15 \
  https://api.github.com/zen
```

Immediately capture its exit status:

```bash
echo $?
```

Inspect the logs:

```bash
/usr/bin/openshell logs sentry-first --since 5m
```

Leave any access approval unapproved. Do not modify policy.

Expected evidence:

- Curl fails during connection.
- A matching `NET:OPEN` event identifies `/usr/bin/curl`.
- The destination is `api.github.com:443`.
- The event reports `transparent_tcp_policy_denied`.

The intended request is GET `/zen`, but the observed denial occurs
before TLS or HTTP. This does not demonstrate HTTP method or path filtering.

## Scripted Validation

From the repository root:

```bash
bash -n validate-denial.sh &&
bash validate-denial.sh
```

Optional configuration:

```bash
OPEN_SHELL=/usr/bin/openshell SANDBOX=sentry-first \
  bash validate-denial.sh
```

The script checks that:

- The request fails.
- A matching denial is timestamped after the request begins.
- The sandbox is Ready before and after.
- Effective policy and policy revision remain unchanged.

It saves a concise report under `evidence/` and raw diagnostics under
the Git-excluded `.local/` directory. Review evidence before committing.

## Observed Result

Manual and scripted validation passed on Spark.

The scripted request returned exit status 7. A fresh log event identified:

```text
NET:OPEN [MED] DENIED /usr/bin/curl(0) -> api.github.com:443
[reason:transparent_tcp_policy_denied]
```

The sandbox remained Ready and policy remained at revision 1.

Fresh-clone validation has not yet been recorded.

## Troubleshooting

### Workspace-scope error

Use `/usr/bin/openshell` explicitly. If the error persists, investigate
CLI/gateway compatibility and workspace selection without changing policy.

### Missing denial evidence

Inspect the raw diagnostics under `.local/`.

A timeout, DNS error, TLS error, connection refusal, or generic HTTP
error alone is insufficient evidence of OpenShell policy enforcement.

### Log-buffer warning

Older records may have been discarded. The validation script requires
a matching denial from the current attempt.

### Timestamp correlation

The script assumes sufficiently synchronized clocks between the
Spark command runner and the component emitting the log events.

### Unexpected request success

Preserve the output and inspect effective policy and routing.
Do not change policy merely to manufacture a passing result.

## Evidence Limits

This demonstrates one denied destination through the tested OpenShell
execution path.

It does not establish:

- Complete egress isolation.
- Resistance to administrative bypass.
- HTTP method or path filtering.
- Agent or model integration.
- DPU enforcement.
- Clean-machine or macOS runtime compatibility.

Fresh-clone testing, when performed, still reuses the existing Spark
image and sandbox.

## Cleanup and Recovery

The validation script changes no sandbox policy and creates no containers.

Leave `sentry-first` available for the next workshop. Retain evidence
as needed. Remove only identified workshop-generated diagnostic
directories when deliberately cleaning up.

Do not prune unrelated Docker resources.

## Next Workshop

Task 05 — Allow reads and deny writes.

No new hardware is expected.
