# Nayak Pen Testing Tool — NPT v7.0 Source of Truth

## Non-negotiable execution rule

Assessment category selection creates an assessment workflow. It never grants unrestricted tool execution.

Every execution request must pass:

`Authorization → Scope → Policy → Capability → Resource Limits → User Confirmation → Orchestrator → Tool → Evidence → Verification → Finding → Report`

A failed gate means no worker execution.

## Assessment modules

1. Network Pentesting
2. Web Application Pentesting
3. API Pentesting
4. Mobile App Pentesting
5. Cloud Pentesting
6. Wireless Pentesting
7. Active Directory Pentesting
8. Social Engineering
9. Physical Security Testing
10. IoT / Embedded Pentesting
11. Red Teaming
12. External Pentesting
13. Internal Pentesting

## Core tool registry

The registry contains the fifteen core tools defined by v7.0. The default execution policy currently enables only bounded read-only discovery/review workers: Nmap, Gobuster, Nikto and Nuclei.

The remaining tools are capability-disabled until their dedicated worker, sandbox, policy contract, parser/evidence model and regression tests exist. They are not exposed as arbitrary shell commands.

## Evidence contract

A finding must retain provenance to the tool run, target, timestamp, SHA-256 content hash, artifact reference, scope version, policy version and parser version.

No evidence means no verified finding.

## State machine

The backend uses the explicit NPT state machine and rejects skipped transitions. The normal bounded assessment lifecycle is:

`CREATED → AUTHORIZATION_CHECK → SCOPE_VALIDATION → POLICY_VALIDATION → PLANNING → QUEUED → RUNNING → EVIDENCE_COLLECTION → VERIFICATION → (VERIFIED|UNCERTAIN) → FALSE_POSITIVE_GATE/HUMAN_REVIEW → AI_ANALYSIS → CORRELATION → FINDING → REPORT → COMPLETE`

Execution errors enter `ERROR`; retry/circuit-breaker behavior remains a separate worker/queue implementation concern.

## Current implementation boundary

The repository contains the v7 frontend workflow, FastAPI control path, SQLite persistence, real bounded subprocess execution for the four enabled scanners, evidence hashing, verification, category routing, capability registry and CI tests.

Production components that require separate infrastructure before claiming enterprise completeness include durable job queues, isolated container/VM workers, external identity/RBAC, PostgreSQL migrations, secrets management, dedicated MCP/LLM gateway, human-review persistence, PDF/HTML reporting, distributed observability and production retry/DLQ orchestration.

These components must preserve the same gates and must never bypass the control plane.
