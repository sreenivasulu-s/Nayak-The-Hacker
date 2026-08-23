"""NPT v7 assessment state machine."""

from enum import StrEnum


class State(StrEnum):
    CREATED = "CREATED"
    AUTHORIZATION_CHECK = "AUTHORIZATION_CHECK"
    SCOPE_VALIDATION = "SCOPE_VALIDATION"
    POLICY_VALIDATION = "POLICY_VALIDATION"
    PLANNING = "PLANNING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    EVIDENCE_COLLECTION = "EVIDENCE_COLLECTION"
    VERIFICATION = "VERIFICATION"
    VERIFIED = "VERIFIED"
    UNCERTAIN = "UNCERTAIN"
    REJECTED = "REJECTED"
    FALSE_POSITIVE_GATE = "FALSE_POSITIVE_GATE"
    HUMAN_REVIEW = "HUMAN_REVIEW"
    AI_ANALYSIS = "AI_ANALYSIS"
    CORRELATION = "CORRELATION"
    FINDING = "FINDING"
    REPORT = "REPORT"
    COMPLETE = "COMPLETE"
    ERROR = "ERROR"
    RETRY = "RETRY"
    CIRCUIT_BREAKER = "CIRCUIT_BREAKER"


TRANSITIONS = {
    State.CREATED: {State.AUTHORIZATION_CHECK},
    State.AUTHORIZATION_CHECK: {State.SCOPE_VALIDATION, State.REJECTED},
    State.SCOPE_VALIDATION: {State.POLICY_VALIDATION, State.REJECTED},
    State.POLICY_VALIDATION: {State.PLANNING, State.REJECTED},
    State.PLANNING: {State.QUEUED, State.REJECTED},
    State.QUEUED: {State.RUNNING},
    State.RUNNING: {State.EVIDENCE_COLLECTION, State.ERROR},
    State.EVIDENCE_COLLECTION: {State.VERIFICATION, State.ERROR},
    State.VERIFICATION: {State.VERIFIED, State.UNCERTAIN, State.REJECTED},
    State.VERIFIED: {State.FALSE_POSITIVE_GATE},
    State.UNCERTAIN: {State.HUMAN_REVIEW, State.REPORT},
    State.FALSE_POSITIVE_GATE: {State.HUMAN_REVIEW, State.AI_ANALYSIS},
    State.HUMAN_REVIEW: {State.AI_ANALYSIS, State.REJECTED, State.VERIFICATION},
    State.AI_ANALYSIS: {State.CORRELATION, State.REPORT},
    State.CORRELATION: {State.FINDING, State.REPORT},
    State.FINDING: {State.REPORT},
    State.REPORT: {State.COMPLETE},
    State.ERROR: {State.RETRY, State.CIRCUIT_BREAKER},
    State.RETRY: {State.QUEUED, State.CIRCUIT_BREAKER},
}


def can_transition(current: State, next_state: State) -> bool:
    return next_state in TRANSITIONS.get(current, set())


def transition(current: State, next_state: State) -> State:
    if not can_transition(current, next_state):
        raise ValueError(f"Invalid NPT state transition: {current} -> {next_state}")
    return next_state
