pub(super) fn valid_case_transition(current: &str, next: &str) -> bool {
    matches!(
        (current, next),
        ("new", "triaged")
            | ("triaged", "investigating")
            | ("investigating", "resolved")
            | ("resolved", "closed")
            | ("new" | "triaged" | "investigating", "duplicate")
            | ("new" | "triaged" | "investigating", "false_positive")
            | ("new" | "triaged" | "investigating", "accepted_risk")
            | ("closed", "reopened")
            | ("reopened", "investigating")
    )
}

pub(super) fn severity_rank(value: &str) -> u8 {
    match value {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        _ => 1,
    }
}
