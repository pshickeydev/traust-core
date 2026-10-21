import json

TRIAGE = json.dumps(
    {
        "triage_completed": "2025-01-01",
        "triage_context": {
            "mode": "synthetic",
            "environment": "synthetic test environment",
            "scoring": "synthetic test scoring",
            "noise_tolerance": "synthetic",
            "votes_per_finding": 1,
            "repo": "example.invalid/synthetic/repository",
            "harness_version": "0.0.0",
            "reemitted": "2025-01-02",
            "reemit_method": "synthetic fixture generation",
        },
        "summary": {
            "input_count": 0,
            "true_positives": 0,
            "hardening": 0,
            "false_positives": 0,
            "undetermined": 0,
            "duplicates": 0,
            "needs_manual_test": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0},
        },
        "findings": [],
    }
).encode()
