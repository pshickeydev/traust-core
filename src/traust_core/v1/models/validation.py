from __future__ import annotations

import re
from datetime import date, datetime
from enum import StrEnum
from fnmatch import fnmatchcase
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import Field

from traust_core.v1.errors import ValidationError
from traust_core.v1.models.base import Model
from traust_core.v1.models.findings import EvidenceRef, SkillInput
from traust_core.v1.models.vocabulary import (
    ScopeBindingMode,
    ValidationAdapterKind,
    ValidationApprovalMode,
    ValidationTechnique,
    ValidationVerdict,
)

# Control-plane namespaces/resources are a deny-floor, not a grant: only explicit
# engagement grants unlock them (legacy assessments 2026-07-31 F2/F4; "openshift-*"
# replaced a literal list that missed openshift-config/-ingress/-monitoring).
# Stays in core on purpose — moving a deny-list out weakens it.
_CONTROL_PLANE_NAMESPACES = (
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "default",
    "openshift",
    "openshift-*",
)
_CONTROL_PLANE_RESOURCES = frozenset(
    {
        "nodes",
        "node",
        "clusterroles",
        "clusterrole",
        "clusterrolebindings",
        "clusterrolebinding",
        "customresourcedefinitions",
        "customresourcedefinition",
        "crds",
        "crd",
        "machineconfigs",
        "machineconfig",
        "machineconfigpools",
        "machineconfigpool",
        "apiservices",
        "apiservice",
        "clusterversions",
        "clusterversion",
        "clusteroperators",
        "clusteroperator",
        "namespaces",
        "namespace",
        "ns",
        "priorityclasses",
        "priorityclass",
        "oauths",
        "oauth",
        "validatingwebhookconfigurations",
        "mutatingwebhookconfigurations",
    }
)
_READONLY_VERBS = frozenset(
    {
        "get",
        "list",
        "watch",
        "describe",
        "logs",
        "top",
        "explain",
        "raw-read",
        "rbac-can-i",
        "can-i",
    }
)
_ERROR_SIGNATURES = (
    (
        "forbidden",
        re.compile(
            r"Error from server \(Forbidden\)|\bforbidden: User\b"
            r"|\bForbidden\b[^\n]{0,160}\bcannot (?:get|list|watch|create|update|patch|delete"
            r"|impersonate|use)\b"
            r'|\bUser "[^"]+" cannot (?:get|list|watch|create|update|patch|delete'
            r"|impersonate|use)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "command-not-found",
        re.compile(
            r"command not found|executable file not found|not found in \$?PATH",
            re.IGNORECASE,
        ),
    ),
    (
        "jsonpath-error",
        re.compile(
            r"error executing jsonpath|error parsing jsonpath|unrecognized identifier",
            re.IGNORECASE,
        ),
    ),
    (
        "not-found",
        re.compile(
            r"Error from server \(NotFound\)|the server doesn'?t have a resource type",
            re.IGNORECASE,
        ),
    ),
    ("does-not-exist", re.compile(r"\bdoes not exist\b", re.IGNORECASE)),
    (
        "could-not-connect",
        re.compile(
            r"Could not connect|Unable to connect to the server"
            r"|could not resolve host|no route to host",
            re.IGNORECASE,
        ),
    ),
    (
        "unsubstituted-template",
        re.compile(
            r"system:serviceaccount:\{[^}]*\}|\{ns\}:\{sa\}|--as=[^\s\"']*\{[a-z_]+\}",
        ),
    ),
)
_RBAC_TRIED_EMPTY = re.compile(r"^vf-rbac-tried:\s*$", re.MULTILINE)


class ValidationActionKind(StrEnum):
    """Scope operations, including operations outside the execution-adapter registry."""

    K8S = "k8s"
    CONTAINER = "container"
    WASM = "wasm"
    BROWSER = "browser"
    CREDENTIAL = "credential"
    INVENTORY = "inventory"


class ValidationAction(Model):
    kind: ValidationActionKind
    verb: str = Field(min_length=1)


class ValidationTarget(Model):
    context: str | None = None
    namespace: str | None = None
    resource: str | None = None
    name: str | None = None
    image: str | None = None
    artifact_id: UUID | None = None
    url: str | None = None


class ClusterScope(Model):
    context: str
    namespaces: tuple[str, ...] = ()
    verbs_denied: frozenset[str] = frozenset()
    explicit_namespaces: frozenset[str] = frozenset()

    def permits_namespace(self, namespace: str | None) -> bool:
        if namespace is None:
            return "*" in self.namespaces
        return any(fnmatchcase(namespace, pattern) for pattern in self.namespaces)


class OffLimit(Model):
    context: str | None = None
    namespace: str | None = None
    resource: str | None = None
    verb: str | None = None
    name: str | None = None
    image: str | None = None

    def matches(self, action: ValidationAction, target: ValidationTarget) -> bool:
        pairs = (
            (self.context, target.context),
            (self.namespace, target.namespace),
            (self.resource, target.resource),
            (self.verb, action.verb),
            (self.name, target.name),
            (self.image, target.image),
        )
        # An unknown target field cannot bypass a deny keyed on that field.
        return all(
            rule is None or value is None or fnmatchcase(value, rule) for rule, value in pairs
        )


class BrowserTarget(Model):
    victim_origin: str
    attacker_origins: tuple[str, ...] = ()
    allowed_verbs: frozenset[str] = frozenset()

    def matches_url(self, url: str) -> bool:
        origin = _origin(url)
        return origin is not None and any(
            origin == _origin(allowed) for allowed in (self.victim_origin, *self.attacker_origins)
        )


def _origin(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
    except ValueError as e:
        raise ValidationError("invalid browser validation target URL") from e
    return f"{parsed.scheme}://{parsed.netloc}".lower() if parsed.scheme and parsed.netloc else None


class PlanStep(Model): ...


class RefusalReason(Model): ...


class SoundnessResult(Model):
    verdict: ValidationVerdict
    flag: str | None = None


# TODO(validation-flow): is_rbac()/refutation_flag() parse the legacy harness
# transcript format ("vf-rbac-*" markers) — bridge only. When execution lands,
# producers stamp structured fields; core should not own the wire format.
class ValidationProbe(Model):
    """Only the observations consumed by the refutation-soundness rules."""

    verdict: ValidationVerdict
    verb: str
    observed: str | None = None
    positive_controls: tuple[bool, ...] = ()
    differential_discriminated: bool | None = None

    def is_rbac(self) -> bool:
        return self.verb == "rbac-can-i" or "vf-rbac-" in (self.observed or "")

    def refutation_flag(self) -> str | None:
        if self.verdict != ValidationVerdict.REFUTED:
            return None
        observed = self.observed or ""
        for name, pattern in _ERROR_SIGNATURES:
            if pattern.search(observed):
                return f"error-signature:{name}"
        if self.is_rbac() and _RBAC_TRIED_EMPTY.search(observed):
            return "rbac-zero-subjects"
        return None


class ResourceState(Model): ...


class ClusterDiff(Model): ...


class FindingChain(Model): ...


class Authorization(Model): ...


class TargetObservation(Model): ...


class TargetAttestation(Model): ...


class ValidationRun(Model): ...


class ValidationFilter(Model): ...


class ValidationDimension(Model): ...


class ValidationRollup(Model): ...


class ValidationInput(SkillInput): ...


class ValidationScope(Model):
    expires: date | None = None
    modes: frozenset[ScopeBindingMode] = frozenset()
    clusters: tuple[ClusterScope, ...] = ()
    off_limits: tuple[OffLimit, ...] = ()
    browser: tuple[BrowserTarget, ...] = ()
    containers: tuple[str, ...] = ()
    images: tuple[str, ...] = ()
    wasm_artifact_ids: frozenset[UUID] = frozenset()
    credential_probe_classes: frozenset[str] = frozenset()
    inventory_aws_profiles: frozenset[str] = frozenset()
    inventory_cluster_contexts: frozenset[str] = frozenset()

    def permits(self, action: ValidationAction, target: ValidationTarget, *, as_of: date) -> bool:
        if self.expires is not None and as_of > self.expires:
            return False
        if any(rule.matches(action, target) for rule in self.off_limits):
            return False
        if action.kind == ValidationActionKind.K8S:
            cluster = next((c for c in self.clusters if c.context == target.context), None)
            if cluster is None:
                # TODO(validation-flow): "__current__" is a sentinel shared with scope builders
                # — extract to a module constant before the service layer constructs ClusterScope.
                cluster = next((c for c in self.clusters if c.context == "__current__"), None)
            if cluster is None or action.verb in cluster.verbs_denied:
                return False
            if target.namespace and any(
                fnmatchcase(target.namespace, pattern) for pattern in _CONTROL_PLANE_NAMESPACES
            ):
                if not any(
                    fnmatchcase(target.namespace, pattern)
                    for pattern in cluster.explicit_namespaces
                ):
                    return False
            elif (
                not target.namespace
                and target.resource in _CONTROL_PLANE_RESOURCES
                and action.verb not in _READONLY_VERBS
                and "*" not in cluster.explicit_namespaces
            ):
                return False
            return cluster.permits_namespace(target.namespace) and self._permits_image(target.image)
        if action.kind == ValidationActionKind.CONTAINER:
            return (
                bool(self.containers)
                and (
                    target.name is None or any(fnmatchcase(target.name, p) for p in self.containers)
                )
                and self._permits_image(target.image)
            )
        if action.kind == ValidationActionKind.WASM:
            return target.artifact_id in self.wasm_artifact_ids
        if action.kind == ValidationActionKind.BROWSER:
            if not target.url:
                return False
            matched = next((b for b in self.browser if b.matches_url(target.url)), None)
            return matched is not None and action.verb in matched.allowed_verbs
        if ScopeBindingMode.EXPLICIT not in self.modes:
            return False
        if action.kind == ValidationActionKind.CREDENTIAL:
            return action.verb == "introspect" and target.resource in self.credential_probe_classes
        return action.verb == "enumerate" and (
            (target.resource == "aws_profile" and target.name in self.inventory_aws_profiles)
            or (
                target.resource == "cluster_context"
                and target.name in self.inventory_cluster_contexts
            )
        )

    def _permits_image(self, image: str | None) -> bool:
        return not image or not self.images or any(fnmatchcase(image, p) for p in self.images)


class ValidationPlan(Model):
    finding_id: UUID
    target: ValidationTarget
    technique: ValidationTechnique
    adapter: ValidationAdapterKind
    approval_mode: ValidationApprovalMode
    steps: tuple[PlanStep, ...] = ()
    refusal: RefusalReason | None = None

    def requires_approval(self) -> bool:
        return self.approval_mode == ValidationApprovalMode.INTERACTIVE


class ValidationAttempt(Model):
    plan_id: UUID
    verdict: ValidationVerdict
    evidence: tuple[EvidenceRef, ...] = ()
    started_at: datetime
    finished_at: datetime
    probes: tuple[ValidationProbe, ...] = ()
    observed_impact: str | None = None
    soundness_flag: str | None = None
    install_failed: bool | None = None
    controls_required: bool
    differential_required: bool

    def soundness(self) -> SoundnessResult:
        flag = self.soundness_flag or None
        if not flag and self.verdict == ValidationVerdict.REFUTED:
            flag = self._refutation_flag()
        verdict = (
            ValidationVerdict.INCONCLUSIVE
            if flag and self.verdict == ValidationVerdict.REFUTED
            else self.verdict
        )
        return SoundnessResult(verdict=verdict, flag=flag)

    def _refutation_flag(self) -> str | None:
        if self.install_failed:
            return "target-not-deployed"
        probes = tuple(p for p in self.probes if p.verdict == ValidationVerdict.REFUTED)
        controls = tuple(ok for p in probes for ok in p.positive_controls)
        if any(ok is False for ok in controls):
            return "failed-positive-control"
        if self.controls_required and not any(controls):
            return "missing-positive-control"
        if any(p.differential_discriminated is False for p in probes):
            return "non-discriminating-oracle"
        if (
            self.differential_required
            and any(p.is_rbac() for p in probes)
            and not any(p.differential_discriminated for p in probes)
        ):
            return "missing-differential-probe"
        if not probes and self.observed_impact:
            probes = (
                ValidationProbe(
                    verdict=ValidationVerdict.REFUTED,
                    verb="",
                    observed=self.observed_impact,
                ),
            )
        flags = tuple(p.refutation_flag() for p in probes)
        return flags[0] if flags and all(flags) else None


class ClusterSnapshot(Model):
    taken_at: datetime
    resources: tuple[ResourceState, ...] = ()

    def diff(self, other: ClusterSnapshot) -> ClusterDiff:
        raise NotImplementedError("stub: replaces cluster_state_diff.diff")
