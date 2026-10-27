"""Configuration models, YAML loading, validation and the starter config."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from secretsift.core.scenario import LABEL_PATTERN, ScenarioSpec
from secretsift.exceptions import ConfigError
from secretsift.models import DataType, Destination
from secretsift.policies.evaluator import PolicyEvaluator
from secretsift.policies.loader import compile_policy
from secretsift.policies.schema import PolicyConfig

MAX_CONFIG_BYTES = 1024 * 1024
_LABEL = re.compile(r"^" + LABEL_PATTERN + r"$")


ReportFormat = Literal["terminal", "json", "html", "junit"]


def _default_formats() -> list[ReportFormat]:
    return ["terminal", "json", "html"]


class ReportSpec(BaseModel):
    """Where and how reports are written."""

    model_config = ConfigDict(extra="forbid")

    dir: str = "secretsift-reports"
    formats: list[ReportFormat] = Field(default_factory=_default_formats)
    fail_on: Literal["deny", "warn", "never"] = "deny"


class SyntheticValueSpec(BaseModel):
    """One synthetic value to plant: a label and its data type."""

    model_config = ConfigDict(extra="forbid")

    label: str
    type: DataType

    @field_validator("label")
    @classmethod
    def _check_label(cls, v: str) -> str:
        if not _LABEL.match(v):
            raise ValueError("label must start with a letter or '_' and use letters, digits, _.-")
        return v


class SyntheticSpec(BaseModel):
    """Synthetic data section."""

    model_config = ConfigDict(extra="forbid")

    values: list[SyntheticValueSpec] = Field(default_factory=list)


class SecretsiftConfig(BaseModel):
    """Top-level secretsift configuration (``version: 1``)."""

    model_config = ConfigDict(extra="forbid")

    version: Literal[1]
    seed: int | None = None
    offline: bool = True
    network_allowlist: list[str] = Field(default_factory=list)
    sys_path: list[str] = Field(default_factory=lambda: ["."])
    report: ReportSpec = Field(default_factory=ReportSpec)
    synthetic: SyntheticSpec = Field(default_factory=SyntheticSpec)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    providers: dict[str, dict[str, Any]] = Field(default_factory=dict)
    scenarios: list[ScenarioSpec] = Field(default_factory=list)

    @field_validator("providers")
    @classmethod
    def _check_providers(cls, v: dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
        for name, conf in v.items():
            if not isinstance(conf.get("type"), str) or not conf["type"]:
                raise ValueError(f"provider {name!r} needs a string 'type'")
        return v

    @property
    def labels_to_types(self) -> dict[str, DataType]:
        return {v.label: v.type for v in self.synthetic.values}

    def policy_evaluator(self) -> PolicyEvaluator:
        """Compile the policy against this config's labels and scenarios."""
        return compile_policy(
            self.policy,
            set(self.labels_to_types),
            self.labels_to_types,
            scenario_names=[s.name for s in self.scenarios],
            approved_destinations={
                s.name: s.approved_destinations for s in self.scenarios if s.approved_destinations
            },
        )


def _format_errors(err: ValidationError) -> str:
    lines = []
    for e in err.errors(include_input=False, include_url=False):
        loc = ".".join(str(p) for p in e["loc"]) or "<root>"
        lines.append(f"  {loc}: {e['msg']}")
    return "\n".join(lines)


def parse_config(data: Any) -> SecretsiftConfig:
    """Validate an already-parsed mapping; raises ``ConfigError`` without echoing values."""
    if not isinstance(data, dict):
        raise ConfigError("config must be a YAML mapping at the top level")
    version = data.get("version")
    if type(version) is not int or version != 1:
        raise ConfigError("config 'version' is required and must be 1")
    try:
        return SecretsiftConfig.model_validate(data)
    except ValidationError as exc:
        raise ConfigError("invalid config:\n" + _format_errors(exc)) from None


def load_config(path: Path) -> SecretsiftConfig:
    """Load and parse a YAML config (safe_load, 1 MB limit)."""
    p = Path(path)
    try:
        if p.stat().st_size > MAX_CONFIG_BYTES:
            raise ConfigError(f"config file exceeds the {MAX_CONFIG_BYTES} byte limit")
        with p.open("rb") as fh:
            raw = fh.read(MAX_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ConfigError(f"cannot read config file {p.name!r}: {exc.strerror}") from None
    if len(raw) > MAX_CONFIG_BYTES:
        raise ConfigError(f"config file exceeds the {MAX_CONFIG_BYTES} byte limit")
    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        raise ConfigError(f"config is not valid YAML{where}") from None
    return parse_config(data)


def validate_config(cfg: SecretsiftConfig) -> list[str]:
    """Check cross-references (raises ``ConfigError``) and return non-fatal warnings."""
    warnings: list[str] = []
    labels = [v.label for v in cfg.synthetic.values]
    dup = sorted({x for x in labels if labels.count(x) > 1})
    if dup:
        raise ConfigError(f"duplicate synthetic labels: {', '.join(dup)}")
    names = [s.name for s in cfg.scenarios]
    dup = sorted({x for x in names if names.count(x) > 1})
    if dup:
        raise ConfigError(f"duplicate scenario names: {', '.join(dup)}")
    declared = set(labels)
    from secretsift.providers.registry import create_provider

    for pname in cfg.providers:
        try:
            create_provider(pname, cfg.providers)
        except ConfigError as exc:
            raise ConfigError(f"provider {pname!r}: {exc}") from None
    for s in cfg.scenarios:
        for lab in s.data or []:
            if lab not in declared:
                raise ConfigError(f"scenario {s.name!r}: data label {lab!r} is not declared")
        if s.provider is not None and s.provider not in cfg.providers:
            raise ConfigError(f"scenario {s.name!r}: unknown provider {s.provider!r}")
        if Destination.APPROVED_TEST_INPUT in s.approved_destinations:
            warnings.append(
                f"scenario {s.name!r}: approved_test_input is always approved; remove it"
            )
    cfg.policy_evaluator()
    if not cfg.scenarios:
        warnings.append("no scenarios defined; nothing will be tested")
    if not cfg.synthetic.values:
        warnings.append("no synthetic values declared")
    if cfg.policy.mode == "warn_only":
        warnings.append("policy mode is warn_only: deny decisions are downgraded to warn")
    if cfg.policy.default_action.value == "allow":
        warnings.append("default_action is allow: unmatched observations will not be reported")
    if cfg.network_allowlist and cfg.offline:
        warnings.append("network_allowlist is ignored while offline is true")
    if cfg.report.fail_on == "never":
        warnings.append("report.fail_on is never: findings will not fail the run")
    return warnings


_DEFAULT_CONFIG = """\
# secretsift starter configuration. Run: secretsift test --config secretsift.yaml
version: 1                      # required, must be 1
seed: 1337                      # optional: same seed + config => same synthetic values
offline: true                   # block non-loopback network while scenarios run
network_allowlist: []           # hosts permitted when offline: false
sys_path: ["."]                 # directories prepended to sys.path to import targets

report:
  dir: secretsift-reports
  formats: [terminal, json, html]   # terminal | json | html | junit
  fail_on: deny                     # deny | warn | never

synthetic:
  values:                       # test-only secrets planted into scenario inputs
    - {label: customer_api_key, type: synthetic_api_key}

policy:
  mode: strict                  # strict | warn_only (warn_only downgrades deny to warn)
  default_action: deny          # applied to unmatched, non-approved observations
  rules:
    - id: R1
      data: customer_api_key    # a label, a data type, or "*"
      destination: application_logs   # a destination, or "*"
      action: deny
      severity: high
      scenario: leaky-login
      reason: API keys must never be logged
      remediation: Mask the key before logging, or do not log the request.

providers:
  chat: {type: mock, behavior: safe}

scenarios:
  - name: leaky-login           # expected to FAIL: demo target that logs the key
    category: logging
    target: "secretsift.demo:leaky_login"
    inputs: {api_key: "{{ customer_api_key }}", note: hello}
    data: [customer_api_key]
  - name: safe-login            # expected to PASS: demo target that masks the key
    category: logging
    target: "secretsift.demo:safe_login"
    inputs: {api_key: "{{ customer_api_key }}", note: hello}
    data: [customer_api_key]
    provider: chat
"""


def dump_default_config() -> str:
    """Return the annotated starter YAML used by ``secretsift init``."""
    return _DEFAULT_CONFIG
