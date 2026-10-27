"""Config loading, templating and starter-config tests."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import yaml

from secretsift.config import (
    SecretsiftConfig,
    dump_default_config,
    load_config,
    parse_config,
    validate_config,
)
from secretsift.core.scenario import ScenarioSpec, render_inputs
from secretsift.exceptions import ConfigError, PolicyError
from secretsift.models import DataType
from secretsift.synthetic import generate_value

BASE = "version: 1\n"


class ConfigTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def write(self, text: str | bytes) -> Path:
        p = self.dir / "c.yaml"
        if isinstance(text, bytes):
            p.write_bytes(text)
        else:
            p.write_text(text)
        return p


class DefaultConfigTests(ConfigTestCase):
    def test_round_trip_clean(self) -> None:
        text = dump_default_config()
        cfg = load_config(self.write(text))
        self.assertEqual(validate_config(cfg), [])
        targets = {s.target for s in cfg.scenarios}
        self.assertEqual(targets, {"secretsift.demo:leaky_login", "secretsift.demo:safe_login"})
        self.assertEqual({p["type"] for p in cfg.providers.values()}, {"mock"})
        self.assertIn("#", text)

    def test_default_policy_compiles(self) -> None:
        cfg = parse_config(yaml.safe_load(dump_default_config()))
        self.assertIn("R1", cfg.policy_evaluator().rule_ids)


class LoadTests(ConfigTestCase):
    def test_minimal(self) -> None:
        cfg = load_config(self.write(BASE))
        self.assertTrue(cfg.offline)
        self.assertEqual(cfg.report.fail_on, "deny")
        self.assertEqual(cfg.sys_path, ["."])

    def test_version_required_and_one(self) -> None:
        for text in ("seed: 1\n", "version: 2\n", "version: true\n", "version: '1'\n"):
            with self.assertRaisesRegex(ConfigError, "version"):
                load_config(self.write(text))

    def test_extra_key_named(self) -> None:
        with self.assertRaisesRegex(ConfigError, "bogus_key"):
            load_config(self.write(BASE + "bogus_key: 1\n"))
        with self.assertRaisesRegex(ConfigError, "report.colour"):
            load_config(self.write(BASE + "report: {colour: red}\n"))
        with self.assertRaisesRegex(ConfigError, "scenarios.0.oops"):
            load_config(
                self.write(
                    BASE + "scenarios:\n  - {name: a, category: logging, target: 'm:f', oops: 1}\n"
                )
            )

    def test_error_does_not_echo_values(self) -> None:
        with self.assertRaises(ConfigError) as cm:
            load_config(self.write(BASE + "seed: sk-test-SUPERSECRETVALUE\n"))
        self.assertNotIn("SUPERSECRETVALUE", str(cm.exception))

    def test_python_tag_rejected(self) -> None:
        text = BASE + "seed: !!python/object/apply:os.getcwd []\n"
        with self.assertRaisesRegex(ConfigError, "not valid YAML"):
            load_config(self.write(text))

    def test_size_limit(self) -> None:
        with self.assertRaisesRegex(ConfigError, "limit"):
            load_config(self.write(BASE + "# " + "x" * (1024 * 1024) + "\n"))

    def test_missing_file_and_non_mapping(self) -> None:
        with self.assertRaisesRegex(ConfigError, "cannot read"):
            load_config(self.dir / "absent.yaml")
        with self.assertRaisesRegex(ConfigError, "mapping"):
            load_config(self.write("- 1\n- 2\n"))
        with self.assertRaisesRegex(ConfigError, "mapping"):
            load_config(self.write(""))

    def test_bad_enums(self) -> None:
        with self.assertRaisesRegex(ConfigError, "report.fail_on"):
            load_config(self.write(BASE + "report: {fail_on: sometimes}\n"))
        with self.assertRaisesRegex(ConfigError, "synthetic.values.0.type"):
            load_config(self.write(BASE + "synthetic: {values: [{label: a, type: nope}]}\n"))

    def test_provider_needs_type(self) -> None:
        with self.assertRaisesRegex(ConfigError, "needs a string 'type'"):
            load_config(self.write(BASE + "providers: {chat: {behavior: safe}}\n"))


SCEN = "  - {{name: s1, category: logging, target: 'm:f'{extra}}}\n"
SYN = "synthetic: {values: [{label: k, type: synthetic_api_key}]}\n"


class ValidateTests(ConfigTestCase):
    def cfg(self, text: str) -> SecretsiftConfig:
        return load_config(self.write(BASE + text))

    def test_warnings(self) -> None:
        w = validate_config(self.cfg("policy: {mode: warn_only, default_action: allow}\n"))
        self.assertTrue(any("no scenarios" in x for x in w))
        self.assertTrue(any("warn_only" in x for x in w))
        self.assertTrue(any("default_action is allow" in x for x in w))

    def test_unknown_data_label(self) -> None:
        c = self.cfg(SYN + "scenarios:\n" + SCEN.format(extra=", data: [zzz]"))
        with self.assertRaisesRegex(ConfigError, "'zzz' is not declared"):
            validate_config(c)

    def test_invalid_provider_options_rejected_by_validate(self) -> None:
        c = self.cfg("version: 1\nproviders:\n  bad: {type: mock, behaviour: safe}\n")
        with self.assertRaisesRegex(ConfigError, "provider 'bad': unknown option"):
            validate_config(c)

    def test_unknown_provider(self) -> None:
        c = self.cfg(SYN + "scenarios:\n" + SCEN.format(extra=", provider: nope"))
        with self.assertRaisesRegex(ConfigError, "unknown provider 'nope'"):
            validate_config(c)

    def test_duplicate_scenarios_and_labels(self) -> None:
        c = self.cfg("scenarios:\n" + SCEN.format(extra="") * 2)
        with self.assertRaisesRegex(ConfigError, "duplicate scenario"):
            validate_config(c)
        c = self.cfg(
            "synthetic: {values: [{label: k, type: synthetic_email},"
            " {label: k, type: synthetic_name}]}\n"
        )
        with self.assertRaisesRegex(ConfigError, "duplicate synthetic"):
            validate_config(c)

    def test_policy_errors_propagate(self) -> None:
        c = self.cfg(SYN + "policy: {rules: [{id: R, data: nope, action: deny}]}\n")
        with self.assertRaises(PolicyError):
            validate_config(c)
        c = self.cfg(
            SYN
            + "scenarios:\n"
            + SCEN.format(extra="")
            + "policy: {rules: [{id: R, scenario: other, action: deny}]}\n"
        )
        with self.assertRaisesRegex(PolicyError, "unknown scenario 'other'"):
            validate_config(c)

    def test_scenario_approved_destinations_reach_policy(self) -> None:
        c = self.cfg(
            SYN + "scenarios:\n" + SCEN.format(extra=", approved_destinations: [http_request]")
        )
        validate_config(c)
        self.assertIn("s1", c.policy_evaluator()._approved)

    def test_bad_scenario_fields(self) -> None:
        for extra in (", target: 'nocolon'", ", category: regression", ", name: '../x'"):
            bad = "{name: s1, category: logging, target: 'm:f'" + extra + "}"
            with self.assertRaises(ConfigError, msg=extra):
                parse_config(yaml.safe_load(BASE + "scenarios:\n  - " + bad + "\n"))


class TemplateTests(unittest.TestCase):
    def values(self) -> dict[str, str]:
        v = generate_value("k", DataType.API_KEY, run_id="r", seed=1)
        return {"k": v.value}

    def test_deep_substitution_and_whitespace(self) -> None:
        raw = self.values()["k"]
        out = render_inputs(
            {"a": "{{k}}", "b": ["x {{ k }}", {"c": "{{   k   }}!"}], "n": 3, "t": ("{{ k }}",)},
            self.values(),
        )
        self.assertEqual(out["a"], raw)
        self.assertEqual(out["b"][0], "x " + raw)
        self.assertEqual(out["b"][1]["c"], raw + "!")
        self.assertEqual((out["n"], out["t"]), (3, [raw]))

    def test_accepts_synthetic_value(self) -> None:
        v = generate_value("k", DataType.API_KEY, run_id="r", seed=1)
        self.assertEqual(render_inputs({"a": "{{ k }}"}, {"k": v})["a"], v.value)

    def test_unknown_label(self) -> None:
        with self.assertRaisesRegex(ConfigError, "unknown label 'missing'"):
            render_inputs({"a": ["{{ missing }}"]}, self.values())

    def test_no_template_untouched_and_input_not_mutated(self) -> None:
        src = {"a": "plain {x}", "b": ["{{ k }}"]}
        render_inputs(src, self.values())
        self.assertEqual(src["b"], ["{{ k }}"])

    def test_spec_repr_has_no_values(self) -> None:
        s = ScenarioSpec(name="a", category="logging", target="m:f")  # type: ignore[arg-type]
        self.assertNotIn("sk-test", repr(s))


if __name__ == "__main__":
    unittest.main()
