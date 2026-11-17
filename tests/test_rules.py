import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import validate_rules  # noqa: E402
from rulelib import Rule, load_rules  # noqa: E402


def sentinel_rule(**overrides):
    data = {
        "id": "00000000-0000-4000-8000-000000000001", "name": "Test rule",
        "description": "d", "severity": "Medium", "kind": "Scheduled",
        "requiredDataConnectors": [], "queryFrequency": "1h", "queryPeriod": "1h",
        "triggerOperator": "gt", "triggerThreshold": 0, "tactics": ["CredentialAccess"],
        "relevantTechniques": ["T1110.003"], "query": "SigninLogs | project IPAddress",
        "entityMappings": [{"entityType": "IP", "fieldMappings": [
            {"identifier": "Address", "columnName": "IPAddress"}]}],
        "version": "1.0.0",
    }
    data.update(overrides)
    return Rule(Path("test.yaml"), "sentinel", data,
                data["tactics"], data["relevantTechniques"])


class RepositoryRulesTests(unittest.TestCase):
    def test_all_rules_pass_validation(self):
        rules = load_rules()
        self.assertGreater(len(rules), 0)
        for rule in rules:
            with self.subTest(rule=rule.path.name):
                problems = validate_rules.check_common(rule)
                problems += (validate_rules.check_sigma(rule) if rule.kind == "sigma"
                             else validate_rules.check_sentinel(rule))
                self.assertEqual(problems, [])


class ValidatorCatchesMistakesTests(unittest.TestCase):
    def problems(self, rule):
        return validate_rules.check_common(rule) + validate_rules.check_sentinel(rule)

    def test_good_rule_passes(self):
        self.assertEqual(self.problems(sentinel_rule()), [])

    def test_period_shorter_than_frequency(self):
        rule = sentinel_rule(queryFrequency="1h", queryPeriod="30m")
        self.assertTrue(any("queryPeriod" in p for p in self.problems(rule)))

    def test_entity_column_missing_from_query(self):
        rule = sentinel_rule(query="SigninLogs | project UserPrincipalName")
        self.assertTrue(any("IPAddress" in p for p in self.problems(rule)))

    def test_bad_technique_and_tactic(self):
        rule = sentinel_rule(tactics=["Hacking"], relevantTechniques=["T99"])
        problems = self.problems(rule)
        self.assertTrue(any("technique" in p for p in problems))
        self.assertTrue(any("tactic" in p for p in problems))

    def test_unbalanced_query(self):
        rule = sentinel_rule(query="SigninLogs | where (IPAddress == '1.2.3.4'")
        self.assertTrue(any("unbalanced" in p for p in self.problems(rule)))


if __name__ == "__main__":
    unittest.main()
