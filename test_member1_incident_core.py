"""Tests for member1_incident_core.py
Run with: python -m unittest -v test_member1_incident_core
"""

import unittest

from incident_management import (
    now,
    validate_datetime,
    ACTION_FIELDS,
    INCIDENT_FIELDS,
    SEVERITY_LEVELS,
    URGENCY_LEVELS,
    Incident,
    IncidentManager,
)

REPORT = {
    "category": "Phishing / Suspicious Message",
    "description": "A simulated message asked me to verify my account.",
    "severity": "High",
    "urgency": "Medium",
    "affected_scope": "One user",
}


def make_incident(**changes):
    data = dict(
        incident_id="INC-1001",
        reported_at="12/10/2026 10:00 AM",
        category="Phishing / Suspicious Message",
        description="A simulated message asked me to verify my account.",
        severity="High",
        urgency="Medium",
        affected_scope="One user",
        priority_score=5,
    )
    data.update(changes)
    return Incident(**data)


class ValidationTests(unittest.TestCase):
    def test_valid_incident(self):
        make_incident().validate()

    def test_invalid_values_are_rejected(self):
        bad_changes = [
            {"incident_id": "1001"},
            {"incident_id": "INC-abc"},
            {"reported_at": "yesterday"},
            {"reported_at": "2026-10-12T10:00:00"},   # old ISO format
            {"reported_at": "12/10/2026 10:00"},      # no AM/PM
            {"reported_at": "32/10/2026 10:00 AM"},   # day does not exist
            {"category": "Spam"},
            {"description": "   "},
            {"description": "x" * 1001},
            {"severity": "Extreme"},
            {"urgency": "Urgent"},
            {"affected_scope": "Everyone"},
            {"status": "Pending"},
            {"description": None},
            {"priority_score": 7},        # does not match High + Medium
            {"priority_score": 5.0},      # equal to 5 but not an int
            {"priority_score": "5"},
            {"priority_score": True},
            {"reviewed_at": "not a date"},
            {"status": "Resolved", "reviewed_at": "12/10/2026 11:00 AM"},  # no resolution
            {"status": "Under Review"},   # reviewed but no review time
        ]
        for change in bad_changes:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):
                    make_incident(**change).validate()

    def test_reviewed_incident_with_review_time_is_valid(self):
        make_incident(status="Under Review", reviewed_at="12/10/2026 11:00 AM").validate()
        make_incident(
            status="Resolved", reviewed_at="12/10/2026 11:00 AM", resolution="Done."
        ).validate()

    def test_date_format(self):
        self.assertTrue(validate_datetime("12/10/2026 10:00 AM"))
        self.assertTrue(validate_datetime(now()))
        self.assertFalse(validate_datetime("2026-10-12 10:00 AM"))
        self.assertFalse(validate_datetime(""))

    def test_description_with_1000_characters_is_allowed(self):
        make_incident(description="x" * 1000).validate()


class PriorityTests(unittest.TestCase):
    def test_all_combinations(self):
        for s, severity in enumerate(SEVERITY_LEVELS, start=1):
            for u, urgency in enumerate(URGENCY_LEVELS, start=1):
                incident = make_incident(severity=severity, urgency=urgency)
                self.assertEqual(incident.calculate_priority(), s + u)

    def test_lowest_and_highest(self):
        self.assertEqual(make_incident(severity="Low", urgency="Low").calculate_priority(), 2)
        self.assertEqual(make_incident(severity="Critical", urgency="High").calculate_priority(), 7)

    def test_invalid_severity_or_urgency(self):
        for bad in ("Extreme", None, ["High"]):
            with self.assertRaises(ValueError):
                make_incident(severity=bad).calculate_priority()
            with self.assertRaises(ValueError):
                make_incident(urgency=bad).calculate_priority()


class StatusTests(unittest.TestCase):
    def test_normal_path(self):
        incident = make_incident()
        incident.update_status("Under Review")
        incident.update_status("Resolved", "Password reset.")
        incident.update_status("Closed")
        self.assertEqual(incident.status, "Closed")
        self.assertEqual(incident.resolution, "Password reset.")

    def test_not_allowed_changes(self):
        incident = make_incident()
        for target in ("Resolved", "Closed", "Submitted", "Pending"):
            with self.assertRaises(ValueError):
                incident.update_status(target, "x")
        self.assertEqual(incident.status, "Submitted")
        with self.assertRaises(ValueError):
            make_incident(status="Closed").update_status("Under Review")

    def test_resolving_needs_a_resolution(self):
        incident = make_incident(status="Under Review")
        with self.assertRaises(ValueError):
            incident.update_status("Resolved", "  ")
        self.assertEqual(incident.status, "Under Review")

    def test_resolution_is_only_accepted_when_resolving(self):
        incident = make_incident()
        with self.assertRaises(ValueError):
            incident.update_status("Under Review", "some text")
        self.assertEqual(incident.status, "Submitted")
        incident.update_status("Under Review")
        with self.assertRaises(ValueError):
            incident.update_status("Closed", "some text")
        self.assertEqual(incident.status, "Under Review")

    def test_review_time_has_the_agreed_format(self):
        incident = make_incident()
        incident.update_status("Under Review")
        self.assertTrue(validate_datetime(incident.reviewed_at))

    def test_reopening_clears_the_old_resolution(self):
        incident = make_incident(status="Under Review")
        incident.update_status("Resolved", "Done.")
        incident.update_status("Under Review")
        self.assertEqual(incident.resolution, "")
        incident.validate()

    def test_reviewed_at_is_set_once(self):
        incident = make_incident()
        self.assertEqual(incident.reviewed_at, "")
        incident.update_status("Under Review")
        first_time = incident.reviewed_at
        self.assertNotEqual(first_time, "")
        incident.update_status("Resolved", "Done.")
        incident.update_status("Under Review")  # reopen
        self.assertEqual(incident.reviewed_at, first_time)


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.manager = IncidentManager()

    def test_add_incident(self):
        incident = self.manager.add_incident(REPORT)
        self.assertEqual(incident.incident_id, "INC-1001")
        self.assertEqual(incident.priority_score, 5)
        self.assertEqual(incident.status, "Submitted")
        self.assertEqual(tuple(incident.to_dict()), INCIDENT_FIELDS)
        self.assertEqual(len(self.manager.incidents), 1)

    def test_bad_reports_are_rejected(self):
        bad_reports = [
            dict(REPORT, description=" "),
            dict(REPORT, description=None),
            dict(REPORT, category="Spam"),
            dict(REPORT, severity=["High"]),
            dict(REPORT, urgency=""),
            dict(REPORT, affected_scope="Everyone"),
            dict(REPORT, description="x" * 1001),
        ]
        for report in bad_reports:
            with self.assertRaises(ValueError):
                self.manager.add_incident(report)
        self.assertEqual(len(self.manager.incidents), 0)

    def test_missing_field_or_wrong_type(self):
        report = dict(REPORT)
        del report["severity"]
        with self.assertRaises(ValueError):
            self.manager.add_incident(report)
        with self.assertRaises(ValueError):
            self.manager.add_incident(None)

    def test_ids_are_unique(self):
        first = self.manager.add_incident(REPORT)
        second = self.manager.add_incident(REPORT)
        self.assertNotEqual(first.incident_id, second.incident_id)
        self.assertEqual(second.incident_id, "INC-1002")

    def test_new_id_continues_after_loaded_incidents(self):
        manager = IncidentManager([make_incident(incident_id="INC-1050")])
        self.assertEqual(manager.add_incident(REPORT).incident_id, "INC-1051")

    def test_duplicate_or_invalid_loaded_incidents(self):
        with self.assertRaises(ValueError):
            IncidentManager([make_incident(), make_incident()])
        with self.assertRaises(ValueError):
            IncidentManager([make_incident(severity="Extreme")])

    def test_find_incident(self):
        incident = self.manager.add_incident(REPORT)
        self.assertIs(self.manager.find_incident("INC-1001"), incident)
        self.assertIsNone(self.manager.find_incident("INC-9999"))
        self.assertIsNone(self.manager.find_incident(""))
        self.assertIsNone(self.manager.find_incident(None))

    def test_update_status_saves_an_action(self):
        incident = self.manager.add_incident(REPORT)
        result = self.manager.update_status("INC-1001", "Under Review", note="Started.")
        self.assertIs(result, incident)
        self.assertEqual(incident.status, "Under Review")
        action = self.manager.actions[0]
        self.assertEqual(tuple(action), ACTION_FIELDS)
        self.assertEqual(action["action_id"], "ACT-0001")
        self.assertEqual(action["incident_id"], "INC-1001")
        self.assertEqual(action["action_type"], "Status changed: Submitted -> Under Review")
        self.assertEqual(action["note"], "Started.")

    def test_action_ids_are_unique(self):
        self.manager.add_incident(REPORT)
        self.manager.update_status("INC-1001", "Under Review")
        self.manager.update_status("INC-1001", "Resolved", resolution="Fixed.")
        self.manager.update_status("INC-1001", "Closed")
        ids = [action["action_id"] for action in self.manager.actions]
        self.assertEqual(ids, ["ACT-0001", "ACT-0002", "ACT-0003"])

    def test_reopening_keeps_the_old_resolution_in_the_action_note(self):
        self.manager.add_incident(REPORT)
        self.manager.update_status("INC-1001", "Under Review")
        self.manager.update_status("INC-1001", "Resolved", resolution="Password reset.")
        self.manager.update_status("INC-1001", "Under Review", note="New evidence.")
        note = self.manager.actions[-1]["note"]
        self.assertIn("Password reset.", note)
        self.assertIn("New evidence.", note)

    def test_action_id_uses_the_biggest_loaded_number(self):
        old = [
            {"action_id": "ACT-0001", "incident_id": "INC-1001"},
            {"action_id": "ACT-0007", "incident_id": "INC-1001"},
        ]
        manager = IncidentManager([make_incident()], old)
        manager.update_status("INC-1001", "Under Review")
        self.assertEqual(manager.actions[-1]["action_id"], "ACT-0008")

    def test_bad_loaded_actions_are_rejected(self):
        one = {"action_id": "ACT-0001", "incident_id": "INC-1001"}
        for actions in ([one, dict(one)], [{"incident_id": "INC-1001"}],
                        [{"action_id": "ACT-x", "incident_id": "INC-1001"}]):
            with self.assertRaises(ValueError):
                IncidentManager([make_incident()], actions)

    def test_failed_update_changes_nothing(self):
        self.manager.add_incident(REPORT)
        with self.assertRaises(ValueError):
            self.manager.update_status("INC-1001", "Closed")
        with self.assertRaises(ValueError):
            self.manager.update_status("INC-9999", "Under Review")
        self.assertEqual(self.manager.find_incident("INC-1001").status, "Submitted")
        self.assertEqual(self.manager.actions, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
