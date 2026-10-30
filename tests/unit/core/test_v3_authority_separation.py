import unittest
from kinetic_trust_library.errors import ValidationError
from kinetic_trust_library.v3.authority_separation import project_authority_separation


def facts():
    return dict(agent_processes=["process:agent"],agent_boundary_processes=["process:agent","process:helper"],
        lease_constructor_processes=["process:authority"],accepted_lease_keys=["key:lease"],
        operator_boundary="boundary:operator",
        measurers=[dict(id="measurer:a",operator_boundary="boundary:operator",processes=["process:measure-a"],accepted_keys=["key:measure-a"]),
                   dict(id="measurer:b",operator_boundary="boundary:external",processes=["process:measure-b"],accepted_keys=["key:measure-b"])],
        key_custody=[dict(key="key:lease",processes=["process:authority"]),
                     dict(key="key:measure-a",processes=["process:measure-a"]),
                     dict(key="key:measure-b",processes=["process:measure-b"])],used_measurers=["measurer:a","measurer:b"])


class AuthoritySeparationTests(unittest.TestCase):
    def evaluate(self,f=None,**changes):
        args=dict(inventory=f or facts(),quorum_members=["measurer:a","measurer:b"],quorum_k=2,
            zone_class="blue",single_measurer_limit=None)
        args.update(changes);return project_authority_separation(**args)

    def test_valid_separation_is_audit_grade_never_permission(self):
        r=self.evaluate();self.assertTrue(r.valid)
        self.assertEqual(r.external_measurers,("measurer:b",));self.assertEqual(r.evidence_grade,"architectural-audit")
        self.assertFalse(r.action_permitted)

    def test_constructor_or_accepted_key_anywhere_inside_agent_boundary_fails(self):
        f=facts();f["lease_constructor_processes"].append("process:helper")
        self.assertEqual(self.evaluate(f).reason,"AGENT_CAN_CONSTRUCT_LEASE")
        for index in range(3):
            f=facts();f["key_custody"][index]["processes"].append("process:helper")
            with self.subTest(index=index):self.assertEqual(self.evaluate(f).reason,"AGENT_HOLDS_ACCEPTED_KEY")

    def test_a_process_cannot_both_measure_and_carry_action(self):
        f=facts();f["measurers"][0]["processes"].append("process:agent")
        self.assertEqual(self.evaluate(f).reason,"MEASUREMENT_EXECUTION_PROCESS_OVERLAP")

    def test_outside_operator_measurer_must_actually_participate(self):
        f=facts();f["used_measurers"]=["measurer:a"]
        self.assertFalse(self.evaluate(f).valid)
        f=facts();f["measurers"][1]["operator_boundary"]="boundary:operator"
        self.assertEqual(self.evaluate(f).reason,"NO_EXTERNAL_MEASURER")

    def test_blue_and_deep_blue_cannot_select_single_measurer_quorum(self):
        for zone in ("blue","deep_blue"):
            with self.subTest(zone=zone),self.assertRaises(ValidationError):self.evaluate(quorum_k=1,zone_class=zone)

    def test_green_and_cyan_single_measurer_need_declared_limitation(self):
        for zone in ("green","cyan"):
            with self.subTest(zone=zone),self.assertRaises(ValidationError):self.evaluate(quorum_k=1,zone_class=zone)
            self.assertTrue(self.evaluate(quorum_k=1,zone_class=zone,single_measurer_limit="No redundant failure tolerance").valid)

    def test_incomplete_key_custody_is_not_assumed_separated(self):
        f=facts();f["key_custody"].pop()
        with self.assertRaises(ValidationError):self.evaluate(f)

    def test_two_measurer_names_cannot_turn_one_key_into_two_votes(self):
        f=facts();f["measurers"][1]["accepted_keys"]=["key:measure-a"]
        self.assertEqual(self.evaluate(f).reason,"MEASURER_KEYS_SHARED")

    def test_distinct_keys_in_one_process_cannot_count_as_two_measurers(self):
        f=facts();f["measurers"][1]["processes"]=["process:measure-a"]
        self.assertEqual(self.evaluate(f).reason,"MEASURER_PROCESS_SHARED")
