"""Offline complete deployment installation and catalog joins."""
import copy,json,unittest
from importlib.util import find_spec
from pathlib import Path
from kinetic_trust_library.errors import ValidationError


def fixture():
    p=json.loads((Path(__file__).parents[3]/'spec/proposals/demand-supplier-v1.json').read_text())['deployment_profile']
    p['standing_policy']=dict(mode='history-with-scoped-readiness-v1',profile_id='fixture-readiness',version=1,digest='sha256:'+'a'*64)
    p['boundary']=dict(resources=['urn:resource:test'],entitled_subjects=['software_agent'],affected_outside=[],jurisdictions=['test'],authority_limits=['approved operations'])
    p['label_sets']={'body.hardware.bmc_reachable':{'labels':['reachable','unreachable']}}
    return p


@unittest.skipUnless(all(find_spec(n) for n in ('rfc8785','jsonschema')),'install v3-proofs')
class DeploymentDeclarationTests(unittest.TestCase):
    def validate(self,p):
        import rfc8785
        from kinetic_trust_library.v3.deployment_declaration import validate_deployment_declaration
        return validate_deployment_declaration(rfc8785.dumps(p))

    def test_complete_declaration_and_required_boundary(self):
        p=fixture();self.assertEqual(self.validate(p),p)
        for name in ('boundary','standing_policy','risk_factors','soul_veto'):
            q=copy.deepcopy(p);del q[name]
            with self.subTest(name=name),self.assertRaises(ValidationError):self.validate(q)
        for patch in (dict(version=True),dict(version=1.5),dict(extra=True),dict(standing_decay_rate=2)):
            with self.subTest(patch=patch),self.assertRaises(ValidationError):self.validate(dict(p,**patch))

    def test_catalog_existence_normalization_and_labels(self):
        p=fixture()
        for path in ('risk','feed','normalization','label_sets'):
            q=copy.deepcopy(p)
            if path=='risk':q['risk_factors']['evidence_density']['signals']=['world.security.not_a_signal']
            elif path=='feed':q['feeds']['feed-01']['populates']=['world.security.not_a_signal']
            else:q.setdefault(path,{})['world.security.not_a_signal']={'method':'test'} if path=='normalization' else {'labels':['a','b']}
            with self.subTest(path=path),self.assertRaises(ValidationError):self.validate(q)
        q=copy.deepcopy(p);del q['normalization']['world.security.anomaly_score']
        with self.assertRaisesRegex(ValidationError,'normalization'):self.validate(q)
        q=copy.deepcopy(p);del q['label_sets']
        with self.assertRaisesRegex(ValidationError,'label'):self.validate(q)
        q=copy.deepcopy(p);q['risk_factors']['trust_trend']['signals']=['world.weather.precipitation_type']
        with self.assertRaisesRegex(ValidationError,'label'):self.validate(q)
        q['label_sets']['world.weather.precipitation_type']={'labels':['rain','snow','none']}
        self.validate(q)

    def test_numeric_category_dependencies_are_not_lost(self):
        for signal in ('world.digital.healthy_region_fraction','world.presence.direction_entropy',
                       'information.emotion.emotion_entropy','time.rhythm.spectral_entropy'):
            p=fixture();p['risk_factors']['trust_trend']['signals']=[signal]
            with self.subTest(signal=signal),self.assertRaisesRegex(ValidationError,'label'):self.validate(p)
            p['label_sets'][signal]={'labels':['one','other']}
            self.validate(p)
        # A physical quantity does not become categorical merely because its
        # group is named entropy or its value is a bounded ratio.
        for signal in ('body.entropy.memory_leak_rate','body.compute.gpu_utilization'):
            p=fixture();p['risk_factors']['trust_trend']['signals']=[signal];self.validate(p)

    def test_alias_collision_and_selection(self):
        p=fixture();p['risk_factors']['trust_trend']['signals']=['body.network.interface_count']
        with self.assertRaisesRegex(ValidationError,'alias'):self.validate(p)
        p['aliases']['network_interface_count']='body.network.interface_count';self.validate(p)
        for selected in ('world.security.anomaly_score','world.network.interface_count'):
            q=copy.deepcopy(p);q['aliases']['network_interface_count']=selected
            with self.subTest(selected=selected),self.assertRaisesRegex(ValidationError,'alias'):self.validate(q)
        q=copy.deepcopy(p);q['risk_factors']['trust_trend']['signals'].append('world.network.interface_count')
        with self.assertRaisesRegex(ValidationError,'alias'):self.validate(q)
        q=copy.deepcopy(p);q['aliases']['invented']='body.network.interface_count'
        with self.assertRaisesRegex(ValidationError,'alias'):self.validate(q)

    def test_exact_weights_and_numeric_controls(self):
        p=fixture();names=list(p['risk_factors'])
        for values,valid in (([.3333333333333333,.3333333333333333,.1333333333333334,.1,.1],True),
                             ([.3333333333333333,.3333333333333333,.1333333333333333,.1,.1],False),
                             ([True,.2,.2,.2,.2],False)):
            q=copy.deepcopy(p)
            for n,v in zip(names,values):q['risk_factors'][n]['weight']=v
            if valid:self.validate(q)
            else:
                with self.assertRaises(ValidationError):self.validate(q)
        for patch in (dict(peer_share=True),dict(external_root=dict(hop_bound=True,adjudicator='test')),
                      dict(envelope_thresholds=dict(m_veto=.2,m_allow=.2))):
            with self.subTest(patch=patch),self.assertRaises(ValidationError):self.validate(dict(p,**patch))

    def test_core_context_requires_complete_installed_declaration(self):
        import rfc8785
        from kinetic_trust_library.v3.core_projection import NativeCoreContext
        op=dict(subject='urn:s',actor='urn:a',audience='urn:z',operation='urn:op',resource='urn:resource:test',parameters={},request_id='1',replay_domain='urn:replay')
        p=fixture();NativeCoreContext(rfc8785.dumps(p),rfc8785.dumps(op),10,'sha256')
        del p['boundary']
        with self.assertRaises(ValidationError):NativeCoreContext(rfc8785.dumps(p),rfc8785.dumps(op),10,'sha256')

    def test_invalid_environment_installation_precedes_source(self):
        import rfc8785
        from kinetic_trust_library.v3.installed_environment import InstalledEnvironmentVerifier
        p=fixture();del p['normalization']['world.security.anomaly_score']
        class Source:
            def verify(self,*args,**kwargs):raise AssertionError('invalid declaration reached Source')
        with self.assertRaisesRegex(ValidationError,'normalization'):
            InstalledEnvironmentVerifier(rfc8785.dumps(p),Source(),'sha256')
