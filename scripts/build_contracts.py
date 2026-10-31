"""Vendor complete single file contracts for the pinned GenVM runner."""
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
HEADER = '# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }\n'
common = (ROOT / 'contracts/src/common.py').read_text()
for name in ['source_registry', 'relation_docket', 'certificate_hub']:
    (ROOT / f'contracts/{name}.py').write_text(HEADER + common + '\n' + (ROOT / f'contracts/src/{name}.py').read_text())
consumer = (ROOT / 'contracts/src/consumer.py').read_text()
for filename, name, action, kind in [('incident_consumer','IncidentEvidenceConsumer','admit_incident','incident_evidence'),('disclosure_consumer','ProviderDisclosureConsumer','admit_disclosure','provider_disclosure')]:
    code = consumer.replace('CONSUMER_NAME',name).replace('ACTION_NAME',action).replace('CONSUMER_KIND',kind)
    (ROOT / f'contracts/{filename}.py').write_text(HEADER + common + '\n' + code)

# Probes use the exact production adjudication and validator logic.
probe = ROOT / 'tests/integration/validator_probe.py'
existing = probe.read_text()
probe_class = existing[existing.index('class ValidatorProbe'): ]
probe_class = probe_class.replace('independent_validator(proposal, honest)', 'independent_validator(proposal, honest, records, lambda value:verify_pair_proposal(records, value))')
probe_class = probe_class.replace('        records = json.loads(records_json)', '        require(gl.message.sender_address == self.owner, "Probe owner required")\n        text(operation_id)\n        records = json.loads(records_json)') if 'Probe owner required' not in probe_class else probe_class
probe_class = probe_class.replace('    accepted: TreeMap[str, str]', '    accepted: TreeMap[str, str]\n    owner: Address') if '    owner: Address' not in probe_class else probe_class
probe_class = probe_class.replace('        pass', '        self.owner = gl.message.sender_address')
probe_class = probe_class.replace('        self.accepted[operation_id] = canon(value)', '        require(len(self.accepted) < 128 or operation_id in self.accepted, "Probe capacity reached")\n        self.accepted[operation_id] = canon(value)') if 'Probe capacity reached' not in probe_class else probe_class
pair_functions = (ROOT / 'contracts/src/relation_docket.py').read_text().split('class RelationDocket')[0]
probe.write_text(HEADER + common + '\n' + pair_functions + '\n' + probe_class)
