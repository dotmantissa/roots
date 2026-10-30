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
