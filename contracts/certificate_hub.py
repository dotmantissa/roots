# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import hashlib
import json
import re
from datetime import datetime

MAX_RECORD_BYTES = 49152
MAX_PACKET_BYTES = 16384
MAX_REQUEST_BYTES = 24576
RULES = ["R_SHARED_CONTROL", "R_SYNDICATION", "R_COPIED_REPORTING", "R_INDEPENDENT_PROCESS", "R_AMBIGUOUS", "R_UNAVAILABLE"]
CONFIG_FIELDS = ["request_id", "policy_id", "policy_revision", "subject_id", "subject_digest", "subject_text", "manifest_digest", "consumer", "consequence_digest", "consequence_text", "admission_scope", "generation", "deadline"]
REQUEST_FIELDS = CONFIG_FIELDS + ["owner", "parties"]
MAX_GENERATIONS = 8
MAX_OPERATIONS = 524288
LABELS = ["SHARED_ORIGIN", "INDEPENDENT", "UNKNOWN"]

def canon(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def digest(value):
    return hashlib.sha256(canon(value).encode()).hexdigest()

def require(condition, message):
    if not condition:
        raise gl.vm.UserError("[EXPECTED] " + message)

def text(value, limit=128):
    require(isinstance(value, str) and 0 < len(value.encode()) <= limit, "Invalid text size")
    return value

def hash_value(value):
    require(isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value), "Invalid digest")
    return value

def integer(value, minimum, maximum):
    require(type(value) is int and minimum <= value <= maximum, "Invalid integer")
    return value

def now():
    # The documented transaction datetime, not a local wall clock.
    return datetime.fromisoformat(gl.message_raw["datetime"].replace("Z", "+00:00"))

def deadline_ok(deadline):
    require(isinstance(deadline, str) and len(deadline) <= 40, "Invalid deadline")
    require(re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:[0-9]{2})", deadline) is not None, "ISO timestamp with timezone required")
    try:
        expiry = datetime.fromisoformat(deadline.replace("Z", "+00:00"))
        require(expiry.tzinfo is not None and now() <= expiry, "Deadline expired")
    except ValueError:
        require(False, "Invalid deadline")

def exact_fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names), "Unexpected or missing fields")

def public_url(value):
    url = text(value, 2048)
    match = re.fullmatch(r"https://([A-Za-z0-9.-]+)(?::443)?(?:[/?][^\s\\#]*)?", url)
    require(match is not None, "Public HTTPS URL with default port required")
    host = match.group(1).lower()
    labels = host.split(".")
    require(len(labels) >= 2 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is not None for label in labels), "Public DNS hostname required")
    require(re.fullmatch(r"[a-z]{2,63}", labels[-1]) is not None and labels[-1] not in ["local", "localhost", "internal", "invalid", "test", "onion"], "Public DNS hostname required")
    return url

def configuration_value(value):
    return {k:value[k] for k in CONFIG_FIELDS}

def batch_commitment(value):
    # v2: the entire exact request, including parties, generation and preimages.
    return digest({"version":2, "request":{k:value[k] for k in REQUEST_FIELDS}})

def envelope(raw):
    require(isinstance(raw, str) and len(raw.encode()) <= MAX_REQUEST_BYTES, "Request size exceeded")
    value = json.loads(raw)
    exact_fields(value, REQUEST_FIELDS)
    for name in ["request_id", "owner", "policy_id", "subject_id", "consumer"]:
        text(value.get(name))
    for name in ["subject_digest", "manifest_digest", "consequence_digest"]:
        hash_value(value.get(name))
    for name, commitment, limit in [("subject_text", "subject_digest", 4000), ("consequence_text", "consequence_digest", 1000)]:
        text(value.get(name), limit)
        require(hashlib.sha256(value[name].encode()).hexdigest() == value[commitment], "Preimage digest mismatch")
    require(value.get("admission_scope") == "DOCUMENT_ANCESTRY", "Document ancestry admission scope required")
    integer(value.get("policy_revision"), 1, 4294967295)
    integer(value.get("generation"), 1, 4294967295)
    require(isinstance(value.get("parties"), list) and len(value["parties"]) <= 6, "Invalid parties")
    for party in value["parties"]:
        Address(party)
    Address(value["consumer"])
    Address(value["owner"])
    deadline_ok(value.get("deadline"))
    return value

def record(value):
    exact_fields(value, ["record_id", "authority", "channel", "scope", "url", "capture_url", "byte_hash", "revision", "byte_length", "spans"])
    text(value.get("record_id"))
    for name in ["authority", "channel", "scope"]:
        text(value.get(name), 256)
    for name in ["url", "capture_url"]:
        public_url(value.get(name))
    hash_value(value.get("byte_hash"))
    integer(value.get("revision"), 1, 4294967295)
    integer(value.get("byte_length"), 1, MAX_RECORD_BYTES)
    spans = value.get("spans")
    require(isinstance(spans, list) and 1 <= len(spans) <= 8, "Witness spans required")
    seen = []
    for span in spans:
        exact_fields(span, ["span_id", "start", "end", "quote_hash"])
        text(span.get("span_id"))
        require(span["span_id"] not in seen, "Duplicate span")
        seen.append(span["span_id"])
        integer(span.get("start"), 0, value["byte_length"] - 1)
        integer(span.get("end"), span["start"] + 1, value["byte_length"])
        hash_value(span.get("quote_hash"))
    return value

def maximum_subset(sources, pairs):
    n = len(sources)
    require(2 <= n <= 6 and len(pairs) == n * (n - 1) // 2, "Incomplete matrix")
    best = []
    for mask in range(1 << n):
        candidate = [i for i in range(n) if mask & (1 << i)]
        valid = True
        for ai in range(len(candidate)):
            for bi in range(ai + 1, len(candidate)):
                a, b = candidate[ai], candidate[bi]
                p = pairs[str(a) + ":" + str(b)]
                if sources[a]["publisher_id"] == sources[b]["publisher_id"] or p["relation"] != "INDEPENDENT" or not p["witnesses"]:
                    valid = False
        if valid and len(candidate) > len(best):
            best = candidate
    return best

def canonical_decision(result, packet):
    if not isinstance(result, dict):
        raise gl.vm.UserError("[LLM_ERROR] Result must be an object")
    relation = result.get("relation")
    rule = result.get("rule_id")
    if relation not in LABELS or rule not in RULES:
        raise gl.vm.UserError("[LLM_ERROR] Invalid relation or rule")
    allowed = {"SHARED_ORIGIN":RULES[:3], "INDEPENDENT":[RULES[3]], "UNKNOWN":RULES[4:]}
    if rule not in allowed[relation]:
        raise gl.vm.UserError("[LLM_ERROR] Controlling exception omitted")
    candidates = {}
    for item in packet:
        for span in item["record"]["spans"]:
            key = canon([item["record"]["record_id"], span["span_id"]])
            require(key not in candidates, "Duplicate witness locator")
            candidates[key] = {"source_hash":item["record"]["byte_hash"], "span_id":span["span_id"], "record_id":item["record"]["record_id"], "start":span["start"], "end":span["end"], "quote_hash":span["quote_hash"]}
    keys = result.get("witness_ids")
    if isinstance(keys, list):
        keys = [canon(k) if isinstance(k, list) and len(k) == 2 and all(isinstance(part, str) for part in k) else k for k in keys]
    if not isinstance(keys, list) or len(keys) > 32 or any(not isinstance(k, str) for k in keys) or len(set(keys)) != len(keys) or any(k not in candidates for k in keys):
        raise gl.vm.UserError("[LLM_ERROR] Forged witness locator")
    if relation != "UNKNOWN" and (not keys or any(item["record"]["record_id"] not in [candidates[k]["record_id"] for k in keys] for item in packet)):
        raise gl.vm.UserError("[LLM_ERROR] Incomplete evidence coverage")
    return {"relation":relation, "rule_id":rule, "scope":"editorial_or_measurement_origin", "witnesses":[candidates[k] for k in sorted(keys)], "coverage":relation != "UNKNOWN", "unresolved":relation == "UNKNOWN"}

def valid_decision_witnesses(value, records):
    try:
        exact_fields(value, ["relation", "rule_id", "scope", "witnesses", "coverage", "unresolved"])
        ids = [canon([w["record_id"], w["span_id"]]) for w in value["witnesses"]]
        rebuilt = canonical_decision({"relation":value["relation"], "rule_id":value["rule_id"], "witness_ids":ids}, [{"record":r} for r in records])
        return rebuilt == value
    except Exception:
        return False

def independent_validator(proposal, derive, records=None, verify=None):
    if isinstance(proposal, gl.vm.VMError):
        return False
    if isinstance(proposal, gl.vm.UserError):
        try:
            derive()
        except gl.vm.UserError as error:
            return proposal.message.startswith("[EXPECTED]") and error.message == proposal.message
        except Exception:
            return False
        return False
    if not isinstance(proposal, gl.vm.Return):
        return False
    try:
        independent = derive()
        leader = proposal.calldata
        if records is None:
            return leader == independent
        if not valid_decision_witnesses(leader, records):
            return False
        # Citation and overlapping shared-origin rule choices may differ. Each
        # validator still derives the relationship and verifies the leader's
        # exact controlling rule and cited evidence independently.
        if any(leader[k] != independent[k] for k in ["relation", "scope", "coverage", "unresolved"]):
            return False
        if leader["relation"] == "UNKNOWN":
            return leader["rule_id"] == independent["rule_id"]
        return verify is not None and verify(leader)

    except Exception:
        return False

class CertificateHub(gl.Contract):
    owner: Address
    docket: Address
    certificates: TreeMap[str, str]
    subscriptions: TreeMap[str, str]
    deliveries: TreeMap[str, str]
    acknowledgements: TreeMap[str, str]
    certificate_ids: DynArray[str]
    subscription_ids: DynArray[str]
    count: u32
    delivery_ids: TreeMap[str, str]

    def __init__(self, docket: str):
        self.owner = gl.message.sender_address
        self.docket = Address(docket)
        self.count = u32(0)

    @gl.public.write
    def subscribe(self, operation_id: str, consumer: str, request_id: str, configuration_digest: str) -> None:
        text(operation_id)
        text(request_id)
        hash_value(configuration_digest)
        require(gl.message.sender_address == Address(consumer), "Consumer contract required")
        batch = gl.get_contract_at(self.docket).view().get_batch(request_id)
        require(batch["consumer"] == consumer, "Consumer binding mismatch")
        expected = digest(configuration_value(batch))
        require(expected == configuration_digest, "Subscription configuration mismatch")
        binding = digest([consumer,request_id,configuration_digest])
        operation_key = canon(["operation", operation_id])
        if operation_key in self.subscriptions:
            require(self.subscriptions[operation_key] == binding, "Conflicting operation reuse")
            return
        require(len(self.subscription_ids) < 8192, "Subscription capacity reached")
        # One retained subscription operation per configuration commitment.
        config_key = canon(["configuration", configuration_digest])
        if config_key in self.subscriptions:
            require(self.subscriptions[config_key] == binding, "Conflicting subscription binding")
            return
        self.subscriptions[config_key] = binding
        self.subscriptions[operation_key] = binding
        self.subscriptions[canon(["request", consumer, request_id])] = configuration_digest
        self.subscription_ids.append(operation_id)

    @gl.public.write
    def publish_certificate(self, certificate_json: str) -> None:
        require(gl.message.sender_address == self.docket, "Finalized docket message required")
        value = json.loads(certificate_json)
        require(value["status"] == "SEALED", "Unsealed certificate")
        current = gl.get_contract_at(self.docket).view().get_batch(value["request_id"])
        require(current == value and gl.get_contract_at(self.docket).view().is_current(value["request_id"], value["generation"]), "Stale certificate")
        require(maximum_subset(value["manifest"], value["pairs"]) == value["selected_subset"], "Invalid certified subset")
        key = value["certificate_id"]
        value["status"] = "UNRESOLVED" if value["unresolved"] else "FINALIZED"
        value["superseded_by"] = ""
        if key in self.certificates:
            require(self.certificates[key] == canon(value), "Conflicting certificate reuse")
            return
        require(len(self.certificate_ids) < 8192, "Certificate capacity reached")
        for prior in value["prior_certificates"]:
            if prior in self.certificates:
                previous = json.loads(self.certificates[prior])
                previous["status"] = "SUPERSEDED"
                previous["superseded_by"] = key
                self.certificates[prior] = canon(previous)
        self.certificates[key] = canon(value)
        self.certificate_ids.append(key)
        self.count = u32(int(self.count) + 1)

    @gl.public.write
    def deliver_certificate(self, operation_id: str, certificate_id: str, consumer: str) -> None:
        text(operation_id)
        cert = self.get_certificate(certificate_id)
        authority = gl.get_contract_at(Address(consumer)).view().get_authority()
        require(gl.message.sender_address == Address(cert["owner"]) or gl.message.sender_address == Address(authority["owner"]), "Request or consumer owner delivery required")
        require(cert["consumer"] == consumer, "Consumer mismatch")
        require(self.is_active(certificate_id), "Certificate stale or quarantined")
        key = canon(["request", consumer, cert["request_id"]])
        require(key in self.subscriptions, "Consumer has not subscribed")
        config = digest(configuration_value(cert))
        require(self.subscriptions[key] == config, "Consumer configuration stale")
        binding = digest([certificate_id, consumer, config])
        if certificate_id in self.delivery_ids:
            require(self.delivery_ids[certificate_id] == operation_id, "Reuse the certificate delivery operation")
        else:
            require(len(self.delivery_ids) < 8192, "Delivery capacity reached")
            self.delivery_ids[certificate_id] = operation_id
        if operation_id in self.deliveries:
            require(self.deliveries[operation_id] == binding, "Conflicting delivery reuse")
            # An exact duplicate may retry a failed callback safely.
        self.deliveries[operation_id] = binding
        payload = dict(cert)
        payload["operation_id"] = operation_id
        payload["configuration_digest"] = config
        gl.get_contract_at(Address(consumer)).emit(on="finalized").receive_certificate(canon(payload))

    @gl.public.write
    def acknowledge_revision(self, operation_id: str, certificate_id: str, generation: int) -> None:
        cert = self.get_certificate(certificate_id)
        require(gl.message.sender_address == Address(cert["consumer"]), "Consumer acknowledgement required")
        require(generation == cert["generation"] and operation_id in self.deliveries, "Unknown delivery generation")
        require(self.deliveries[operation_id] == digest([certificate_id, cert["consumer"], digest(configuration_value(cert))]), "Delivery acknowledgement binding mismatch")
        value = canon({"operation_id":operation_id,"certificate_id":certificate_id,"consumer":cert["consumer"],"generation":generation})
        if operation_id in self.acknowledgements:
            require(self.acknowledgements[operation_id] == value, "Conflicting acknowledgement")
            return
        self.acknowledgements[operation_id] = value

    @gl.public.view
    def get_delivery(self, operation_id: str) -> dict:
        return {"operation_id":operation_id, "broadcast":operation_id in self.deliveries, "acknowledgement":json.loads(self.acknowledgements[operation_id]) if operation_id in self.acknowledgements else None}

    @gl.public.view
    def is_active(self, certificate_id: str) -> bool:
        if certificate_id not in self.certificates:
            return False
        cert = json.loads(self.certificates[certificate_id])
        return now() <= datetime.fromisoformat(cert["deadline"].replace("Z", "+00:00")) and cert["status"] in ["FINALIZED", "UNRESOLVED"] and gl.get_contract_at(self.docket).view().is_current(cert["request_id"], cert["generation"])

    @gl.public.view
    def get_certificate(self, certificate_id: str) -> dict:
        require(certificate_id in self.certificates, "Unknown certificate")
        value = json.loads(self.certificates[certificate_id])
        if value["status"] != "SUPERSEDED" and now() > datetime.fromisoformat(value["deadline"].replace("Z", "+00:00")):
            value["status"] = "TIMEOUT"
        elif value["status"] != "SUPERSEDED" and not self.is_active(certificate_id):
            value["status"] = "QUARANTINED"
        return value

    @gl.public.view
    def get_dependencies(self) -> dict:
        return {"owner":str(self.owner), "docket":str(self.docket)}

    @gl.public.view
    def get_batch(self, request_id: str) -> dict:
        return gl.get_contract_at(self.docket).view().get_batch(request_id)

    @gl.public.view
    def has_certificate(self, certificate_id: str) -> bool:
        return certificate_id in self.certificates

    @gl.public.view
    def get_subscription(self, consumer: str, request_id: str) -> str:
        key = canon(["request", consumer, request_id])
        return self.subscriptions[key] if key in self.subscriptions else ""

    @gl.public.view
    def get_delivery_operation(self, certificate_id: str) -> str:
        return self.delivery_ids[certificate_id] if certificate_id in self.delivery_ids else ""

    @gl.public.view
    def list_certificates(self, offset: int, limit: int) -> dict:
        integer(offset, 0, 8192)
        integer(limit, 1, 50)
        return {"total":len(self.certificate_ids), "items":[self.get_certificate(self.certificate_ids[i]) for i in range(offset, min(offset + limit, len(self.certificate_ids)))]}
