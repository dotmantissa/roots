# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import hashlib
import json
from datetime import datetime

MAX_RECORD_BYTES = 49152
MAX_PACKET_BYTES = 16384
MAX_REQUEST_BYTES = 24576
RULES = ["R_SHARED_CONTROL", "R_SYNDICATION", "R_COPIED_REPORTING", "R_INDEPENDENT_PROCESS", "R_AMBIGUOUS", "R_UNAVAILABLE"]
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
    try:
        expiry = datetime.fromisoformat(deadline.replace("Z", "+00:00"))
        require(expiry.tzinfo is not None and now() <= expiry, "Deadline expired")
    except ValueError:
        require(False, "Invalid deadline")

def envelope(raw):
    require(isinstance(raw, str) and len(raw.encode()) <= MAX_REQUEST_BYTES, "Request size exceeded")
    value = json.loads(raw)
    require(isinstance(value, dict), "Expected request object")
    for name in ["request_id", "owner", "policy_id", "subject_id", "consumer"]:
        text(value.get(name))
    for name in ["subject_digest", "manifest_digest", "consequence_digest"]:
        hash_value(value.get(name))
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
    require(isinstance(value, dict), "Invalid record")
    for name in ["record_id", "authority", "channel", "scope"]:
        text(value.get(name), 256)
    for name in ["url", "capture_url"]:
        url = text(value.get(name), 2048)
        require(url.startswith("https://") and "@" not in url and "#" not in url, "HTTPS record required")
    hash_value(value.get("byte_hash"))
    integer(value.get("revision"), 1, 4294967295)
    integer(value.get("byte_length"), 1, MAX_RECORD_BYTES)
    spans = value.get("spans")
    require(isinstance(spans, list) and 1 <= len(spans) <= 8, "Witness spans required")
    seen = []
    for span in spans:
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
            key = item["record"]["record_id"] + ":" + span["span_id"]
            candidates[key] = {"source_hash":item["record"]["byte_hash"], "span_id":span["span_id"], "record_id":item["record"]["record_id"], "start":span["start"], "end":span["end"], "quote_hash":span["quote_hash"]}
    keys = result.get("witness_ids")
    if not isinstance(keys, list) or len(keys) > 32 or len(set(keys)) != len(keys) or any(k not in candidates for k in keys):
        raise gl.vm.UserError("[LLM_ERROR] Forged witness locator")
    if relation != "UNKNOWN" and (not keys or any(not any(k.startswith(item["record"]["record_id"] + ":") for k in keys) for item in packet)):
        raise gl.vm.UserError("[LLM_ERROR] Incomplete evidence coverage")
    return {"relation":relation, "rule_id":rule, "scope":"editorial_or_measurement_origin", "witnesses":[candidates[k] for k in sorted(keys)], "coverage":relation != "UNKNOWN", "unresolved":relation == "UNKNOWN"}

def independent_validator(proposal, derive):
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
        return proposal.calldata == independent
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
        expected = digest({k:batch[k] for k in ["request_id", "policy_id", "policy_revision", "subject_id", "subject_digest", "manifest_digest", "consumer", "consequence_digest", "generation", "deadline"]})
        require(expected == configuration_digest, "Subscription configuration mismatch")
        binding = digest([consumer,request_id,configuration_digest])
        if operation_id in self.subscriptions:
            require(self.subscriptions[operation_id] == binding, "Conflicting operation reuse")
            return
        require(len(self.subscription_ids) < 4096, "Subscription capacity reached")
        self.subscriptions[operation_id] = binding
        self.subscriptions[consumer + ":" + request_id] = configuration_digest
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
        require(cert["consumer"] == consumer, "Consumer mismatch")
        require(self.is_active(certificate_id), "Certificate stale or quarantined")
        key = consumer + ":" + cert["request_id"]
        require(key in self.subscriptions, "Consumer has not subscribed")
        config = digest({k:cert[k] for k in ["request_id", "policy_id", "policy_revision", "subject_id", "subject_digest", "manifest_digest", "consumer", "consequence_digest", "generation", "deadline"]})
        require(self.subscriptions[key] == config, "Consumer configuration stale")
        binding = digest([certificate_id, consumer, config])
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
        return cert["status"] in ["FINALIZED", "UNRESOLVED"] and gl.get_contract_at(self.docket).view().is_current(cert["request_id"], cert["generation"])

    @gl.public.view
    def get_certificate(self, certificate_id: str) -> dict:
        require(certificate_id in self.certificates, "Unknown certificate")
        value = json.loads(self.certificates[certificate_id])
        if value["status"] != "SUPERSEDED" and not self.is_active(certificate_id):
            value["status"] = "QUARANTINED"
        return value

    @gl.public.view
    def list_certificates(self, offset: int, limit: int) -> dict:
        integer(offset, 0, 8192)
        integer(limit, 1, 50)
        return {"total":len(self.certificate_ids), "items":[self.get_certificate(self.certificate_ids[i]) for i in range(offset, min(offset + limit, len(self.certificate_ids)))]}
