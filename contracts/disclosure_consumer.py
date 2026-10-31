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

class ProviderDisclosureConsumer(gl.Contract):
    owner: Address
    hub: Address
    configurations: TreeMap[str, str]
    receipts: TreeMap[str, str]
    acknowledgements: TreeMap[str, str]
    generations: TreeMap[str, u32]
    actions: TreeMap[str, str]
    action_ids: DynArray[str]
    count: u32
    pending_owner: str
    operation_count: u32
    relevance_approvals: TreeMap[str, str]
    configuration_operations: TreeMap[str, str]

    def __init__(self, hub: str, owner: str):
        self.hub = Address(hub)
        self.owner = Address(owner)
        self.count = u32(0)
        self.pending_owner = ""
        self.operation_count = u32(0)

    def _remember(self, operation_id, binding):
        require(int(self.operation_count) < 16384, "Consumer operation capacity reached")
        self.acknowledgements[operation_id] = binding
        self.operation_count = u32(int(self.operation_count) + 1)

    @gl.public.write
    def nominate_owner(self, principal: str) -> None:
        require(gl.message.sender_address == self.owner, "Consumer owner required")
        require(Address(principal) != Address("0x" + "0" * 40), "Nonzero owner required")
        self.pending_owner = str(Address(principal))

    @gl.public.write
    def accept_owner(self) -> None:
        require(self.pending_owner and gl.message.sender_address == Address(self.pending_owner), "Nominated owner required")
        self.owner = Address(self.pending_owner)
        self.pending_owner = ""

    @gl.public.view
    def get_authority(self) -> dict:
        return {"owner":str(self.owner), "pending_owner":self.pending_owner, "hub":str(self.hub), "admission_scope":"DOCUMENT_ANCESTRY", "relevance_responsibility":"CONSUMER_OWNER"}

    @gl.public.write
    def configure(self, operation_id: str, configuration_json: str, relevance_approved: bool) -> None:
        text(operation_id)
        require(gl.message.sender_address == self.owner, "Consumer owner required")
        require(relevance_approved is True, "Owner must review exact claim and source relevance")
        config = json.loads(configuration_json)
        exact_fields(config, CONFIG_FIELDS)
        # An exact request, subject and intended consequence are locked by this owner.
        envelope(canon(dict(config, owner=str(self.owner), parties=[])))
        require(config["consumer"] == str(gl.message.contract_address), "Consumer address mismatch")
        key = config["request_id"]
        binding = digest(config)
        operation_key = canon(["configuration", operation_id])
        if operation_key in self.acknowledgements:
            require(self.acknowledgements[operation_key] == binding, "Conflicting configuration reuse")
            require(self.configurations[key] == canon(config), "Configuration superseded")
            # Re-emit identical subscription after a failed finalized child.
            gl.get_contract_at(self.hub).emit(on="finalized").subscribe(operation_id, str(gl.message.contract_address), key, binding)
            return
        if key in self.configurations:
            old = json.loads(self.configurations[key])
            if config["generation"] == old["generation"]:
                require(config == old, "Conflicting same-generation configuration")
                # Use the original operation to keep recovery storage bounded.
                require(False, "Reuse the original configuration operation")
            require(config["generation"] > old["generation"], "Configuration generation must increase")
            for name in ["policy_id", "policy_revision", "subject_id", "subject_digest", "subject_text", "consequence_digest", "consequence_text", "admission_scope", "consumer"]:
                require(old[name] == config[name], "Locked consumer binding changed")
        authoritative = gl.get_contract_at(self.hub).view().get_batch(key)
        require(config == configuration_value(authoritative), "Configuration differs from docket")
        require(len(self.configurations) < 1024 or key in self.configurations, "Consumer configuration capacity reached")
        self.configurations[key] = canon(config)
        self.configuration_operations[key] = operation_id
        self.relevance_approvals[key] = binding
        self._remember(operation_key, binding)
        # Configuration changes freeze the prior receipt immediately, before subscription finality.
        gl.get_contract_at(self.hub).emit(on="finalized").subscribe(operation_id, str(gl.message.contract_address), key, binding)

    @gl.public.write
    def receive_certificate(self, payload_json: str) -> None:
        require(gl.message.sender_address == self.hub, "Authenticated finalized hub message required")
        payload = json.loads(payload_json)
        key = payload["request_id"]
        require(key in self.configurations, "Consumer configuration missing")
        config = json.loads(self.configurations[key])
        require(payload["configuration_digest"] == digest(config), "Certificate configuration mismatch")
        for name in config:
            require(payload.get(name) == config[name], "Certificate binding mismatch")
        require(payload["status"] in ["FINALIZED", "UNRESOLVED"], "Finalized boundary required")
        require(gl.get_contract_at(self.hub).view().is_active(payload["certificate_id"]), "Stale finalized delivery")
        require(maximum_subset(payload["manifest"], payload["pairs"]) == payload["selected_subset"], "Mutated certified subset")
        stored = gl.get_contract_at(self.hub).view().get_certificate(payload["certificate_id"])
        require(all(payload.get(k) == v for k,v in stored.items()), "Certificate differs from authoritative hub record")
        generation = payload["generation"]
        last = int(self.generations[key]) if key in self.generations else 0
        require(generation >= last, "Reordered stale callback")
        op = payload["operation_id"]
        binding = digest(payload)
        acknowledgement_key = canon(["delivery", op])
        if acknowledgement_key in self.acknowledgements:
            require(self.acknowledgements[acknowledgement_key] == binding, "Conflicting callback reuse")
        else:
            self.receipts[key] = canon(payload)
            self.generations[key] = u32(generation)
            self._remember(acknowledgement_key, binding)
        gl.get_contract_at(self.hub).emit(on="finalized").acknowledge_revision(op, payload["certificate_id"], generation)

    @gl.public.write
    def admit_disclosure(self, operation_id: str, request_id: str, subject_digest: str, consequence_digest: str) -> None:
        text(operation_id)
        require(gl.message.sender_address == self.owner, "Consumer owner required")
        binding = digest([request_id, subject_digest, consequence_digest])
        if operation_id in self.actions:
            require(json.loads(self.actions[operation_id])["binding"] == binding, "Conflicting action reuse")
            return
        require(request_id in self.receipts and request_id in self.configurations, "Finalized certificate required")
        receipt = json.loads(self.receipts[request_id])
        config = json.loads(self.configurations[request_id])
        require(request_id in self.relevance_approvals and self.relevance_approvals[request_id] == digest(config), "Owner relevance review required")
        require(receipt["configuration_digest"] == digest(config), "New revision awaiting acknowledgement")
        require(receipt["subject_digest"] == subject_digest and receipt["consequence_digest"] == consequence_digest, "Exact action binding required")
        deadline_ok(receipt["deadline"])
        require(gl.get_contract_at(self.hub).view().is_active(receipt["certificate_id"]), "Certificate stale or quarantined")
        require(receipt["status"] == "FINALIZED" and not receipt["unresolved"] and len(receipt["selected_subset"]) >= 3, "Three certified independent origins required")
        require(maximum_subset(receipt["manifest"], receipt["pairs"]) == receipt["selected_subset"], "Mutated certified subset")
        require(len(self.action_ids) < 4096, "Action capacity reached")
        self.actions[operation_id] = canon({"operation_id":operation_id,"request_id":request_id,"certificate_id":receipt["certificate_id"],"generation":receipt["generation"],"binding":binding,"status":"ADMITTED","consumer_kind":"provider_disclosure"})
        self.action_ids.append(operation_id)
        self.count = u32(int(self.count) + 1)

    @gl.public.view
    def get_state(self, request_id: str) -> dict:
        return {"owner":str(self.owner), "configuration_operation":self.configuration_operations[request_id] if request_id in self.configuration_operations else "", "subscription_digest":gl.get_contract_at(self.hub).view().get_subscription(str(gl.message.contract_address), request_id), "consumer_kind":"provider_disclosure", "configuration":json.loads(self.configurations[request_id]) if request_id in self.configurations else None, "receipt":json.loads(self.receipts[request_id]) if request_id in self.receipts else None, "last_generation":int(self.generations[request_id]) if request_id in self.generations else 0}

    @gl.public.view
    def get_action(self, operation_id: str) -> dict:
        require(operation_id in self.actions, "Unknown action")
        return json.loads(self.actions[operation_id])
