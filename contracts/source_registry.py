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

class SourceRegistry(gl.Contract):
    owner: Address
    publishers: TreeMap[str, str]
    policies: TreeMap[str, str]
    operations: TreeMap[str, str]
    publisher_ids: DynArray[str]
    policy_ids: DynArray[str]
    count: u32
    operation_count: u32
    pending_principals: TreeMap[str, str]
    pending_owner: str
    publisher_operations: TreeMap[str, u32]

    def __init__(self):
        self.owner = gl.message.sender_address
        self.count = u32(0)
        self.operation_count = u32(0)
        self.pending_owner = ""

    @gl.public.write
    def register_publisher(self, operation_id: str, publisher_id: str, principal: str, evidence_json: str) -> None:
        text(operation_id)
        text(publisher_id)
        p = Address(principal)
        require(gl.message.sender_address == self.owner, "Registry owner enrollment required")
        require(p != Address("0x" + "0" * 40), "Nonzero principal required")
        evidence = record(json.loads(evidence_json))
        binding = digest([publisher_id, principal, evidence])
        if operation_id in self.operations:
            require(self.operations[operation_id] == binding, "Conflicting operation reuse")
            return
        require(publisher_id not in self.publishers, "Publisher already registered")
        require(len(self.publisher_ids) < 4096, "Publisher capacity reached")
        value = {"publisher_id":publisher_id, "principal":str(p), "revision":1, "status":"ACTIVE", "evidence":evidence}
        self.publishers[publisher_id] = canon(value)
        self.publisher_ids.append(publisher_id)
        self._publisher_operation(publisher_id)
        self._remember(operation_id, binding)
        self.count = u32(int(self.count) + 1)

    @gl.public.write
    def correct_affiliation(self, operation_id: str, publisher_id: str, evidence_json: str, quarantine: bool) -> None:
        text(operation_id)
        value = self.get_publisher(publisher_id)
        require(gl.message.sender_address == Address(value["principal"]), "Publisher principal required")
        evidence = record(json.loads(evidence_json))
        binding = digest([publisher_id, evidence, quarantine])
        if operation_id in self.operations:
            require(self.operations[operation_id] == binding, "Conflicting operation reuse")
            return
        value["revision"] += 1
        require(value["revision"] <= 4294967295, "Revision exhausted")
        require(evidence["revision"] == value["revision"], "Evidence revision mismatch")
        value["evidence"] = evidence
        value["status"] = "QUARANTINED" if quarantine else "ACTIVE"
        self.publishers[publisher_id] = canon(value)
        self._publisher_operation(publisher_id)
        self._remember(operation_id, binding)

    @gl.public.write
    def register_source_policy(self, operation_id: str, policy_id: str, revision: int, policy_json: str) -> None:
        text(operation_id)
        text(policy_id)
        integer(revision, 1, 4294967295)
        require(gl.message.sender_address == self.owner, "Registry owner required")
        require(len(policy_json.encode()) <= 4096, "Policy too large")
        policy = json.loads(policy_json)
        require(isinstance(policy, dict) and set(policy) in [set(["min_origins", "max_sources", "unresolved_consequence"]), set(["min_origins", "max_sources", "unresolved_consequence", "name"])], "Unsupported policy fields")
        if "name" in policy:
            text(policy["name"])
        require(policy.get("min_origins") == 3 and policy.get("max_sources") == 6 and policy.get("unresolved_consequence") == "REFUSE_ADMISSION", "Unsupported policy")
        binding = digest([policy_id, revision, policy])
        if operation_id in self.operations:
            require(self.operations[operation_id] == binding, "Conflicting operation reuse")
            return
        key = policy_id + ":" + str(revision)
        require(key not in self.policies and len(self.policy_ids) < 4096, "Policy version exists or capacity reached")
        if revision > 1:
            require(policy_id + ":" + str(revision - 1) in self.policies, "Policy revision gap")
        policy.update({"policy_id":policy_id, "revision":revision, "owner":str(self.owner)})
        self.policies[key] = canon(policy)
        self.policy_ids.append(key)
        self._remember(operation_id, binding)

    def _publisher_operation(self, publisher_id):
        used = int(self.publisher_operations[publisher_id]) if publisher_id in self.publisher_operations else 0
        require(used < 128, "Publisher operation allocation exhausted; steward replacement required")
        self.publisher_operations[publisher_id] = u32(used + 1)

    def _remember(self, operation_id, binding):
        require(int(self.operation_count) < 1048576, "Operation capacity reached")
        self.operations[operation_id] = binding
        self.operation_count = u32(int(self.operation_count) + 1)

    @gl.public.write
    def nominate_owner(self, principal: str) -> None:
        require(gl.message.sender_address == self.owner, "Registry owner required")
        self.pending_owner = str(Address(principal))

    @gl.public.write
    def accept_owner(self) -> None:
        require(self.pending_owner and gl.message.sender_address == Address(self.pending_owner), "Nominated owner required")
        self.owner = Address(self.pending_owner)
        self.pending_owner = ""

    @gl.public.write
    def nominate_principal(self, publisher_id: str, principal: str) -> None:
        value = self.get_publisher(publisher_id)
        require(gl.message.sender_address == Address(value["principal"]), "Publisher principal required")
        self.pending_principals[publisher_id] = str(Address(principal))

    @gl.public.write
    def accept_principal(self, publisher_id: str) -> None:
        require(publisher_id in self.pending_principals and gl.message.sender_address == Address(self.pending_principals[publisher_id]), "Nominated principal required")
        value = self.get_publisher(publisher_id)
        self._rotate(value, self.pending_principals[publisher_id])
        del self.pending_principals[publisher_id]

    @gl.public.write
    def recover_principal(self, operation_id: str, publisher_id: str, principal: str, evidence_json: str) -> None:
        text(operation_id)
        require(gl.message.sender_address == self.owner, "Registry owner recovery required")
        value = self.get_publisher(publisher_id)
        evidence = record(json.loads(evidence_json))
        principal = str(Address(principal))
        binding = digest(["recover_principal", publisher_id, principal, evidence])
        if operation_id in self.operations:
            require(self.operations[operation_id] == binding, "Conflicting operation reuse")
            return
        require(evidence["revision"] == value["revision"] + 1, "Recovery evidence revision mismatch")
        self._rotate(value, principal)
        value = self.get_publisher(publisher_id)
        value["evidence"] = evidence
        value["status"] = "ACTIVE"
        self.publishers[publisher_id] = canon(value)
        if publisher_id in self.pending_principals:
            del self.pending_principals[publisher_id]
        self._publisher_operation(publisher_id)
        self._remember(operation_id, binding)

    def _rotate(self, value, principal):
        require(Address(principal) != Address("0x" + "0" * 40), "Nonzero principal required")
        require(value["revision"] < 4294967295, "Revision exhausted")
        value["principal"] = principal
        value["revision"] += 1
        value["evidence"]["revision"] = value["revision"]
        self.publishers[value["publisher_id"]] = canon(value)

    @gl.public.view
    def get_authority(self) -> dict:
        return {"owner":str(self.owner), "pending_owner":self.pending_owner, "enrollment":"REGISTRY_OWNER_VETTED", "operation_count":int(self.operation_count), "operation_limit":1048576, "publisher_operation_limit":128}

    @gl.public.view
    def get_publisher(self, publisher_id: str) -> dict:
        require(publisher_id in self.publishers, "Unknown publisher")
        return json.loads(self.publishers[publisher_id])

    @gl.public.view
    def get_policy(self, policy_id: str, revision: int) -> dict:
        key = policy_id + ":" + str(revision)
        require(key in self.policies, "Unknown policy")
        return json.loads(self.policies[key])

    @gl.public.view
    def list_records(self, kind: str, offset: int, limit: int) -> dict:
        integer(offset, 0, 4096)
        integer(limit, 1, 50)
        require(kind in ["publishers", "policies"], "Unknown record kind")
        order = self.publisher_ids if kind == "publishers" else self.policy_ids
        table = self.publishers if kind == "publishers" else self.policies
        return {"total":len(order), "items":[json.loads(table[order[i]]) for i in range(offset, min(offset + limit, len(order)))]}
