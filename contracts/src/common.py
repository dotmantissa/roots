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
