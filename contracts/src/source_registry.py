class SourceRegistry(gl.Contract):
    owner: Address
    publishers: TreeMap[str, str]
    policies: TreeMap[str, str]
    operations: TreeMap[str, str]
    publisher_ids: DynArray[str]
    policy_ids: DynArray[str]
    count: u32

    def __init__(self):
        self.owner = gl.message.sender_address
        self.count = u32(0)

    @gl.public.write
    def register_publisher(self, operation_id: str, publisher_id: str, principal: str, evidence_json: str) -> None:
        text(operation_id)
        text(publisher_id)
        p = Address(principal)
        require(gl.message.sender_address == self.owner or gl.message.sender_address == p, "Publisher principal or registry owner required")
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
        self.operations[operation_id] = binding
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
        self.operations[operation_id] = binding

    @gl.public.write
    def register_source_policy(self, operation_id: str, policy_id: str, revision: int, policy_json: str) -> None:
        text(operation_id)
        text(policy_id)
        integer(revision, 1, 4294967295)
        require(gl.message.sender_address == self.owner, "Registry owner required")
        require(len(policy_json.encode()) <= 4096, "Policy too large")
        policy = json.loads(policy_json)
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
        self.operations[operation_id] = binding

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
