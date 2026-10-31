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
