class CONSUMER_NAME(gl.Contract):
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
        if operation_id in self.acknowledgements:
            require(self.acknowledgements[operation_id] == binding, "Conflicting configuration reuse")
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
        self.relevance_approvals[key] = binding
        self._remember(operation_id, binding)
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
        if op in self.acknowledgements:
            require(self.acknowledgements[op] == binding, "Conflicting callback reuse")
        else:
            self.receipts[key] = canon(payload)
            self.generations[key] = u32(generation)
            self._remember(op, binding)
        gl.get_contract_at(self.hub).emit(on="finalized").acknowledge_revision(op, payload["certificate_id"], generation)

    @gl.public.write
    def ACTION_NAME(self, operation_id: str, request_id: str, subject_digest: str, consequence_digest: str) -> None:
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
        self.actions[operation_id] = canon({"operation_id":operation_id,"request_id":request_id,"certificate_id":receipt["certificate_id"],"generation":receipt["generation"],"binding":binding,"status":"ADMITTED","consumer_kind":"CONSUMER_KIND"})
        self.action_ids.append(operation_id)
        self.count = u32(int(self.count) + 1)

    @gl.public.view
    def get_state(self, request_id: str) -> dict:
        return {"owner":str(self.owner), "subscription_digest":gl.get_contract_at(self.hub).view().get_subscription(str(gl.message.contract_address), request_id), "consumer_kind":"CONSUMER_KIND", "configuration":json.loads(self.configurations[request_id]) if request_id in self.configurations else None, "receipt":json.loads(self.receipts[request_id]) if request_id in self.receipts else None, "last_generation":int(self.generations[request_id]) if request_id in self.generations else 0}

    @gl.public.view
    def get_action(self, operation_id: str) -> dict:
        require(operation_id in self.actions, "Unknown action")
        return json.loads(self.actions[operation_id])
