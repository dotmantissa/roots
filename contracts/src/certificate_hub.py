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
