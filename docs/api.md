# API and contract reference

Schemas are executable Zod definitions in `packages/sdk/src/schema.ts`. Contracts accept canonical JSON strings for complex request records so their public GenVM ABI stays straightforward. All digests are lowercase SHA 256 hex with sixty four characters; addresses are hexadecimal twenty byte account addresses. Canonical JSON sorts object keys, uses compact separators and preserves UTF 8.

## Request envelope

| Field | Meaning |
| --- | --- |
| request_id | Unique request identifier, 1 to 128 UTF 8 bytes |
| owner, parties | Locked signing owner and up to six appeal parties |
| policy_id, policy_revision | Registered immutable policy version |
| subject_id, subject_digest | Subject label and exact claim byte commitment |
| manifest_digest | Canonical commitment to every source and disclosure record |
| consumer | Exact subscribing application contract |
| consequence_digest | Exact intended application consequence |
| generation | Positive u32 revision generation |
| deadline | ISO timestamp with timezone, checked against transaction datetime |

A manifest contains two to six sources. A source contains publisher_id, publisher_revision, publication and ownership. Each record contains record_id, authority, channel, original public HTTPS URL, audit capture URL, byte_hash, byte_length, revision, scope and one to eight required spans. Each span names span_id, start and end byte offsets with an exclusive end, and quote_hash. It points into the raw committed UTF 8 bytes. The complete manifest is limited to 24 KiB of encoded JSON. Each assessment must fit the smaller complete pair budget.

## Canonical result

A batch or certificate preserves the request fields. It adds batch_digest, status, pairs, selected_subset, supported_origin_ids, non_merge_witnesses, attempts, certificate_id, prior_certificates, coverage, unresolved and superseded_by.

The pairs map uses `left:right` in manifest index order. Every entry contains relation, rule_id, scope, witnesses, coverage and unresolved. A witness includes source_hash, record_id, span_id, start, end and quote_hash. The scope is `editorial_or_measurement_origin`. Model prose is not a consensus binding.

Relations are SHARED_ORIGIN, INDEPENDENT and UNKNOWN. Controlling rules are R_SHARED_CONTROL, R_SYNDICATION, R_COPIED_REPORTING, R_INDEPENDENT_PROCESS, R_AMBIGUOUS and R_UNAVAILABLE. Shared control, syndication and copied reporting control SHARED_ORIGIN. Only the independent process rule controls INDEPENDENT. Ambiguity and unavailable evidence control UNKNOWN.

## Constructors

| Contract | Arguments |
| --- | --- |
| SourceRegistry | None; deployer becomes registry owner |
| RelationDocket | Registry address; deployer becomes docket owner |
| CertificateHub | Docket address; deployer becomes hub owner |
| IncidentEvidenceConsumer | Hub address, independently configured incident owner |
| ProviderDisclosureConsumer | Hub address, independently configured disclosure owner |

The docket owner binds its hub once using `bind_hub(hub)`. Identical rebinding is idempotent; changing the bound address is refused.

## Public writes

| Contract and method | Typed arguments | Exact permission and consequence |
| --- | --- | --- |
| Registry.register_source_policy | operation_id:str, policy_id:str, revision:int, policy_json:str | Registry owner only; fixed minimum three, maximum six and unresolved refusal; versions sequential and immutable |
| Registry.register_publisher | operation_id:str, publisher_id:str, principal:str, evidence_json:str | Registry owner or the signing principal; new publisher authority binding only |
| Registry.correct_affiliation | operation_id:str, publisher_id:str, evidence_json:str, quarantine:bool | Existing principal only; new disclosure revision invalidates dependent use |
| Docket.open_batch | request_json:str, manifest_json:str | Locked request owner only; generation one, registered policy, current publisher revisions, unique record IDs and correct manifest commitment |
| Docket.assess_pair | request_id:str, generation:int, left:int, right:int | Anyone; current unlocked request, valid ordered pair, current authority revisions, deadline and complete context budget |
| Docket.seal_batch | request_id:str, generation:int, proposed_subset_json:str | Anyone; complete terminal matrix, canonical maximum subset, current revisions and deadline; emits publication on finalized status |
| Docket.appeal_relation | operation_id:str, request_id:str, generation:int, left:int, right:int | Request owner or named party; assessed pair and fewer than three attempts; freezes prior generation and clears the entire matrix |
| Docket.acknowledge_revision | operation_id:str, request_id:str, manifest_json:str, deadline:str | Request owner only; same publishers, new current disclosures and committed source revisions; starts successor generation |
| Docket.expire_batch | request_id:str | Anyone after the transaction deadline; unfinished requests become TIMEOUT |
| Hub.subscribe | operation_id:str, consumer:str, request_id:str, configuration_digest:str | Exact consumer contract only; matches the locked envelope |
| Hub.publish_certificate | certificate_json:str | Configured docket contract only through its finalized emission; exact sealed current record and maximum subset |
| Hub.deliver_certificate | operation_id:str, certificate_id:str, consumer:str | Anyone can schedule; exact active certificate, consumer and configuration subscription required; emits finalized callback |
| Hub.acknowledge_revision | operation_id:str, certificate_id:str, generation:int | Exact consumer contract only; existing delivery operation and matching generation |
| Consumer.configure | operation_id:str, configuration_json:str | That consumer owner only; approve exact bindings, strictly increasing replacement generation; emits subscription after finality |
| Consumer.receive_certificate | payload_json:str | Configured hub contract only; authenticated finalized boundary, exact current record and maximum subset; persists acknowledgement |
| Incident.admit_incident | operation_id:str, request_id:str, subject_digest:str, consequence_digest:str | Incident owner only; finalized received certificate, current configuration and evidence, deadline, no unresolved flag and three origins |
| Disclosure.admit_disclosure | operation_id:str, request_id:str, subject_digest:str, consequence_digest:str | Disclosure owner only; same strict boundary under separate control |

Identical repeated operations are idempotent. Conflicting reuse is an expected deterministic error. An exact duplicate delivery may retry a failed callback. Reordered older callbacks cannot update a consumer with a newer configuration or generation. Historical completed action retries return the original acknowledgement; they do not create fresh admissions.

## Views and pagination

`Registry.get_policy(policy_id, revision)` and `get_publisher(publisher_id)` return the corresponding immutable policy or current disclosure. `list_records(kind, offset, limit)` accepts publishers or policies.

`Docket.get_batch(request_id)`, `is_current(request_id, generation)`, `list_batches(offset, limit)` and `list_history(offset, limit)` expose current and superseded records.

`Hub.get_certificate(certificate_id)`, `is_active(certificate_id)`, `get_delivery(operation_id)` and `list_certificates(offset, limit)` expose finality, quarantine and callback acknowledgement state.

Each consumer has `get_state(request_id)` and `get_action(operation_id)`. State includes its separate owner, last applied generation, configuration and receipt. All page limits are 1 to 50.

## Lifecycle

| State | Meaning and permitted use |
| --- | --- |
| PENDING, BROADCAST | Signed operation queued or submitted; no certificate use |
| ACCEPTED | Network outcome accepted; execution success is checked separately |
| PROVISIONAL | Batch open or successor waiting for a complete matrix |
| SEALED | Complete matrix persisted; finalized source publication still awaited |
| FINALIZED | Authenticated finalized source publication; delivery and exact consumer checks still required |
| UNRESOLVED | Terminal matrix contains unknown evidence; both examples refuse admission |
| SUPERSEDED | Historical revision replaced; superseded_by points to its successor |
| QUARANTINED | Current source revision or status has invalidated this certificate |
| TIMEOUT | Unfinished request expired; no fresh assessment or admission |
| DELIVERY_FAILED | Client display for a failed execution; hub delivery journal and acknowledgement reveal actual completion |
| ADMITTED | Historical consumer action completed under its exact certificate boundary |

Execution failure does not become a fabricated successful lifecycle state. The RPC transaction can be finalized with an execution error; the operation journal records both separately.

## HTTP API

Public GET endpoints are `/api/health`, `/api/deployment`, `/api/records` and `/api/captures/:hash`. Captures serve committed bytes as plain text with a restrictive content policy. The explorer response includes its observation timestamp and a stale flag when it falls back to indexed data.

Email authenticated POST `/api/captures` accepts record_id, authority, URL, scope and revision, returning a committed record and the exact decoded text. No server AI assessment is involved.

Email authenticated POST `/api/operations` accepts operation_id, signer_address, contract, method and bounded primitive args. The embedded Privy account must belong to the verified email identity. POST `/api/operations/:id/broadcast` accepts signed_transaction, verifies its exact consensus and application bindings, journals before broadcast and returns transaction_hash. GET `/api/operations` lists the current identity’s latest fifty operation statuses.

Bearer headers contain a verified Privy identity token. No private key enters these API bodies. Server secrets are read from deployment environment settings and never returned by public configuration.
