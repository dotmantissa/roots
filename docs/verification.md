# Verification record

Roots has been exercised on GenLayer Studio using the pinned runner in the deployment manifest. The source contracts are tied to their SHA 256 hashes and signed deployment receipts. The two example consumers have separate signing owners.

## Reproducible checks

The clean source copy excluded environment credentials and installed the exact Node and Python dependency manifests. Contract lint includes the five product contracts, the runtime probe and the adversarial validator probe. The deterministic suite has six Node tests and twenty four Python tests. Hosted browser checks cover desktop and mobile navigation, email readiness, persistent themes, the live data API and refused unauthenticated requests.

```sh
npm ci
python3 -m pip install -r requirements.lock.txt
npm run contracts:build
npm run lint
npm test
npm run build
BASE_URL=https://roots-mauve-delta.vercel.app npm run test:browser
```

Contract tests generate a temporary signing identity. CI does not require a production wallet or account secret. Authenticated network runs are separate from CI because they use real signing authorities and hosted validators.

## Public evidence and controlled fixtures

The NASA Worldview and NOAA workflow records were retrieved from their authentic public repositories and organizational disclosures. Independent validators agreed on their separate origins. Mirrored NASA records produced consensus disagreement and no accepted result. That is an unresolved public case, not a successfully adjudicated shared origin certificate.

The wire dispatches, gauges, affiliation changes and injection documents are authored validation fixtures. They are labelled as controlled records throughout the retained inputs and application subjects. They do not represent real incidents, hardware deployments, publishers or adoption.

The original temporary fixture host stopped during the disclosure scenario. Generations one and two correctly retained an unavailable relation and withheld a third origin. The original commitments and receipts remain in the evidence directory. The same authored bytes are now published at `https://roots-mauve-delta.vercel.app/validation/`, with a byte manifest. Restoration uses signed disclosure revisions and successor source manifests; it does not alter a committed URL in place.

The full six source matrix passed all fifteen comparisons and deterministic subset enumeration. A fourteen pair seal, an oversized request and an expired assessment were refused. An appeal before publication cleared the matrix and prevented sealing its incomplete successor. See `evidence/bounds-results.json` and its signed receipts.

Wrong decisions, omitted controlling exceptions, forged spans and injected instructions were tested with captured validator callbacks and actual Studio validators. The live malicious proposals received validator disagreement and were not applied. Changed bytes produced an agreed deterministic refusal. The public source commitments and validator votes are retained in `evidence/validator-probe-results.json`.

The live email workflow completed three authenticated public captures, embedded signing, durable operation preparation and broadcast, then verified the finalized exact batch record. The same email principal registered a public disclosure and signed a correction through the hosted publisher form. Both transactions finalized successfully; contract reads verified the signer, principal and second disclosure revision. The workflow record contains public operation identifiers and receipts, never identity tokens or private signing keys.

## Recovery and delivery

A dedicated worker was terminated with exit code 86 immediately after an authentic signed broadcast and before hash persistence. Reconciliation recovered the missing transaction identifier and the finalized copied-source refusal. `evidence/worker-termination.json` records the actual process boundary. The earlier reconstructed crash state and interrupted index checkpoint test remain in `evidence/recovery-results.json`.

Finalized callback delivery, duplicate callbacks and consumer acknowledgements are verified through their emitted transaction receipts. Application actions still check the exact configuration and current source revisions at execution time.

Both separately owned consumers accepted the restored three-origin measurement certificate: incident generation two and disclosure generation three. A signed affiliation correction froze fresh admission and refused stale delivery. Complete successor assessments produced subset `[0,1]` in incident generation three and disclosure generation four. Each owner approved its replacement configuration, received a finalized delivery and acknowledgement, and refused admission with fewer than three origins. `evidence/scenario-results.json` retains these results alongside the original copied-source refusals.

Disclosure generation four initially received validator disagreement for pair `0:2`; no pair state was applied. One explicit retry used a distinct operation identifier and unchanged contract arguments after confirming that absence. It finalized with validator agreement. Both receipts remain available, bound by `evidence/consensus-recovery.json`; the initial disagreement has not been overwritten.

The supplemental copied-reporting case used three distinct public URL hostnames, including two temporary fixture tunnels. Validators finalized all three relations as `SHARED_ORIGIN`, and the one-origin certificate received an authenticated delivery acknowledgement. The incident consumer refused admission. The public fixture hostnames served explicitly authored dispatch copies. Inputs, public hostnames, signed transactions and outcomes are retained in `evidence/three-domain-input.json`, `evidence/three-domain-results.json` and the operation receipts.

The final database rebuild and interrupted-checkpoint continuation preserved exactly the same 32 records and payloads, including both superseded measurement certificates and their finalized successors. The verification reader encountered the actual 500-request hourly quota, waited using the server's retry hint, and retried the same page without restarting completed feeds. The optional reader leaves the indexer's default behavior unchanged. `evidence/recovery-results.json` and `evidence/index-quota-recovery.json` retain the outcomes.

The hosted API returned nine batches, nine certificates, one policy and seven publishers from current contract reads. It matched both consumer successors and the supplemental one-origin certificate. All three hosted browser checks passed with the final records visible in desktop and mobile screenshots; see `evidence/hosted-records.json`.

The complete offline audit verified five deployed source hashes, twenty captured source hashes, 187 finalized operation receipts and 48 exact signed journals, including the finalized parent, consumer callback and acknowledgement links. Run `bash scripts/python.sh scripts/verify_evidence.py --require-complete` to repeat this audit without network requests.

`npm run integration:studio` resumes retained recovery inputs through `scripts/studio_resume.py` when present. Its operation journals separate restoration, independent acceptance and substantive affiliation correction. An explicit RPC quota refusal or HTTP 429 waits sixty seconds before retrying the exact RPC payload. The helper persists the exact signed transaction and its hash before sending, and bounds each RPC request to thirty seconds. An ambiguous transport error stops the run; resumption checks that hash and, only when absent, resends the same signed bytes. Recovery tests cover both accepted and unsent transactions after a lost response, and refusal of a modified signed journal.

## Resource measurements

`evidence/resource-profile.json` records exact source bytes, decoded text lengths and complete prompt sizes for committed source packets. Each participant performs one substantive model call per pair. Four records must fit the 16 KiB complete packet and 24 KiB prompt budget; the record ceiling is 48 KiB. Oversized tasks are refused without truncation.

Studio receipts do not expose VM CPU, memory or billed model token telemetry. The report states that limitation and does not substitute network latency for VM measurements. The observed hosted quota is 500 RPC requests per hour. Recovery reuses verified finalized receipts and polls new operations conservatively.

## Dependency review

The retained dependency audit has no critical advisories. It still reports twenty one high and ten moderate advisories in upstream Privy and wallet dependencies, including nested Zod, WebSocket and URI decoding packages. The suggested automated fix downgrades Privy across a major version and would change the verified authentication integration. These findings remain open; this is not a clean security audit.

Only email authentication and embedded accounts are enabled. Account secrets remain server settings or protected local configuration. Public transaction receipts and evidence captures contain no account tokens or private keys.

## Final source record

The verified implementation and receipt stage is `06520d724fe0e1cbb33aee9e613988e7950cf035`. `evidence/verification-summary.json` records the final checks and distinguishes that source from the already hosted production release. The adversarial probe deployment manifest is retained with its matching source hash and finalized deployment receipt.
