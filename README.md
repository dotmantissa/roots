# Roots

Three articles can repeat one press release. Roots makes that visible.

Roots is an evidence federation for applications that need separate reporting or measurement processes before accepting a claim. It commits the source material, evaluates each relationship with independent GenLayer validators, and publishes a certificate describing the largest group of pairwise independent origins. It does not decide whether the underlying claim is true.

## The product

The evidence desk lets you open a source batch and inspect its relation matrix. The source browser keeps public publisher disclosures beside their revisions. The certificate explorer retains unresolved, finalized, suspended and superseded records. Applications approve their own exact configurations and receive authenticated certificate messages only after source transaction finality.

Sign in uses email through Privy. The application handles transaction preparation and signing through an embedded account. Signed bytes are journaled before broadcast; private account keys stay with Privy. The API never supplies an authoritative AI verdict.

The interface includes a custom branching root mark, an editorial layout, light and dark themes, keyboard focus states and reduced motion support.

## Run locally

Use Node 22 and Python 3.14. Copy `.env.example` to `.env`, fill in the private server settings and the public Privy application identifier, then run:

```sh
npm run setup
npm run db:migrate
npm run dev
```

Open http://localhost:5173. The API listens on port 3911. The committed deployment manifest connects this workspace to GenLayer Studio. Do not reuse the application owner keys for another deployment.

For continuous indexing and receipt reconciliation, run `npm run worker` in a separate process. `npm run index:rebuild` rebuilds the database projection from contract records. The database is a cache and broadcast journal, not the certificate authority.

## Contracts

| Contract | Responsibility |
| --- | --- |
| SourceRegistry | Bind disclosure principals and immutable policy versions |
| RelationDocket | Lock requests, assess bounded source pairs, retain witnesses and seal complete matrices |
| CertificateHub | Authenticate finalized docket messages, manage subscriptions, deliver certificates and record acknowledgements |
| IncidentEvidenceConsumer | Enforce exact certificates before incident admission |
| ProviderDisclosureConsumer | Enforce exact certificates before disclosure admission |

The two consumers have separate owner addresses. All consumer action methods require a received finalized certificate, the approved configuration, at least three independent origins and current source revisions. Corrections and appeals freeze fresh use. A prior receipt cannot clear a newer restriction.

Deployment addresses, source hashes and transaction identifiers are in [the Studio manifest](deployments/studionet.json). The runtime is pinned to `py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6`, verified by an actual Studio deployment. Complete deployable source is committed alongside its local source templates. Run `npm run contracts:build` after editing a template.

## Checks

```sh
npm run lint
npm test
npm run build
npm run test:browser
```

Tests generate an ephemeral signing identity and need no production wallet credentials. Python tests execute the real contract source with GenLayer direct storage. They also explicitly invoke captured validator callbacks with wrong decisions, omitted rules and forged spans. Browser tests use the live local API and public contract records. Network evidence is kept separately because hosted Studio runs use real validators and have rate limits.

The controlled Studio scenario is run with `npm run integration:studio`. Its authored fixture documents must be served from the public origin recorded with the run. `scripts/studio_probes.py` exercises independent public sources and malicious leader proposals. These fixtures are labelled controlled validation records; they are not real incidents or adoption claims.

## Integration

The source policy SDK is in `packages/sdk/src`. It exports schemas, canonical hashing, deterministic subset selection and signed wrappers for the public methods. Constructor parameters, permissions, envelopes, terminal states and trust boundaries are described in [the API and contract reference](docs/api.md) and [the architecture note](docs/architecture.md).

An application starts by approving a locked batch configuration. It waits for authenticated finalized delivery, checks the certificate again at action time, and records its operation acknowledgement. An indexer or sponsor can schedule transactions, but cannot bypass that boundary.

Roots begins with two integrations and three useful measurements: certificate reuse, duplicate origin detections and validator disagreement per relation. Certificate creation and monitoring are bounded services. Payment collection is not part of this Studio deployment.
