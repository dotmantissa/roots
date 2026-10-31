CREATE TABLE IF NOT EXISTS roots_captures (
 hash text PRIMARY KEY CHECK (length(hash)=64),
 raw_bytes bytea NOT NULL,
 original_url text NOT NULL,
 media_type text NOT NULL,
 byte_length integer NOT NULL CHECK (byte_length BETWEEN 1 AND 49152),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS roots_operations (
 operation_id text PRIMARY KEY,
 user_id text NOT NULL,
 signer_address text NOT NULL,
 binding_digest text NOT NULL,
 contract_address text NOT NULL,
 method text NOT NULL,
 args jsonb NOT NULL,
 signed_transaction text,
 transaction_hash text,
 status text NOT NULL DEFAULT 'PENDING',
 execution_success boolean,
 error_code text,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS roots_operations_user ON roots_operations(user_id,created_at DESC);
ALTER TABLE roots_operations ADD COLUMN IF NOT EXISTS delivery_status text;
CREATE TABLE IF NOT EXISTS roots_records (
 contract_address text NOT NULL,
 record_kind text NOT NULL,
 record_id text NOT NULL,
 payload jsonb NOT NULL,
 indexed_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(contract_address,record_kind,record_id)
);
CREATE TABLE IF NOT EXISTS roots_checkpoints (
 contract_address text NOT NULL,
 record_kind text NOT NULL,
 next_offset integer NOT NULL,
 PRIMARY KEY(contract_address,record_kind)
);
CREATE TABLE IF NOT EXISTS roots_metrics (
 operation_id text PRIMARY KEY,
 relation_key text NOT NULL,
 generation integer NOT NULL,
 disagreement_count integer NOT NULL DEFAULT 0,
 receipt jsonb NOT NULL
);
ALTER TABLE roots_operations ADD COLUMN IF NOT EXISTS next_reconcile_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE roots_operations ADD COLUMN IF NOT EXISTS reconcile_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE roots_operations ADD COLUMN IF NOT EXISTS callback_next_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE roots_operations ADD COLUMN IF NOT EXISTS callback_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE roots_operations ADD COLUMN IF NOT EXISTS callback_status text;
ALTER TABLE roots_operations ADD COLUMN IF NOT EXISTS needs_attention boolean NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS roots_operations_reconcile ON roots_operations(next_reconcile_at) WHERE status IN ('PENDING','BROADCAST','ACCEPTED');
CREATE INDEX IF NOT EXISTS roots_operations_callbacks ON roots_operations(callback_next_at) WHERE status='FINALIZED' AND execution_success=true;
CREATE TABLE IF NOT EXISTS roots_source_observations (
 contract_address text NOT NULL,
 record_hash text NOT NULL,
 original_url text NOT NULL,
 observed_hash text,
 status text NOT NULL DEFAULT 'UNCHECKED',
 checked_at timestamptz,
 next_check_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(contract_address,record_hash,original_url)
);
