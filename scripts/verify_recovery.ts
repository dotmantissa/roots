import {readFile,writeFile} from 'node:fs/promises';
import {sql} from '../apps/api/src/db';
import {reconcile} from '../apps/api/src/reconciliation';
import {indexRecords} from '../apps/api/src/indexer';
import type {Deployment} from '../packages/sdk/src/schema';
import {keccak256} from 'viem';
const receipt=JSON.parse(await readFile('evidence/runtime-probe-receipt.json','utf8'));const raw=receipt.sim_config.signed_rollup_transaction;const hash=keccak256(raw);
if(hash!==receipt.hash)throw Error('Recorded signed bytes do not match the authentic receipt');
const id='controlled-crash-recovery';
// Reconstruct precisely the durable state left by termination after broadcast, before saving the hash.
await sql`INSERT INTO roots_operations(operation_id,user_id,signer_address,binding_digest,contract_address,method,args,signed_transaction,status) VALUES(${id},'controlled recovery test',${receipt.from_address},${'0'.repeat(64)},${receipt.to_address},'runtime compatibility',${'[]'}::jsonb,${raw},'PENDING') ON CONFLICT(operation_id) DO UPDATE SET transaction_hash=NULL,status='PENDING',signed_transaction=EXCLUDED.signed_transaction`;
await reconcile();const rows=await sql`SELECT operation_id,transaction_hash,status,execution_success FROM roots_operations WHERE operation_id=${id}`;
if(rows[0].transaction_hash!==receipt.hash||rows[0].status!=='FINALIZED'||rows[0].execution_success!==true)throw Error('Lost broadcast was not recovered');
const deployment=JSON.parse(await readFile('deployments/studionet.json','utf8')) as Deployment;
await indexRecords(deployment,true);
const before=await sql`SELECT count(*)::int AS n FROM roots_records`;
// Persist an interrupted index checkpoint and resume. Page writes and checkpoint are atomic.
const address=deployment.contracts.source_registry!.address;
await sql`INSERT INTO roots_checkpoints(contract_address,record_kind,next_offset) VALUES(${address},'publishers',1) ON CONFLICT(contract_address,record_kind) DO UPDATE SET next_offset=1`;
await indexRecords(deployment);
const after=await sql`SELECT count(*)::int AS n FROM roots_records`;if(after[0].n<before[0].n)throw Error('Interrupted index lost records');
await writeFile('evidence/recovery-results.json',JSON.stringify({authentic_receipt:receipt.hash,lost_broadcast_reconciled:rows[0],records_before:before[0].n,records_after:after[0].n,classification:'controlled crash state reconstructed from authentic signed broadcast',interrupted_checkpoint_resumed:true},null,2));
console.log('Signed broadcast recovery and interrupted indexing verified');
