import {readFile,writeFile} from 'node:fs/promises';
import {sql} from '../apps/api/src/db.js';
import {reconcile} from '../apps/api/src/reconciliation.js';
import {indexRecords} from '../apps/api/src/indexer.js';
import type {Deployment} from '../packages/sdk/src/schema.js';
import {readPage} from '../packages/sdk/src/client.js';
import {keccak256} from 'viem';
function quotaDelay(error:unknown):number|null{
 let current=error;
 for(let depth=0;depth<6&&current&&typeof current==='object';depth++){
  const detail=current as {code?:number;status?:number;data?:{retry_after_seconds?:number};cause?:unknown};
  if(detail.code===-32029||detail.status===429){
   const seconds=detail.data?.retry_after_seconds;
   return typeof seconds==='number'&&Number.isFinite(seconds)?Math.max(1000,Math.min(60000,Math.ceil(seconds)*1000)):60000;
  }
  current=detail.cause;
 }
 return null;
}
async function readPageWithRetry(...args:Parameters<typeof readPage>):ReturnType<typeof readPage>{
 for(let attempt=0;attempt<81;attempt++){
  try{return await readPage(...args);}
  catch(error){
   const delay=quotaDelay(error);
   if(delay===null||attempt===80)throw error;
   console.log(`Studio quota; retrying the same index page in ${delay/1000} seconds`);
   await new Promise(resolve=>setTimeout(resolve,delay));
  }
 }
 throw Error('Index page retry limit exceeded');
}
const receipt=JSON.parse(await readFile('evidence/runtime-probe-receipt.json','utf8'));const raw=receipt.sim_config.signed_rollup_transaction;const hash=keccak256(raw);
if(hash!==receipt.hash)throw Error('Recorded signed bytes do not match the authentic receipt');
const id='controlled-crash-recovery';
// Reconstruct precisely the durable state left by termination after broadcast, before saving the hash.
await sql`INSERT INTO roots_operations(operation_id,user_id,signer_address,binding_digest,contract_address,method,args,signed_transaction,status) VALUES(${id},'controlled recovery test',${receipt.from_address},${'0'.repeat(64)},${receipt.to_address},'runtime compatibility',${'[]'}::jsonb,${raw},'PENDING') ON CONFLICT(operation_id) DO UPDATE SET transaction_hash=NULL,status='PENDING',signed_transaction=EXCLUDED.signed_transaction`;
await reconcile();const rows=await sql`SELECT operation_id,transaction_hash,status,execution_success FROM roots_operations WHERE operation_id=${id}`;
if(rows[0].transaction_hash!==receipt.hash||rows[0].status!=='FINALIZED'||rows[0].execution_success!==true)throw Error('Lost broadcast was not recovered');
const deployment=JSON.parse(await readFile('deployments/studionet.json','utf8')) as Deployment;
await indexRecords(deployment,true,readPageWithRetry);
const before=await sql`SELECT count(*)::int AS n FROM roots_records`;
const canonicalBefore=await sql`SELECT contract_address,record_kind,record_id,payload FROM roots_records ORDER BY contract_address,record_kind,record_id`;
// Persist an interrupted index checkpoint and resume. Page writes and checkpoint are atomic.
const address=deployment.contracts.source_registry!.address;
await sql`INSERT INTO roots_checkpoints(contract_address,record_kind,next_offset) VALUES(${address},'publishers',1) ON CONFLICT(contract_address,record_kind) DO UPDATE SET next_offset=1`;
await indexRecords(deployment,false,readPageWithRetry);
const after=await sql`SELECT count(*)::int AS n FROM roots_records`;if(after[0].n<before[0].n)throw Error('Interrupted index lost records');
const canonicalAfter=await sql`SELECT contract_address,record_kind,record_id,payload FROM roots_records ORDER BY contract_address,record_kind,record_id`;
if(JSON.stringify(canonicalAfter)!==JSON.stringify(canonicalBefore))throw Error('Resumed index differs from the complete contract rebuild');
const lifecycle=await sql`SELECT payload->>'status' AS status,count(*)::int AS n FROM roots_records WHERE record_kind IN ('batches','certificates') GROUP BY payload->>'status' ORDER BY status`;
const scenarios=JSON.parse(await readFile('evidence/scenario-results.json','utf8'));
for(const kind of ['incident','disclosure']){
 const key='controlled_measurement_'+kind;const result=scenarios[key];if(!result?.corrected_generation)throw Error('Consumer correction suite remains incomplete');
 const certs=canonicalAfter.filter(row=>row.record_kind==='certificates'&&row.payload.request_id===key);
 const old=certs.find(row=>row.payload.certificate_id===key+':'+(result.generation||1));
 const successor=certs.find(row=>row.payload.certificate_id===key+':'+result.corrected_generation);
 if(old?.payload.status!=='SUPERSEDED'||old.payload.superseded_by!==successor?.payload.certificate_id||JSON.stringify(successor?.payload.selected_subset)!==JSON.stringify(result.corrected_subset))throw Error('Rebuilt certificate revisions do not match verified consumer outcomes');
}
await writeFile('evidence/recovery-results.json',JSON.stringify({authentic_receipt:receipt.hash,lost_broadcast_reconciled:rows[0],records_before:before[0].n,records_after:after[0].n,classification:'controlled crash state reconstructed from authentic signed broadcast',interrupted_checkpoint_resumed:true,exact_rebuilt_records_preserved:true,lifecycle,consumer_successors_verified:true},null,2));
console.log('Signed broadcast recovery and interrupted indexing verified');
