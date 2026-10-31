import assert from 'node:assert/strict';
import {writeFile} from 'node:fs/promises';
import {sql} from '../apps/api/src/db';
import {indexRecords} from '../apps/api/src/indexer';
import {reconcile} from '../apps/api/src/reconciliation';
import {networkClient,type readPage} from '../packages/sdk/src/client';
import type {Deployment} from '../packages/sdk/src/schema';
import {sha256,canonical} from '../packages/sdk/src/schema';
const address='0xfafafafafafafafafafafafafafafafafafafafa';const prefix='controlled-review-'+crypto.randomUUID();
const deployment:Deployment={network:'stubbed',rpc:'stubbed',chain_id:61999,runner:'stubbed',owners:{},contracts:Object.fromEntries(['source_registry','relation_docket','certificate_hub'].map(n=>[n,{address,source_hash:'0'.repeat(64),deployment_transaction:'stubbed'}]))};
await writeFile('.runtime/review-database-test-prefix',prefix,{mode:0o600});
let batch={request_id:prefix,generation:1,certificate_id:'',status:'PROVISIONAL'};
const reader:typeof readPage=async(_d,_c,method)=>({total:method==='list_batches'?1:0,items:method==='list_batches'?[batch]:[]});
try{
 await indexRecords(deployment,false,reader);
 batch={...batch,certificate_id:prefix+':1',status:'SEALED'};
 await indexRecords(deployment,false,reader);
 await sql`INSERT INTO roots_records(contract_address,record_kind,record_id,payload) VALUES(${address},'batches',${prefix+':1'},${JSON.stringify(batch)}::jsonb)`;
 batch={...batch,generation:2,certificate_id:prefix+':2'};
 await indexRecords(deployment,false,reader);
 const indexed=await sql`SELECT record_id,payload FROM roots_records WHERE contract_address=${address} AND record_kind='batches'`;
 assert.equal(indexed.length,1);assert.equal(indexed[0].record_id,prefix);assert.deepEqual(indexed[0].payload,batch);
 const writes=Array.from({length:40},(_,i)=>{const stuck=i<24;const id=`${prefix}-${stuck?'stuck':'later'}-${String(i).padStart(2,'0')}`;return sql`INSERT INTO roots_operations(operation_id,user_id,signer_address,binding_digest,contract_address,method,args,transaction_hash,status,next_reconcile_at) VALUES(${id},'controlled-rpc-test',${address},${'0'.repeat(64)},${address},'admit_incident','[]'::jsonb,${'0x'+i.toString(16).padStart(64,'0')},'BROADCAST',${stuck?'1980-01-01T00:00:00Z':'1981-01-01T00:00:00Z'}::timestamptz)`;});
 await sql.transaction(writes);
 const fake=(()=>({request:async({params}:{params:string[]})=>{const later=parseInt(params[0],16)>=24;return {status:later?7:1,result_name:later?'MAJORITY_AGREE':undefined,consensus_data:{leader_receipt:later?[{mode:'leader',execution_result:'SUCCESS'}]:[]}};}})) as unknown as typeof networkClient;
 await reconcile(fake,prefix);await reconcile(fake,prefix);
 const completed=await sql`SELECT operation_id FROM roots_operations WHERE operation_id LIKE ${prefix+'%'} AND status='FINALIZED' AND execution_success=true`;
 assert.equal(completed.length,16,'Stuck oldest entries must not starve later finalized receipts');
 const config={request_id:prefix+'-callback'};
 await sql.transaction(Array.from({length:40},(_,i)=>{const stuck=i<24;const id=`${prefix}-callback-${stuck?'stuck':'later'}-${i}`;return sql`INSERT INTO roots_operations(operation_id,user_id,signer_address,binding_digest,contract_address,method,args,status,execution_success,callback_next_at) VALUES(${id},'controlled-rpc-test',${address},${'0'.repeat(64)},${address},'configure',${JSON.stringify([id,canonical({...config,request_id:config.request_id+'-'+i}),true])}::jsonb,'FINALIZED',true,${stuck?'1980-01-01T00:00:00Z':'1981-01-01T00:00:00Z'}::timestamptz)`;}));
 const callbacks=(()=>({readContract:async({args}:{args:string[]})=>{const index=Number(args[0].split('-').at(-1));return {configuration:{...config,request_id:args[0]},subscription_digest:index>=24?await sha256(canonical({...config,request_id:args[0]})):'',configuration_operation:'irrelevant'};}})) as unknown as typeof networkClient;
 for(let i=0;i<5;i++)await reconcile(callbacks,prefix+'-callback');
 const delivered=await sql`SELECT operation_id FROM roots_operations WHERE operation_id LIKE ${prefix+'-callback%'} AND callback_status='COMPLETED'`;
 assert.equal(delivered.length,16,'Stuck callbacks must not starve later completed subscriptions');
 await writeFile('evidence/database-recovery-v2.json',JSON.stringify({classification:'Real PostgreSQL integration with stubbed RPC and feed inputs; no network consensus claim',stable_current_batch_key:true,obsolete_rows_removed:true,generations_observed:[1,2],stuck_operations:24,later_finalized_operations_reconciled:16,reconciliation_cycles:2,stuck_callbacks:24,later_completed_callbacks_reconciled:16,callback_cycles:5},null,2));
 console.log('Actual PostgreSQL continuation and fair reconciliation passed; later 16 receipts processed despite 24 stuck entries.');
}finally{
 await sql.transaction([sql`DELETE FROM roots_metrics WHERE operation_id LIKE ${prefix+'%'}`,sql`DELETE FROM roots_operations WHERE operation_id LIKE ${prefix+'%'}`,sql`DELETE FROM roots_records WHERE contract_address=${address}`,sql`DELETE FROM roots_checkpoints WHERE contract_address=${address}`]);
}
