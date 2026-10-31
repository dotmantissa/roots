import {sql} from './db.js';
import {keccak256} from 'viem';
import {networkClient} from '../../../packages/sdk/src/client.js';
import {canonical,sha256} from '../../../packages/sdk/src/schema.js';
import {receiptState,retryDelay,type NetworkReceipt} from './receipt.js';
export async function reconcile(clientFactory:typeof networkClient=networkClient,operationPrefix=''){
 // Claim eligible rows atomically. Leases and independent eligibility timestamps
 // prevent stuck operations or concurrent workers from occupying every slot.
 const pending=await sql`WITH selected AS (
  SELECT operation_id FROM roots_operations WHERE operation_id LIKE ${operationPrefix+'%'} AND next_reconcile_at<=now() AND status IN ('PENDING','ACCEPTED','BROADCAST') AND (transaction_hash IS NOT NULL OR signed_transaction IS NOT NULL)
  ORDER BY next_reconcile_at,updated_at,operation_id FOR UPDATE SKIP LOCKED LIMIT 20
 ) UPDATE roots_operations o SET next_reconcile_at=now()+interval '45 seconds',reconcile_attempts=reconcile_attempts+1 FROM selected s WHERE o.operation_id=s.operation_id RETURNING o.*`;
 await Promise.all(pending.map(async row=>{
  const delay=retryDelay(Number(row.reconcile_attempts));
  try{
   const client=clientFactory();let hash=row.transaction_hash;
   if(!hash){hash=keccak256(row.signed_transaction);try{await client.getTransaction({hash});}catch(error){if(!/not found/i.test(String(error)))throw error;const sent=await client.sendRawTransaction({serializedTransaction:row.signed_transaction});if(sent!==hash)throw Error('Broadcast hash mismatch');}
    await sql`UPDATE roots_operations SET transaction_hash=${hash},status='BROADCAST' WHERE operation_id=${row.operation_id}`;
   }
   const receipt=await client.request({method:'eth_getTransactionByHash',params:[hash]}) as unknown as NetworkReceipt;
   if(!receipt)throw Error('Receipt not available');const state=receiptState(receipt);
   await sql`UPDATE roots_operations SET status=${state.status},execution_success=${state.success},next_reconcile_at=now()+${delay}*interval '1 second',needs_attention=${Number(row.reconcile_attempts)>=12&&state.status!=='FINALIZED'},error_code=NULL,updated_at=now() WHERE operation_id=${row.operation_id}`;
   if(state.status==='FINALIZED'){
    const args=row.args as (string|number)[];const assessment=row.method==='reserve_assessment';const relation=assessment?`${args[1]}:${args[3]}:${args[4]}`:row.operation_id;const generation=assessment?Number(args[2]):0;
    await sql`INSERT INTO roots_metrics(operation_id,relation_key,generation,disagreement_count,receipt) VALUES(${row.operation_id},${relation},${generation},${state.disagreements},${JSON.stringify(receipt)}::jsonb) ON CONFLICT(operation_id) DO UPDATE SET receipt=EXCLUDED.receipt,disagreement_count=EXCLUDED.disagreement_count`;
   }
  }catch{
   await sql`UPDATE roots_operations SET next_reconcile_at=now()+${delay}*interval '1 second',needs_attention=${Number(row.reconcile_attempts)>=12},error_code='RECONCILIATION_PENDING',updated_at=now() WHERE operation_id=${row.operation_id}`;
  }
 }));
 const callbacks=await sql`WITH selected AS (
  SELECT operation_id FROM roots_operations WHERE operation_id LIKE ${operationPrefix+'%'} AND callback_next_at<=now() AND status='FINALIZED' AND execution_success=true AND method IN ('deliver_certificate','configure','seal_batch','reserve_assessment') AND (callback_status IS NULL OR callback_status='AWAITING_CALLBACK')
  ORDER BY callback_next_at,updated_at,operation_id FOR UPDATE SKIP LOCKED LIMIT 8
 ) UPDATE roots_operations o SET callback_next_at=now()+interval '45 seconds',callback_attempts=callback_attempts+1 FROM selected s WHERE o.operation_id=s.operation_id RETURNING o.*`;
 await Promise.all(callbacks.map(async row=>{
  let status='AWAITING_CALLBACK';const delay=retryDelay(Number(row.callback_attempts));
  try{
   const client=clientFactory();const address=row.contract_address as `0x${string}`;const args=row.args as (string|number|boolean)[];
   if(row.method==='deliver_certificate'){
    const delivery=await client.readContract({address,functionName:'get_delivery',args:[args[0]]}) as {acknowledgement:null|{certificate_id:string}};
    if(delivery.acknowledgement?.certificate_id===args[1])status='COMPLETED';
   }else if(row.method==='configure'){
    const config=JSON.parse(String(args[1]));const state=await client.readContract({address,functionName:'get_state',args:[config.request_id]}) as {subscription_digest:string;configuration:unknown};
    if(state.subscription_digest===await sha256(canonical(config)))status='COMPLETED';else if(canonical(state.configuration)!==canonical(config))status='SUPERSEDED';
   }else if(row.method==='seal_batch'){
    const state=await client.readContract({address,functionName:'publication_state',args:[args[0]]}) as {published:boolean;generation:number};
    if(state.generation!==args[1])status='SUPERSEDED';else if(state.published)status='COMPLETED';
   }else{
    const batch=await client.readContract({address,functionName:'get_batch',args:[args[1]]}) as {generation:number;pairs:Record<string,unknown>;pending_attempts:Record<string,string>};const key=`${args[3]}:${args[4]}`;
    if(batch.generation!==args[2]||!batch.pairs[key]&&batch.pending_attempts[key]!==args[0])status='SUPERSEDED';else if(batch.pairs[key])status='COMPLETED';
   }
   if(status==='AWAITING_CALLBACK'){
    const metrics=await sql`SELECT receipt FROM roots_metrics WHERE operation_id=${row.operation_id}`;
    const children=receiptState(metrics[0]?.receipt as NetworkReceipt).children;
    for(const hash of children.slice(0,1)){
     const raw=await client.request({method:'eth_getTransactionByHash',params:[hash as `0x${string}`]}) as unknown as NetworkReceipt;
     if(!raw)continue;const child=receiptState(raw);
     if(child.status==='FINALIZED'&&child.success===false)status='CHILD_FAILED';
    }
   }
  }catch{/* Leave this operation eligible after backoff, allowing later rows through. */}
  const delivery=row.method==='deliver_certificate'?(status==='COMPLETED'?'DELIVERED':status==='CHILD_FAILED'?'DELIVERY_FAILED':'AWAITING_DELIVERY'):null;
  await sql`UPDATE roots_operations SET callback_status=${status},delivery_status=${delivery},callback_next_at=now()+${delay}*interval '1 second',needs_attention=${status==='CHILD_FAILED'||status==='AWAITING_CALLBACK'&&Number(row.callback_attempts)>=12},updated_at=now() WHERE operation_id=${row.operation_id}`;
 }));
}
