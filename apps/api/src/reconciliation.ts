import {sql} from './db';
import {keccak256} from 'viem';
import {networkClient} from '../../../packages/sdk/src/client';
export async function reconcile(){
 const lost=await sql`SELECT operation_id,signed_transaction FROM roots_operations WHERE transaction_hash IS NULL AND signed_transaction IS NOT NULL AND status='PENDING' LIMIT 8`;
 for(const row of lost){const hash=keccak256(row.signed_transaction);try{await networkClient().getTransaction({hash:hash as Parameters<ReturnType<typeof networkClient>["getTransaction"]>[0]["hash"]});await sql`UPDATE roots_operations SET transaction_hash=${hash},status='BROADCAST',updated_at=now() WHERE operation_id=${row.operation_id}`;}catch{try{const sent=await networkClient().sendRawTransaction({serializedTransaction:row.signed_transaction});await sql`UPDATE roots_operations SET transaction_hash=${sent},status='BROADCAST',updated_at=now() WHERE operation_id=${row.operation_id}`;}catch{console.error('Broadcast recovery remains pending for operation',row.operation_id);}}}
 const pending=await sql`SELECT operation_id,transaction_hash,method,args FROM roots_operations WHERE transaction_hash IS NOT NULL AND status IN ('PENDING','ACCEPTED','BROADCAST') ORDER BY created_at LIMIT 20`;
 for(const row of pending){
  try{const receipt=await networkClient().request({method:'eth_getTransactionByHash',params:[row.transaction_hash]});const data=receipt as unknown as {statusName?:string;status:number|string;result_name?:string;consensus_data?:{leader_receipt?:{mode:string;execution_result:string}[]};consensusData?:{leaderReceipt?:{mode:string;executionResult:string}[]}};
   const state=data.statusName||(typeof data.status==='string'?data.status:data.status===7?'FINALIZED':data.status===5?'ACCEPTED':'PENDING');
   const leader=data.consensus_data?.leader_receipt?.find(r=>r.mode==='leader');const success=leader?data.result_name==='MAJORITY_AGREE'&&leader.execution_result==='SUCCESS':null;
   await sql`UPDATE roots_operations SET status=${state},execution_success=${success},updated_at=now() WHERE operation_id=${row.operation_id}`;
   if(state==='FINALIZED'){const raw=receipt as unknown as {consensus_data?:{votes?:Record<string,string>}};const disagreements=Object.values(raw.consensus_data?.votes||{}).filter(x=>x.toLowerCase()==='disagree').length;const relation=row.method==='assess_pair'?`${row.args[0]}:${row.args[2]}:${row.args[3]}`:row.operation_id;const generation=row.method==='assess_pair'?Number(row.args[1]):0;await sql`INSERT INTO roots_metrics(operation_id,relation_key,generation,disagreement_count,receipt) VALUES(${row.operation_id},${relation},${generation},${disagreements},${JSON.stringify(receipt)}::jsonb) ON CONFLICT(operation_id) DO NOTHING`;}
  }catch{console.error('Receipt pending for operation',row.operation_id);}
 }
}
