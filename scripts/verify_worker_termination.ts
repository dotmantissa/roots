import 'dotenv/config';
import {spawn} from 'node:child_process';
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {privateKeyToAccount} from 'viem/accounts';
import {createClient} from 'genlayer-js';
import {studionet} from 'genlayer-js/chains';
import {sql} from '../apps/api/src/db.js';
import {reconcile} from '../apps/api/src/reconciliation.js';
import {canonical} from '../packages/sdk/src/schema.js';

const operationId='controlled-worker-termination';
if(process.argv.includes('--child')){
 const owner=privateKeyToAccount(process.env.INCIDENT_OWNER_PRIVATE_KEY as `0x${string}`);
 const deployment=JSON.parse(await readFile('deployments/studionet.json','utf8'));
 const inputs=JSON.parse(await readFile('evidence/scenario-inputs.json','utf8'));
 const request=inputs.requests.controlled_wire_incident;
 const contract=deployment.contracts.incident_consumer.address;
 const args=['controlled-worker-action',request.request_id,request.subject_digest,request.consequence_digest];
 const binding=createHash('sha256').update(canonical({operation_id:operationId,signer_address:owner.address,contract,method:'admit_incident',args})).digest('hex');
 const provider={request:async({method,params}:{method:string;params?:unknown})=>{
  if(method==='eth_accounts'||method==='eth_requestAccounts')return [owner.address];
  if(method!=='eth_sendTransaction')throw Error('Unexpected recovery signer operation');
  const tx=(params as Record<string,string>[])[0];
  const signed=await owner.signTransaction({to:tx.to as `0x${string}`,data:tx.data as `0x${string}`,chainId:61999,nonce:Number(BigInt(tx.nonce)),gas:BigInt(tx.gas),gasPrice:BigInt(tx.gasPrice||'0'),value:0n,type:'legacy'});
  await sql`INSERT INTO roots_operations(operation_id,user_id,signer_address,binding_digest,contract_address,method,args,signed_transaction,status) VALUES(${operationId},'controlled worker termination test',${owner.address},${binding},${contract},'admit_incident',${JSON.stringify(args)}::jsonb,${signed},'PENDING')`;
  await createClient({chain:studionet}).sendRawTransaction({serializedTransaction:signed});
  // Exit after the authentic broadcast, deliberately before saving its returned hash.
  process.exit(86);
 }};
 await createClient({chain:studionet,account:owner.address,provider}).writeContract({address:contract,functionName:'admit_incident',args,value:0n});
 throw Error('Worker did not terminate at its broadcast boundary');
}else{
 const existing=await sql`SELECT * FROM roots_operations WHERE operation_id=${operationId}`;
 if(!existing.length){
  const child=spawn(process.execPath,['--import','tsx','scripts/verify_worker_termination.ts','--child'],{stdio:['ignore','inherit','inherit'],env:process.env});
  const exitCode=await new Promise<number|null>(resolve=>child.on('exit',resolve));
  if(exitCode!==86)throw Error('Worker did not exit after broadcast');
  const crashed=await sql`SELECT transaction_hash,signed_transaction,status FROM roots_operations WHERE operation_id=${operationId}`;
  if(crashed[0].transaction_hash||!crashed[0].signed_transaction||crashed[0].status!=='PENDING')throw Error('Crash boundary was not reproduced');
  console.log('Actual worker terminated after signed broadcast, before hash persistence');
 }
 for(let attempt=0;attempt<30;attempt++){
  await reconcile();
  const rows=await sql`SELECT operation_id,transaction_hash,status,execution_success FROM roots_operations WHERE operation_id=${operationId}`;
  if(rows[0].status==='FINALIZED'){
   if(!rows[0].transaction_hash||rows[0].execution_success!==false)throw Error('Expected copied-source refusal was not recovered');
   const metrics=await sql`SELECT receipt FROM roots_metrics WHERE operation_id=${operationId}`;
   if(metrics[0])await writeFile('evidence/receipts/worker-termination.json',JSON.stringify(metrics[0].receipt,null,2));
   await writeFile('deployments/operations/worker-termination.json',JSON.stringify({...rows[0],network:'studionet'},null,2));
   await writeFile('evidence/worker-termination.json',JSON.stringify({classification:'Actual process termination after authentic signed Studio broadcast',crash_exit_code:86,journal_before_recovery:'PENDING with signed bytes and no hash',recovered:rows[0],consumer_result:'Refused copied source admission'},null,2));
   console.log('Actual interrupted broadcast recovered to finalized consumer refusal');process.exit(0);
  }
  await new Promise(resolve=>setTimeout(resolve,30000));
 }
 throw Error('Recovery remains pending; rerun the same operation without rebroadcasting');
}
