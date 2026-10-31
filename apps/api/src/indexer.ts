import {recordId} from '../../../packages/sdk/src/records.js';
import {sql} from './db.js';
import {readPage} from '../../../packages/sdk/src/client.js';
import type {Deployment} from '../../../packages/sdk/src/schema.js';
export const feeds=[['source_registry','publishers','list_records'],['source_registry','policies','list_records'],['relation_docket','batches','list_batches'],['relation_docket','history','list_history'],['certificate_hub','certificates','list_certificates']] as const;
export async function indexRecords(deployment:Deployment,rebuild=false,pageReader:typeof readPage=readPage){
 if(rebuild)await sql.transaction([sql`DELETE FROM roots_records`,sql`DELETE FROM roots_checkpoints`]);
 for(const [contract,kind,method] of feeds){
  const address=deployment.contracts[contract]?.address;if(!address)continue;
  const checkpoints=await sql`SELECT next_offset FROM roots_checkpoints WHERE contract_address=${address} AND record_kind=${kind}`;let offset=Number(checkpoints[0]?.next_offset||0);
  while(true){
   const page=await pageReader(deployment,contract,method,method==='list_records'?[kind,offset,20]:[offset,20]);
   if(!Number.isSafeInteger(page.total)||page.total<0||page.items.length===0&&offset<page.total)throw Error('Incomplete index page');
   const writes=page.items.flatMap(raw=>{
    const item=raw as Record<string,unknown>;const id=recordId(kind,item);
    const upsert=sql`INSERT INTO roots_records(contract_address,record_kind,record_id,payload) VALUES(${address},${kind},${id},${JSON.stringify(item)}::jsonb) ON CONFLICT(contract_address,record_kind,record_id) DO UPDATE SET payload=EXCLUDED.payload,indexed_at=now()`;
    const remove=kind==='batches'?[sql`DELETE FROM roots_records WHERE contract_address=${address} AND record_kind='batches' AND payload->>'request_id'=${id} AND record_id<>${id}`]:[];
    return [...remove,upsert];
   });
   const next=offset+page.items.length;const finished=next>=page.total;
   await sql.transaction([...writes,sql`INSERT INTO roots_checkpoints(contract_address,record_kind,next_offset) VALUES(${address},${kind},${finished?0:next}) ON CONFLICT(contract_address,record_kind) DO UPDATE SET next_offset=EXCLUDED.next_offset`]);
   if(finished)break;offset=next;
  }
 }
}
