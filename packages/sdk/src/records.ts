import type {Deployment} from './schema.js';
export function recordId(kind:string,item:Record<string,unknown>):string{
 if(kind==='batches')return String(item.request_id);
 if(kind==='history')return `${item.request_id}:${item.generation}`;
 if(kind==='policies')return `${item.policy_id}:${item.revision}`;
 if(kind==='publishers')return String(item.publisher_id);
 if(kind==='certificates')return String(item.certificate_id);
 throw Error('Unknown feed kind');
}
export function currentIndexedRecords(rows:{contract_address:string;record_kind:string;payload:Record<string,unknown>}[],deployment:Deployment){
 const names={batches:'relation_docket',certificates:'certificate_hub',policies:'source_registry',publishers:'source_registry'} as const;
 const result:{batches:unknown[];certificates:unknown[];policies:unknown[];publishers:unknown[]}={batches:[],certificates:[],policies:[],publishers:[]};
 for(const [kind,contract] of Object.entries(names)){
  const address=deployment.contracts[contract]?.address.toLowerCase();const unique=new Map<string,Record<string,unknown>>();
  for(const row of rows){if(row.record_kind!==kind||row.contract_address.toLowerCase()!==address)continue;
   const key=recordId(kind,row.payload);const previous=unique.get(key);
   if(!previous||Number(row.payload.generation||0)>=Number(previous.generation||0))unique.set(key,row.payload);
  }
  result[kind as keyof typeof result]=[...unique.values()];
 }
 return result;
}
