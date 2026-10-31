import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {indexRecords} from '../apps/api/src/indexer';
import {monitorSources} from '../apps/api/src/source-monitor';
import {sql} from '../apps/api/src/db';
import {readPage,fetchPublicRecords} from '../packages/sdk/src/client';
import {batchCommitment,canonical,sha256,verifyRequestBindings,type Deployment} from '../packages/sdk/src/schema';
const d=JSON.parse(await readFile('deployments/studionet.json','utf8')) as Deployment;
assert.equal(d.schema_version,2);
const reader:typeof readPage=async(...args)=>{
 for(let n=0;n<81;n++){
  try{return await readPage(...args);}
  catch(error){let current=error;let quota=false;for(let depth=0;depth<6&&current&&typeof current==='object';depth++){const e=current as {code?:number;status?:number;cause?:unknown};quota ||= e.code===-32029||e.status===429;current=e.cause;}if(!quota||n===80)throw error;console.log('Studio quota; retaining exact feed page and retrying in 60 seconds');await new Promise(r=>setTimeout(r,60000));}
 }
 throw Error('Feed remains unavailable');
};
const records=await fetchPublicRecords(d,reader);
for(const batch of [...records.batches,...records.certificates]){await verifyRequestBindings(batch);assert.equal(batch.batch_digest,await batchCommitment(batch));assert.equal(batch.manifest_digest,await sha256(canonical(batch.manifest)));}
await indexRecords(d,true,reader);
const before=await sql`SELECT contract_address,record_kind,record_id,payload FROM roots_records ORDER BY contract_address,record_kind,record_id`;
await sql`UPDATE roots_checkpoints SET next_offset=1 WHERE contract_address=${d.contracts.source_registry!.address} AND record_kind='publishers'`;
await indexRecords(d,false,reader);
const after=await sql`SELECT contract_address,record_kind,record_id,payload FROM roots_records ORDER BY contract_address,record_kind,record_id`;
assert.deepEqual(after,before,'Continuation must equal a complete rebuild on stable contract state');
assert.equal(after.filter(r=>r.record_kind==='batches').length,records.batches.length);
await monitorSources(d);await monitorSources(d);
const observations=await sql`SELECT record_hash,original_url,status,checked_at FROM roots_source_observations WHERE contract_address=${d.contracts.relation_docket!.address} ORDER BY record_hash,original_url`;
assert.ok(observations.length>0);assert.ok(observations.every(o=>o.checked_at),'Each original source must have a current observation');
await writeFile('evidence/release-records-v2.json',JSON.stringify({classification:'Actual current Studio feeds, exact SDK bindings and PostgreSQL rebuild/continuation; source observations are operational and do not authorize corrections',release_id:d.release_id,counts:{batches:records.batches.length,certificates:records.certificates.length,publishers:records.publishers.length,policies:records.policies.length,indexed:after.length},sdk_semantic_bindings_verified:true,stable_current_batches:true,interrupted_continuation_equals_rebuild:true,observations},null,2));
console.log('Actual Studio records, exact commitments, continuation equality and original-source monitoring verified.');
