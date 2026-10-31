import {sql} from './db.js';
import {retrieve} from './capture.js';
import {createHash} from 'node:crypto';
import type {Deployment} from '../../../packages/sdk/src/schema.js';
export async function monitorSources(deployment:Deployment){
 const docket=deployment.contracts.relation_docket?.address;if(!docket)return;
 await sql`INSERT INTO roots_source_observations(contract_address,record_hash,original_url)
 SELECT DISTINCT r.contract_address,rec->>'byte_hash',rec->>'url' FROM roots_records r
 CROSS JOIN LATERAL jsonb_array_elements(r.payload->'manifest') source
 CROSS JOIN LATERAL jsonb_array_elements(jsonb_build_array(source->'publication',source->'ownership')) rec
 WHERE r.contract_address=${docket} AND r.record_kind='batches' ON CONFLICT DO NOTHING`;
 const rows=await sql`WITH selected AS (SELECT contract_address,record_hash,original_url FROM roots_source_observations WHERE contract_address=${docket} AND next_check_at<=now() ORDER BY next_check_at,original_url LIMIT 8 FOR UPDATE SKIP LOCKED)
 UPDATE roots_source_observations o SET next_check_at=now()+interval '15 minutes' FROM selected s WHERE o.contract_address=s.contract_address AND o.record_hash=s.record_hash AND o.original_url=s.original_url RETURNING o.record_hash,o.original_url`;
 await Promise.all(rows.map(async row=>{let hash:null|string=null;let status='UNAVAILABLE';try{const {bytes}=await retrieve(row.original_url);hash=createHash('sha256').update(bytes).digest('hex');status=hash===row.record_hash?'MATCHED':'CHANGED';}catch{/* Operational observation only; custodians authorize on-chain revisions. */}
  await sql`UPDATE roots_source_observations SET observed_hash=${hash},status=${status},checked_at=now() WHERE contract_address=${docket} AND record_hash=${row.record_hash} AND original_url=${row.original_url}`;
 }));
}
