import Fastify from 'fastify';
import cors from '@fastify/cors';
import rateLimit from '@fastify/rate-limit';
import {readFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {z} from 'zod';
import {env} from './config.js';
import {sql} from './db.js';
import {authenticate} from './auth.js';
import {retrieve,commitRecord} from './capture.js';
import {verifySignedOperation} from './journal.js';
import {monitorSources} from './source-monitor.js';
import {reconcile} from './reconciliation.js';
import {networkClient,fetchPublicRecords} from '../../../packages/sdk/src/client.js';
import {canonical,Address,Id,Hash,Text256,PublicUrl,Revision,type Deployment} from '../../../packages/sdk/src/schema.js';
import {currentIndexedRecords} from '../../../packages/sdk/src/records.js';
const app=Fastify({logger:{redact:['req.headers.authorization','req.body.signed_transaction','DATABASE_URL','PRIVY_APP_SECRET']},bodyLimit:100000});
await app.register(cors,{origin:env.WEB_ORIGIN,methods:['GET','POST']});await app.register(rateLimit,{max:60,timeWindow:'1 minute'});
app.addHook('onSend',async(_req,reply)=>{reply.header('X-Content-Type-Options','nosniff');reply.header('Referrer-Policy','strict-origin-when-cross-origin');});
app.setErrorHandler((error,_req,reply)=>{const e=error as Error&{statusCode?:number};reply.code(e.statusCode||400).send({error:e.statusCode===401||e.statusCode===403?e.message:e instanceof z.ZodError?e.issues[0].message:'The request could not be completed. Check the source and try again',code:e.statusCode||'REQUEST_FAILED'});});
async function deployment():Promise<Deployment>{try{return JSON.parse(await readFile('deployments/studionet.json','utf8'));}catch{return {network:'studionet',rpc:'https://studio.genlayer.com/api',chain_id:61999,runner:'1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6',contracts:{},owners:{}};}}
app.get('/api/health',async()=>({status:'ready',network:'studionet'}));
app.get('/api/deployment',async()=>{
 const d=await deployment();if(d.schema_version!==2)return d;
 const pending:Record<string,string>={};
 const values=await Promise.all((['source_registry','relation_docket','incident_consumer','disclosure_consumer'] as const).map(async name=>{
  const address=d.contracts[name]?.address;if(!address)return null;
  const authority=await networkClient().readContract({address,functionName:'get_authority',args:[]}) as {owner:string;pending_owner:string};
  return {name,authority};
 }));
 for(const value of values){if(!value)continue;const key=value.name==='source_registry'?'registry':value.name==='relation_docket'?'docket':value.name==='incident_consumer'?'incident':'disclosure';d.owners[key]=value.authority.owner;pending[key]=value.authority.pending_owner;}
 return {...d,pending_owners:pending};
});
app.get('/api/consumer-state/:kind/:request',async req=>{const p=z.object({kind:z.enum(['incident_consumer','disclosure_consumer']),request:Id}).parse(req.params);const d=await deployment();const address=d.contracts[p.kind]?.address;if(!address)throw Error('Missing consumer');return networkClient().readContract({address,functionName:'get_state',args:[p.request]});});
app.get('/api/capacity/:principal',async req=>{const p=Address.parse((req.params as {principal:string}).principal);const d=await deployment();return networkClient().readContract({address:d.contracts.relation_docket!.address,functionName:'get_capacity',args:[p]});});
app.get('/api/delivery-operation/:certificate',async req=>{const key=z.string().min(1).max(256).parse((req.params as {certificate:string}).certificate);const d=await deployment();return {operation_id:await networkClient().readContract({address:d.contracts.certificate_hub!.address,functionName:'get_delivery_operation',args:[key]})};});
app.get('/api/source-observations',async()=>{const d=await deployment();const address=d.contracts.relation_docket?.address;if(!address)return [];await monitorSources(d);return sql`SELECT record_hash,original_url,observed_hash,status,checked_at FROM roots_source_observations WHERE contract_address=${address}`;});
let cache:{deployment:string;at:number;records:Awaited<ReturnType<typeof fetchPublicRecords>>}|null=null;
app.get('/api/records',async()=>{const d=await deployment();if(!d.contracts.source_registry)return {batches:[],certificates:[],policies:[],publishers:[],indexed_at:null};if(cache&&cache.deployment===d.release_id&&Date.now()-cache.at<60000)return {...cache.records,indexed_at:new Date(cache.at).toISOString()};try{const records=await fetchPublicRecords(d);cache={deployment:d.release_id||'',at:Date.now(),records};return {...records,indexed_at:new Date(cache.at).toISOString()};}catch{const rows=await sql`SELECT contract_address,record_kind,payload,indexed_at FROM roots_records WHERE contract_address=ANY(${Object.values(d.contracts).map(c=>c!.address)})`;return {...currentIndexedRecords(rows as {contract_address:string;record_kind:string;payload:Record<string,unknown>}[],d),indexed_at:rows[0]?.indexed_at??null,stale:true};}});
app.post('/api/captures',async req=>{await authenticate(req);const input=z.object({record_id:Id,authority:Text256,url:PublicUrl,scope:Text256,revision:Revision}).strict().parse(req.body);const {bytes,mediaType}=await retrieve(input.url);const record=commitRecord(input,bytes,env.CAPTURE_ORIGIN);await sql`INSERT INTO roots_captures(hash,raw_bytes,original_url,media_type,byte_length) VALUES(${record.byte_hash},decode(${bytes.toString('hex')},'hex'),${input.url},${mediaType},${bytes.length}) ON CONFLICT(hash) DO NOTHING`;return {record,text:bytes.toString('utf8'),audit_url:'/api/captures/'+record.byte_hash};});
app.get('/api/captures/:hash',async(req,reply)=>{const hash=Hash.parse((req.params as {hash:string}).hash);const rows=await sql`SELECT encode(raw_bytes,'base64') AS bytes FROM roots_captures WHERE hash=${hash}`;if(!rows.length)return reply.code(404).send({error:'Capture not found'});reply.header('Content-Type','text/plain; charset=utf-8').header('Content-Security-Policy',"default-src 'none'; sandbox").header('Cache-Control','public, max-age=31536000, immutable');return Buffer.from(rows[0].bytes,'base64');});
const methods:Record<string,string[]>={source_registry:['register_publisher','correct_affiliation','register_source_policy','nominate_owner','accept_owner','nominate_principal','accept_principal','recover_principal'],relation_docket:['nominate_owner','accept_owner','authorize_requester','open_batch','reserve_assessment','seal_batch','appeal_relation','acknowledge_revision','expire_batch'],certificate_hub:['deliver_certificate'],incident_consumer:['configure','admit_incident','nominate_owner','accept_owner'],disclosure_consumer:['configure','admit_disclosure','nominate_owner','accept_owner']};
app.post('/api/operations',async req=>{
 const user=await authenticate(req);const input=z.object({operation_id:Id,signer_address:Address,contract:z.enum(['source_registry','relation_docket','certificate_hub','incident_consumer','disclosure_consumer']),method:Id,args:z.array(z.union([z.string().max(24576),z.number().int(),z.boolean()])).max(8)}).strict().parse(req.body);
 if(!user.addresses.includes(input.signer_address.toLowerCase()))throw Object.assign(Error('This account cannot sign for that principal'),{statusCode:403});
 if(!methods[input.contract].includes(input.method))throw Error('Method unavailable');const d=await deployment();const address=d.contracts[input.contract]?.address;if(!address)throw Error('Contract unavailable');
 const binding=createHash('sha256').update(canonical(input)).digest('hex');const prior=await sql`SELECT * FROM roots_operations WHERE operation_id=${input.operation_id}`;
 if(prior.length){if(prior[0].user_id!==user.id||prior[0].binding_digest!==binding)throw Object.assign(Error('This operation ID already belongs to another request'),{statusCode:409});return {operation_id:input.operation_id,status:prior[0].status,transaction_hash:prior[0].transaction_hash};}
 const count=await sql`SELECT count(*)::int AS n FROM roots_operations WHERE user_id=${user.id} AND status IN ('PENDING','BROADCAST','ACCEPTED')`;
 if(count[0].n>=8)throw Error('Eight requests are already pending. Let them finish first');
 const inserted=await sql.transaction([sql`SELECT pg_advisory_xact_lock(hashtext(${user.id}))`,sql`INSERT INTO roots_operations(operation_id,user_id,signer_address,binding_digest,contract_address,method,args) SELECT ${input.operation_id},${user.id},${input.signer_address},${binding},${address},${input.method},${JSON.stringify(input.args)}::jsonb WHERE (SELECT count(*) FROM roots_operations WHERE user_id=${user.id} AND status IN ('PENDING','BROADCAST','ACCEPTED'))<8 RETURNING operation_id`]);
 if(!inserted[1].length)throw Object.assign(Error('Eight requests are already pending. Let them finish first'),{statusCode:409});
 return {operation_id:input.operation_id,status:'PENDING',contract_address:address};
});
app.post('/api/operations/:id/broadcast',async req=>{
 const user=await authenticate(req);const id=Id.parse((req.params as {id:string}).id);const input=z.object({signed_transaction:z.string().regex(/^0x[a-fA-F0-9]+$/).max(100000)}).strict().parse(req.body);
 const rows=await sql`SELECT * FROM roots_operations WHERE operation_id=${id} AND user_id=${user.id}`;if(!rows.length)throw Error('Operation not found');const row=rows[0];if(row.transaction_hash)return {transaction_hash:row.transaction_hash,status:row.status};
 await verifySignedOperation(input.signed_transaction as `0x${string}`,row as {signer_address:string;contract_address:string;method:string;args:unknown[]});
 if(row.signed_transaction&&row.signed_transaction!==input.signed_transaction)throw Error('This operation already has a signed transaction');
 // Persist signed bytes before broadcast. Repeating these bytes after a crash is safe.
 const saved=await sql`UPDATE roots_operations SET signed_transaction=${input.signed_transaction},updated_at=now() WHERE operation_id=${id} AND status='PENDING' AND (signed_transaction IS NULL OR signed_transaction=${input.signed_transaction}) RETURNING operation_id`;
 if(!saved.length)throw Object.assign(Error('This request was cancelled or already signed with different bytes'),{statusCode:409});
 const hash=await networkClient().sendRawTransaction({serializedTransaction:input.signed_transaction as `0x${string}`});
 await sql`UPDATE roots_operations SET transaction_hash=${hash},status='BROADCAST',updated_at=now() WHERE operation_id=${id}`;
 return {transaction_hash:hash,status:'BROADCAST'};
});
let lastReconciliation=0;
app.post('/api/operations/:id/cancel',async req=>{const user=await authenticate(req);const id=Id.parse((req.params as {id:string}).id);const rows=await sql`UPDATE roots_operations SET status='CANCELLED',updated_at=now() WHERE operation_id=${id} AND user_id=${user.id} AND signed_transaction IS NULL AND transaction_hash IS NULL AND status='PENDING' RETURNING operation_id`;if(!rows.length)throw Object.assign(Error('Only your unsigned pending request can be cancelled'),{statusCode:409});return {operation_id:id,status:'CANCELLED'};});
app.get('/api/operations',async req=>{const user=await authenticate(req);if(Date.now()-lastReconciliation>60000){lastReconciliation=Date.now();await reconcile();}return await sql`SELECT operation_id,method,transaction_hash,status,execution_success,delivery_status,callback_status,reconcile_attempts,callback_attempts,needs_attention,error_code,created_at FROM roots_operations WHERE user_id=${user.id} ORDER BY created_at DESC LIMIT 50`;});
export default app;
