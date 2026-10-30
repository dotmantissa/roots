import { z } from 'zod';
export const Hash = z.string().regex(/^[a-f0-9]{64}$/);
export const Address = z.string().regex(/^0x[a-fA-F0-9]{40}$/);
export const Id = z.string().min(1).max(128);
export const Relation = z.enum(['SHARED_ORIGIN','INDEPENDENT','UNKNOWN']);
export const Lifecycle = z.enum(['PENDING','ACCEPTED','PROVISIONAL','SEALED','FINALIZED','UNRESOLVED','SUPERSEDED','QUARANTINED','TIMEOUT','DELIVERY_FAILED']);
export const SpanSchema = z.object({span_id:Id,start:z.number().int().nonnegative(),end:z.number().int().positive(),quote_hash:Hash}).strict();
export const RecordSchema = z.object({record_id:Id,authority:z.string().min(1).max(256),channel:z.string().min(1).max(256),url:z.url().startsWith('https://').max(2048),capture_url:z.url().startsWith('https://').max(2048),byte_hash:Hash,byte_length:z.number().int().min(1).max(49152),revision:z.number().int().min(1).max(4294967295),scope:z.string().min(1).max(256),spans:z.array(SpanSchema).min(1).max(8)}).strict().superRefine((r,ctx)=>{for(const s of r.spans)if(s.start>=s.end||s.end>r.byte_length)ctx.addIssue({code:'custom',message:'Span is outside committed bytes'});});
export const SourceSchema = z.object({publisher_id:Id,publisher_revision:z.number().int().positive(),publication:RecordSchema,ownership:RecordSchema}).strict();
export const ManifestSchema = z.array(SourceSchema).min(2).max(6);
export const ConfigurationSchema = z.object({request_id:Id,policy_id:Id,policy_revision:z.number().int().positive(),subject_id:Id,subject_digest:Hash,manifest_digest:Hash,consumer:Address,consequence_digest:Hash,generation:z.number().int().positive(),deadline:z.iso.datetime({offset:true})}).strict();
export const RequestSchema = ConfigurationSchema.extend({owner:Address,parties:z.array(Address).max(6)}).strict();
export const WitnessSchema = SpanSchema.extend({source_hash:Hash,record_id:Id});
export const DecisionSchema = z.object({relation:Relation,rule_id:z.enum(['R_SHARED_CONTROL','R_SYNDICATION','R_COPIED_REPORTING','R_INDEPENDENT_PROCESS','R_AMBIGUOUS','R_UNAVAILABLE']),scope:z.literal('editorial_or_measurement_origin'),witnesses:z.array(WitnessSchema).max(32),coverage:z.boolean(),unresolved:z.boolean()});
export const BatchSchema = RequestSchema.extend({batch_digest:Hash,manifest:ManifestSchema,status:Lifecycle,pairs:z.record(z.string(),DecisionSchema),attempts:z.record(z.string(),z.number()),selected_subset:z.array(z.number().int()).max(6),supported_origin_ids:z.array(Id).max(6),non_merge_witnesses:z.array(z.object({pair:z.string(),witnesses:z.array(WitnessSchema)})),superseded_by:z.string(),certificate_id:z.string(),prior_certificates:z.array(z.string()),unresolved:z.boolean(),coverage:z.boolean()});
export const PolicySchema=z.object({policy_id:Id,revision:z.number(),owner:Address,min_origins:z.literal(3),max_sources:z.literal(6),unresolved_consequence:z.literal('REFUSE_ADMISSION'),name:z.string().optional()});
export const PublisherSchema=z.object({publisher_id:Id,principal:Address,revision:z.number(),status:z.enum(['ACTIVE','QUARANTINED']),evidence:RecordSchema});
export type Batch=z.infer<typeof BatchSchema>;
export type Source=z.infer<typeof SourceSchema>;
export type RecordCommitment=z.infer<typeof RecordSchema>;
export type Configuration=z.infer<typeof ConfigurationSchema>;
export type SourcePolicy=z.infer<typeof PolicySchema>;
export type Publisher=z.infer<typeof PublisherSchema>;
export type Decision=z.infer<typeof DecisionSchema>;
export type Contracts=Record<'source_registry'|'relation_docket'|'certificate_hub'|'incident_consumer'|'disclosure_consumer',{address:`0x${string}`;source_hash:string;deployment_transaction:string}>;
export type Deployment={network:string;rpc:string;chain_id:number;runner:string;contracts:Partial<Contracts>;owners:Record<string,string>};
export function canonical(value:unknown):string {
  if(value===null||typeof value!=='object') return JSON.stringify(value);
  if(Array.isArray(value))return '['+value.map(canonical).join(',')+']';
  return '{'+Object.keys(value).sort().map(k=>JSON.stringify(k)+':'+canonical((value as Record<string,unknown>)[k])).join(',')+'}';
}
export async function sha256(value:string|Uint8Array):Promise<string>{const bytes=typeof value==='string'?new TextEncoder().encode(value):value;const result=await crypto.subtle.digest('SHA-256',new Uint8Array(bytes));return Array.from(new Uint8Array(result),b=>b.toString(16).padStart(2,'0')).join('');}
export function configuration(batch:Batch):Configuration{return ConfigurationSchema.parse(Object.fromEntries(Object.keys(ConfigurationSchema.shape).map(k=>[k,batch[k as keyof Batch]])));}
export function selectMaximum(manifest:Source[],pairs:Record<string,Decision>):number[]{
 const n=manifest.length;if(n<2||n>6||Object.keys(pairs).length!==n*(n-1)/2)throw Error('The complete relation matrix is required');let best:number[]=[];
 for(let mask=0;mask<(1<<n);mask++){const subset=Array.from({length:n},(_,i)=>i).filter(i=>mask&(1<<i));const valid=subset.every((a,i)=>subset.slice(i+1).every(b=>manifest[a].publisher_id!==manifest[b].publisher_id&&pairs[`${a}:${b}`]?.relation==='INDEPENDENT'&&pairs[`${a}:${b}`]?.witnesses.length>0));if(valid&&subset.length>best.length)best=subset;}
 return best;
}
export function admissionStatus(batch:Batch):'eligible'|'refused'|'waiting'{if(batch.status!=='FINALIZED')return batch.unresolved&&batch.status==='UNRESOLVED'?'refused':'waiting';return !batch.unresolved&&batch.selected_subset.length>=3?'eligible':'refused';}
