import {createClient} from 'genlayer-js';
import {studionet} from 'genlayer-js/chains';
import {verifyRequestBindings,RequestSchema,ManifestSchema,ConfigurationSchema,canonical,sha256,type Deployment,type RecordCommitment,type Configuration,type Batch} from './schema.js';
export type SignerConfig=Pick<NonNullable<Parameters<typeof createClient>[0]>,'account'|'provider'>;
export class RootsClient {
 private client:ReturnType<typeof createClient>;
 constructor(private deployment:Deployment,signer:SignerConfig={}){this.client=createClient({chain:studionet,...signer});}
 private async write(contract:keyof Deployment['contracts'],functionName:string,args:(string|number|boolean)[]){const address=this.deployment.contracts[contract]?.address;if(!address)throw Error('Missing contract binding');return await this.client.writeContract({address,functionName,args,value:0n});}
 async register_source_policy(operationId:string,policyId:string,revision:number,name:string){return this.write('source_registry','register_source_policy',[operationId,policyId,revision,canonical({name,min_origins:3,max_sources:6,unresolved_consequence:'REFUSE_ADMISSION'})]);}
 async open_batch(request:Parameters<typeof RequestSchema.parse>[0],manifest:Parameters<typeof ManifestSchema.parse>[0]){const r=RequestSchema.parse(request);const m=ManifestSchema.parse(manifest);await verifyRequestBindings(r);if(await sha256(canonical(m))!==r.manifest_digest)throw Error('Manifest commitment mismatch');return this.write('relation_docket','open_batch',[canonical(r),canonical(m)]);}
 async assess_pair(requestId:string,generation:number,left:number,right:number){return this.write('relation_docket','reserve_assessment',[crypto.randomUUID(),requestId,generation,left,right]);}
 async seal_batch(requestId:string,generation:number,subset:number[]){return this.write('relation_docket','seal_batch',[requestId,generation,canonical(subset)]);}
 async subscribe(consumer:'incident_consumer'|'disclosure_consumer',operationId:string,config:Configuration,relevanceApproved:boolean){
  const address=this.deployment.contracts[consumer]?.address;if(!address)throw Error('Missing consumer');
  const parsed=ConfigurationSchema.parse(config);const state=await this.client.readContract({address,functionName:'get_state',args:[parsed.request_id]}) as {configuration:unknown;configuration_operation:string};
  const operation=canonical(state.configuration)===canonical(parsed)&&state.configuration_operation?state.configuration_operation:operationId;
  return this.write(consumer,'configure',[operation,canonical(parsed),relevanceApproved]);
 }
 async deliver_certificate(operationId:string,certificateId:string,consumer:string){const hub=this.deployment.contracts.certificate_hub?.address;if(!hub)throw Error('Missing hub');const existing=await this.client.readContract({address:hub,functionName:'get_delivery_operation',args:[certificateId]}) as string;return this.write('certificate_hub','deliver_certificate',[existing||operationId,certificateId,consumer]);}
 async acknowledge_revision(operationId:string,requestId:string,manifest:Parameters<typeof ManifestSchema.parse>[0],deadline:string){return this.write('relation_docket','acknowledge_revision',[operationId,requestId,canonical(ManifestSchema.parse(manifest)),deadline]);}
 async correct_affiliation(operationId:string,publisherId:string,record:RecordCommitment,quarantine=false){return this.write('source_registry','correct_affiliation',[operationId,publisherId,canonical(record),quarantine]);}
 async nominate_publisher_principal(publisherId:string,principal:string){return this.write('source_registry','nominate_principal',[publisherId,principal]);}
 async accept_publisher_principal(publisherId:string){return this.write('source_registry','accept_principal',[publisherId]);}
 async recover_publisher(operationId:string,publisherId:string,principal:string,record:RecordCommitment){return this.write('source_registry','recover_principal',[operationId,publisherId,principal,canonical(record)]);}
 async nominate_consumer_owner(consumer:'incident_consumer'|'disclosure_consumer',principal:string){return this.write(consumer,'nominate_owner',[principal]);}
 async accept_consumer_owner(consumer:'incident_consumer'|'disclosure_consumer'){return this.write(consumer,'accept_owner',[]);}
 async authorize_requester(principal:string,quota:number){return this.write('relation_docket','authorize_requester',[principal,quota]);}
 async get_batch(requestId:string):Promise<Batch>{const address=this.deployment.contracts.relation_docket?.address;if(!address)throw Error('Missing docket');return await this.client.readContract({address,functionName:'get_batch',args:[requestId]}) as Batch;}
 async admit(consumer:'incident_consumer'|'disclosure_consumer',operationId:string,requestId:string,subjectDigest:string,consequenceDigest:string){return this.write(consumer,consumer==='incident_consumer'?'admit_incident':'admit_disclosure',[operationId,requestId,subjectDigest,consequenceDigest]);}
}
