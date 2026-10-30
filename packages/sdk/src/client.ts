import {createClient} from 'genlayer-js';
import {studionet} from 'genlayer-js/chains';
import {BatchSchema,PolicySchema,PublisherSchema,type Deployment,type Batch} from './schema';
export const networkClient=()=>createClient({chain:studionet});
export async function readPage(deployment:Deployment,contract:keyof Deployment['contracts'],method:string,args:unknown[]):Promise<{total:number;items:unknown[]}>{
 const address=deployment.contracts[contract]?.address;if(!address)throw Error('Contract deployment is unavailable');
 return await networkClient().readContract({address,functionName:method,args:args as (string|number)[]}) as {total:number;items:unknown[]};
}
export async function fetchPublicRecords(d:Deployment):Promise<{batches:Batch[];certificates:Batch[];policies:ReturnType<typeof PolicySchema.parse>[];publishers:ReturnType<typeof PublisherSchema.parse>[]} >{
 const [b,c,p,s]=await Promise.all([readPage(d,'relation_docket','list_batches',[0,50]),readPage(d,'certificate_hub','list_certificates',[0,50]),readPage(d,'source_registry','list_records',['policies',0,50]),readPage(d,'source_registry','list_records',['publishers',0,50])]);
 return {batches:b.items.map(x=>BatchSchema.parse(x)),certificates:c.items.map(x=>BatchSchema.parse(x)),policies:p.items.map(x=>PolicySchema.parse(x)),publishers:s.items.map(x=>PublisherSchema.parse(x))};
}
