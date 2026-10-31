import {createClient} from 'genlayer-js';
import {studionet} from 'genlayer-js/chains';
import {BatchSchema,PolicySchema,PublisherSchema,type Deployment,type Batch} from './schema.js';
export async function withinDeadline<T>(work:()=>Promise<T>,milliseconds=8000):Promise<T>{
 let timer:ReturnType<typeof setTimeout>|undefined;
 try{return await Promise.race([work(),new Promise<never>((_resolve,reject)=>{timer=setTimeout(()=>reject(Error('Network request timed out; saved operations remain recoverable')),milliseconds);})]);}
 finally{clearTimeout(timer);}
}
export const networkClient=()=>{
 const client=createClient({chain:studionet});
 // The SDK transport currently has no timeout. Bound worker-facing actions,
 // while preserving signed bytes in the operation journal before any send.
 return new Proxy(client,{get(target,key){const value=Reflect.get(target,key);return ['request','readContract','getTransaction','sendRawTransaction'].includes(String(key))&&typeof value==='function'? (...args:unknown[])=>withinDeadline(()=>value.apply(target,args)):value;}});
};
export async function readPage(deployment:Deployment,contract:keyof Deployment['contracts'],method:string,args:unknown[]):Promise<{total:number;items:unknown[]}>{
 const address=deployment.contracts[contract]?.address;if(!address)throw Error('Contract deployment is unavailable');
 return await networkClient().readContract({address,functionName:method,args:args as (string|number)[]}) as {total:number;items:unknown[]};
}
export async function readAllPages(d:Deployment,contract:keyof Deployment['contracts'],method:string,prefix:unknown[]=[],reader:typeof readPage=readPage):Promise<unknown[]>{
 const items:unknown[]=[];let offset=0;let total=0;
 do{
  const page=await reader(d,contract,method,[...prefix,offset,50]);
  if(!Number.isSafeInteger(page.total)||page.total<0||page.total>8192||!Array.isArray(page.items)||page.items.length>50||page.items.length===0&&offset<page.total)throw Error('Invalid public feed continuation');
  total=page.total;items.push(...page.items);offset+=page.items.length;
 }while(offset<total);
 return items;
}
export async function fetchPublicRecords(d:Deployment,reader:typeof readPage=readPage):Promise<{batches:Batch[];certificates:Batch[];policies:ReturnType<typeof PolicySchema.parse>[];publishers:ReturnType<typeof PublisherSchema.parse>[]} >{
 const [b,c,p,s]=await Promise.all([readAllPages(d,'relation_docket','list_batches',[],reader),readAllPages(d,'certificate_hub','list_certificates',[],reader),readAllPages(d,'source_registry','list_records',['policies'],reader),readAllPages(d,'source_registry','list_records',['publishers'],reader)]);
 return {batches:b.map(x=>BatchSchema.parse(x)),certificates:c.map(x=>BatchSchema.parse(x)),policies:p.map(x=>PolicySchema.parse(x)),publishers:s.map(x=>PublisherSchema.parse(x))};
}
