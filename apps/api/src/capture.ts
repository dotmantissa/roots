import {lookup} from 'node:dns/promises';
import {isIP} from 'node:net';
import {createHash} from 'node:crypto';
import https from 'node:https';
import type {RecordCommitment} from '../../../packages/sdk/src/schema.js';
export function forbiddenAddress(ip:string):boolean {
 if(isIP(ip)===4){const p=ip.split('.').map(Number);return p[0]===0||p[0]===10||p[0]===127||p[0]>=224||p[0]===169&&p[1]===254||p[0]===172&&p[1]>=16&&p[1]<=31||p[0]===192&&p[1]===168||p[0]===100&&p[1]>=64&&p[1]<=127||p[0]===198&&(p[1]===18||p[1]===19);}
 return !isIP(ip)||ip==='::1'||ip==='::'||ip.toLowerCase().startsWith('fc')||ip.toLowerCase().startsWith('fd')||ip.toLowerCase().startsWith('fe80')||ip.toLowerCase().startsWith('::ffff:');
}
export async function retrieve(urlString:string):Promise<{bytes:Buffer;mediaType:string}>{
 const url=new URL(urlString);if(url.protocol!=='https:'||url.username||url.password||url.port&&url.port!=='443')throw Error('Use a public HTTPS source');
 const records=await lookup(url.hostname,{all:true});if(!records.length||records.some(r=>forbiddenAddress(r.address)))throw Error('This address is not a public source');
 const pinned=records[0];
 return await new Promise((resolve,reject)=>{
  const req=https.get(url,{family:pinned.family,headers:{'User-Agent':'Roots evidence capture/0.1','Accept-Encoding':'identity'},lookup:(_hostname,options,callback)=>{if(options.all)callback(null,[pinned]);else callback(null,pinned.address,pinned.family);}},response=>{
   if(response.statusCode!==200){response.resume();reject(Error('The source did not return a public document. Redirects are refused'));return;}
   if(Number(response.headers['content-length']||0)>49152){response.destroy();reject(Error('Source exceeds the 48 KiB record limit'));return;}
   const chunks:Buffer[]=[];let size=0;
   response.on('data',(chunk:Buffer)=>{size+=chunk.length;if(size>49152){response.destroy();reject(Error('Source exceeds the 48 KiB record limit'));}else chunks.push(chunk);});
   response.on('error',reject);response.on('end',()=>{const bytes=Buffer.concat(chunks);try{new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{reject(Error('Use a UTF 8 text document'));return;}if(!bytes.length){reject(Error('This document is empty'));return;}resolve({bytes,mediaType:String(response.headers['content-type']||'text/plain')});});
  });req.setTimeout(15000,()=>req.destroy(Error('The source took too long to respond')));req.on('error',reject);
 });
}
export function commitRecord(input:{record_id:string;authority:string;url:string;scope:string;revision:number},bytes:Buffer,captureOrigin:string):RecordCommitment{
 const hash=createHash('sha256').update(bytes).digest('hex');
 return {...input,channel:'public',capture_url:captureOrigin.startsWith('https://')?captureOrigin+'/api/captures/'+hash:input.url,byte_hash:hash,byte_length:bytes.length,spans:[{span_id:'complete',start:0,end:bytes.length,quote_hash:hash}]};
}
