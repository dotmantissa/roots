import test from 'node:test';
import assert from 'node:assert/strict';
import {Id,PublicUrl,canonical,sha256,verifyRequestBindings,batchCommitment,RequestSchema,configuration,type Batch,type Deployment} from '../../packages/sdk/src/schema';
import {RootsClient} from '../../packages/sdk/src/roots';
import {readAllPages,withinDeadline,type readPage} from '../../packages/sdk/src/client';
import {recordId,currentIndexedRecords} from '../../packages/sdk/src/records';
import {receiptState,retryDelay} from '../../apps/api/src/receipt';
const deployment:Deployment={network:'studionet',rpc:'unused',chain_id:61999,runner:'pinned',owners:{},contracts:{relation_docket:{address:'0x1111111111111111111111111111111111111111',source_hash:'a'.repeat(64),deployment_transaction:'0x1'}}};
test('an unavailable RPC cannot occupy reconciliation indefinitely',async()=>{
 await assert.rejects(withinDeadline(()=>new Promise(()=>{}),10),/timed out/);
 assert.equal(await withinDeadline(async()=>42,100),42);
 await assert.rejects(withinDeadline(async()=>{throw Error('quota');},100),/quota/);
});
test('successful paginated RPC feeds include entries past fifty and handle growth',async()=>{
 const calls:unknown[][]=[];const reader:typeof readPage=async(_d,_c,_m,args)=>{calls.push(args);const offset=Number(args.at(-2));const total=offset===0?103:104;return {total,items:Array.from({length:Math.min(50,total-offset)},(_,i)=>offset+i)};};
 const items=await readAllPages(deployment,'relation_docket','list_batches',[],reader);
 assert.equal(items.length,104);assert.equal(items[103],103);assert.deepEqual(calls,[[0,50],[50,50],[100,50]]);
 await assert.rejects(readAllPages(deployment,'relation_docket','list_batches',[],async()=>({total:51,items:[]})),/continuation/);
});
test('index continuation uses a stable request key and removes legacy duplicates from fallback',()=>{
 const address=deployment.contracts.relation_docket!.address;const first={request_id:'one',generation:1,certificate_id:'',status:'PROVISIONAL'};const sealed={...first,certificate_id:'one:1',status:'SEALED'};const next={...first,generation:2,certificate_id:'one:2',status:'SEALED'};
 const continuation=new Map<string,unknown>();for(const record of [first,sealed,next])continuation.set(recordId('batches',record),record);
 assert.deepEqual([...continuation.values()],[next]);assert.equal(recordId('history',next),'one:2');assert.equal(recordId('certificates',next),'one:2');
 const rows=[first,sealed,next].map(payload=>({contract_address:address,record_kind:'batches',payload}));rows.push({contract_address:('0x'+'9'.repeat(40)) as `0x${string}`,record_kind:'batches',payload:{...next,request_id:'obsolete-deployment'}});
 assert.deepEqual(currentIndexedRecords(rows,deployment).batches,[next]);
});
test('SDK and contract boundaries count UTF-8 bytes and reject private literal URLs',()=>{
 assert.equal(Id.safeParse('é'.repeat(64)).success,true);assert.equal(Id.safeParse('é'.repeat(65)).success,false);
 for(const url of ['https://10.0.0.1:8443/data','https://127.0.0.1/a','https://[::1]/','https://good.org:444/a','https://good.org\\@evil.org/a','https://good.org/#a','https://good.org@evil.org/a'])assert.equal(PublicUrl.safeParse(url).success,false,url);
 assert.equal(PublicUrl.safeParse('https://good.org:443/a?b=c').success,true);
});
test('approval retains exact preimages and uses the same complete commitment on successors',async()=>{
 const claim='An exact public river claim';const consequence='Review its relevant original publications';
 const request=RequestSchema.parse({request_id:'one',owner:'0x'+'1'.repeat(40),parties:['0x'+'1'.repeat(40)],policy_id:'p',policy_revision:1,subject_id:'river',subject_text:claim,subject_digest:await sha256(claim),manifest_digest:'a'.repeat(64),consumer:'0x'+'2'.repeat(40),consequence_text:consequence,consequence_digest:await sha256(consequence),admission_scope:'DOCUMENT_ANCESTRY',generation:1,deadline:'2099-01-01T00:00:00Z'});
 await verifyRequestBindings(request);await assert.rejects(verifyRequestBindings({...request,subject_text:'Unrelated hidden text'}),/commitment/);
 const initial=await batchCommitment(request);assert.notEqual(await batchCommitment({...request,generation:2}),initial);assert.notEqual(await batchCommitment({...request,parties:[]}),initial);
 assert.equal(initial,await sha256(canonical({version:2,request})));
 const d={...deployment,contracts:{...deployment.contracts,incident_consumer:deployment.contracts.relation_docket}};
 const sdk=new RootsClient(d);const config=configuration(request as Batch);const calls:{args:unknown[]}[]=[];
 Object.defineProperty(sdk,'client',{value:{readContract:async()=>({configuration:config,configuration_operation:'approved-in-another-client'}),writeContract:async(call:{args:unknown[]})=>{calls.push(call);return '0x1';}}});
 await sdk.subscribe('incident_consumer','new-client-operation',config,true);
 await sdk.subscribe('incident_consumer','successor-operation',{...config,generation:2},true);
 assert.equal(calls[0].args[0],'approved-in-another-client');assert.equal(calls[1].args[0],'successor-operation');
});
test('receipt parsing distinguishes finalized disagreement from successful execution in both RPC formats',()=>{
 const snake={status:7,result_name:'MAJORITY_AGREE',consensus_data:{leader_receipt:[{mode:'leader',execution_result:'SUCCESS'}]}};assert.equal(receiptState(snake).success,true);
 assert.equal(receiptState({...snake,result_name:'MAJORITY_DISAGREE'}).success,false);
 assert.equal(receiptState({status:7}).success,null);
 const camel={status:7,statusName:'FINALIZED',resultName:'MAJORITY_AGREE',consensusData:{leaderReceipt:[{mode:'leader',executionResult:'SUCCESS'}]}};assert.equal(receiptState(camel).success,true);
 assert.equal(retryDelay(100),300);assert.ok(retryDelay(1)>0);assert.ok(retryDelay(12)>retryDelay(1));
});
