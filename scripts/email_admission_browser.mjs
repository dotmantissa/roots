// Exercise a genuine retained email session. The state file stays private.
import {chromium} from '@playwright/test';
import fs from 'node:fs/promises';
import {spawn} from 'node:child_process';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
const origin=process.env.ROOTS_PUBLIC_ORIGIN||'https://roots-evidence-federation.vercel.app';
const deployment=JSON.parse(await fs.readFile('deployments/studionet.json','utf8'));
const inputs=JSON.parse(await fs.readFile('evidence/review-v2-inputs.json','utf8'));
const file='evidence/email-admission-v2.json';
let evidence=await fs.readFile(file,'utf8').then(JSON.parse).catch(()=>({release_id:deployment.release_id,classification:'Authentic email-wallet browser signing and public authored fixture captures; controlled execution, not adoption',origin,wallet:'0x06dbBb48045c703f8869816F10Bc2ae1c43D455D',claim:'Controlled validation: independently authored public river measurements support this fixture evidence request.',consequence:'Admit this controlled fixture after the incident owner verifies source relevance.',steps:{},captures:[]}));
assert.equal(evidence.release_id,deployment.release_id);
async function save(){await fs.writeFile(file+'.tmp',JSON.stringify(evidence,null,2));await fs.rename(file+'.tmp',file);}
async function verify(step){await new Promise((resolve,reject)=>{const child=spawn('bash',['scripts/python.sh','scripts/verify_email_admission.py',step],{stdio:['ignore','inherit','inherit']});child.on('error',reject);child.on('exit',code=>code===0?resolve():reject(Error('Browser receipt verification failed: '+step)));});evidence=JSON.parse(await fs.readFile(file,'utf8'));}
for(const [step,value] of Object.entries(evidence.steps)){if(value.transaction_hash&&!value.verified)await verify(step);}
const browser=await chromium.launch();const context=await browser.newContext({storageState:process.env.ROOTS_EMAIL_STATE||'.runtime/email-browser-v2-state.json'});const page=await context.newPage();
let currentStep='',records={batches:[]};let requestError='';
page.on('response',async response=>{
 const url=new URL(response.url());
 if(url.pathname==='/api/records'&&response.ok())records=await response.json();
 if(response.request().method()!=='POST')return;
 if(url.pathname==='/api/operations'){
  const body=await response.json();const input=response.request().postDataJSON();
  if(response.ok()){assert.equal(input.signer_address.toLowerCase(),evidence.wallet.toLowerCase());evidence.steps[currentStep]={operation_id:body.operation_id,method:input.method,args:input.args};await save();}
  else requestError=body.error;
 }else if(url.pathname.endsWith('/broadcast')){
  const body=await response.json();if(response.ok()){evidence.steps[currentStep].transaction_hash=body.transaction_hash;await save();}else requestError=body.error;
 }else if(url.pathname==='/api/captures'&&response.ok()){
  const body=await response.json();assert.equal(createHash('sha256').update(body.text).digest('hex'),body.record.byte_hash);
  evidence.captures.push({record:body.record,captured_bytes_verified:true});await save();
 }
});
async function submit(step,click,dialog=false){
 if(evidence.steps[step]?.transaction_hash){if(!evidence.steps[step].verified)await verify(step);return;}
 currentStep=step;requestError='';await click();
 for(let n=0;n<120&&!evidence.steps[step]?.transaction_hash;n++){
  await page.waitForTimeout(1000);
  const error=page.locator('.error-message:visible,.error-banner:visible');if(await error.count())throw Error(await error.first().innerText());
  if(requestError)throw Error(requestError);
 }
 assert.ok(evidence.steps[step]?.transaction_hash,'No signed broadcast for '+step);
 if(dialog)await page.getByRole('dialog').waitFor({state:'hidden',timeout:30000});
 console.log('Authentic browser broadcast:',step,evidence.steps[step].transaction_hash);await verify(step);
 await fs.writeFile('.runtime/email-browser-v2-state.json',JSON.stringify(await context.storageState()),{mode:0o600});
}
async function waitRecords(predicate){for(let n=0;n<60;n++){if(predicate(records))return;await page.getByRole('button',{name:'Refresh public records',exact:true}).click();await page.waitForTimeout(5000);}throw Error('Current browser records did not reconcile');}
async function applications(){await page.getByRole('link',{name:'Applications',exact:true}).click();}
try{
 await page.goto(origin,{waitUntil:'domcontentloaded'});await page.locator('.account-button').waitFor({timeout:60000});
 if(!evidence.steps.accept?.verified){
  await applications();await page.getByRole('button',{name:'Connect authorized email wallet',exact:true}).first().click();
  await page.getByLabel('Authority action', {exact:true}).selectOption('accept_owner');
  await submit('accept',()=>page.getByRole('button',{name:'Submit authority change',exact:true}).click(),true);
 }
 await page.getByRole('link',{name:'Evidence desk',exact:true}).click();
 if(!evidence.request_id){
  await page.getByRole('button',{name:'Open source batch',exact:true}).click();const dialog=page.getByRole('dialog');
  await dialog.getByLabel('Batch name',{exact:true}).fill('Controlled email-to-admission v2');await dialog.getByLabel('Exact claim',{exact:true}).fill(evidence.claim);await dialog.getByLabel('Intended decision',{exact:true}).fill(evidence.consequence);
  for(let i=0;i<3;i++){const row=dialog.locator('.source-input').nth(i);await row.getByLabel('Publication URL',{exact:true}).fill(inputs.sources[i].publication.url);await row.getByLabel('Registered publisher',{exact:true}).selectOption(inputs.sources[i].publisher_id);await row.getByRole('button',{name:'Capture record',exact:true}).click();await row.getByRole('button',{name:'Captured',exact:true}).waitFor({timeout:45000});}
  await submit('open',()=>dialog.getByRole('button',{name:'Open source batch',exact:true}).click(),true);
 }
 await waitRecords(r=>r.batches.some(b=>b.request_id===evidence.request_id));
 await page.locator('.batch-row').filter({hasText:'Controlled email-to-admission v2'}).click();
 for(const [left,right] of [[0,1],[0,2],[1,2]]){
  const key=left+':'+right;if(evidence.batch.pairs[key])continue;
  for(let attempt=1;attempt<=3;attempt++){
   await page.getByRole('button',{name:new RegExp(inputs.sources[left].publisher_id+' and '+inputs.sources[right].publisher_id+':')}).click();
   await submit('assess-'+left+'-'+right+'-'+attempt,()=>page.getByRole('button',{name:'Assess next relationship',exact:true}).click());
   if(evidence.batch.pairs[key])break;
   await waitRecords(r=>r.batches.find(b=>b.request_id===evidence.request_id)?.attempts[key]>=attempt);
  }
  assert.equal(evidence.batch.pairs[key]?.relation,'INDEPENDENT');
  await waitRecords(r=>Boolean(r.batches.find(b=>b.request_id===evidence.request_id)?.pairs[key]));
 }
 if(!evidence.steps.seal?.verified)await submit('seal',()=>page.getByRole('button',{name:'Seal complete matrix',exact:true}).click());
 await waitRecords(r=>r.batches.find(b=>b.request_id===evidence.request_id)?.status==='SEALED');
 await applications();
 if(!evidence.steps.configure?.verified){
  await page.getByRole('button',{name:'Review a batch',exact:true}).first().click();const dialog=page.getByRole('dialog');await dialog.getByLabel('Registered batch',{exact:true}).selectOption(evidence.request_id);
  assert.equal(await dialog.getByLabel('Exact committed claim',{exact:true}).inputValue(),evidence.claim);assert.equal(await dialog.getByLabel('Exact intended decision',{exact:true}).inputValue(),evidence.consequence);
  await dialog.getByRole('checkbox').check();await submit('configure',()=>dialog.getByRole('button',{name:'Submit application request',exact:true}).click(),true);
 }
 await page.getByRole('link',{name:'Evidence desk',exact:true}).click();await page.locator('.batch-row').filter({hasText:'Controlled email-to-admission v2'}).click();
 if(!evidence.steps.deliver?.verified)await submit('deliver',()=>page.getByRole('button',{name:'Deliver certificate',exact:true}).click());
 await applications();
 if(!evidence.steps.admit?.verified){
  await page.getByRole('button',{name:'Review a batch',exact:true}).first().click();const dialog=page.getByRole('dialog');await dialog.getByLabel('Registered batch',{exact:true}).selectOption(evidence.request_id);await dialog.getByLabel('Application action',{exact:true}).selectOption('admit');await submit('admit',()=>dialog.getByRole('button',{name:'Submit application request',exact:true}).click(),true);
 }
 await page.screenshot({path:'evidence/email-admission-v2.png',fullPage:true});console.log('Complete authentic email capture → opening → consensus → owner approval → delivered acknowledgement → admission verified.');
}finally{await fs.writeFile('.runtime/email-browser-v2-state.json',JSON.stringify(await context.storageState()),{mode:0o600});await browser.close();}
