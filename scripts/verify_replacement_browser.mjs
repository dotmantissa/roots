// Verify recovery controls using the authentic owner session without changing
// the admitted batch. Capture requests are real; no successor is submitted.
import {chromium} from '@playwright/test';
import fs from 'node:fs/promises';
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';

const origin=process.env.ROOTS_PUBLIC_ORIGIN||'https://roots-evidence-federation.vercel.app';
const email=JSON.parse(await fs.readFile('evidence/email-admission-v2.json','utf8'));
assert.ok(email.complete_email_to_admission);
const browser=await chromium.launch();
const context=await browser.newContext({storageState:'.runtime/email-browser-v2-state.json'});
const page=await context.newPage();
try{
 await page.goto(origin,{waitUntil:'domcontentloaded'});
 await page.locator('.account-button').waitFor({timeout:60000});
 await page.locator('.batch-row').filter({hasText:'Controlled email-to-admission v2'}).click({timeout:60000});
 await page.getByRole('button',{name:'Review replacement evidence',exact:true}).click();
 const dialog=page.getByRole('dialog');
 await dialog.getByText(email.claim,{exact:false}).waitFor();
 const url=dialog.getByLabel('Replacement publication URL 1',{exact:true});
 const submit=dialog.getByRole('button',{name:'Open successor revision',exact:true});
 assert.equal(await url.inputValue(),email.batch.manifest[0].publication.url);
 assert.ok(await submit.isDisabled());
 const original=email.batch.manifest[0].publication.url;
 const replacement=origin+new URL(original).pathname;
 await url.fill(replacement);
 assert.ok(await submit.isDisabled(),'An edited URL must be captured first');
 const captured=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/captures'&&r.request().method()==='POST');
 await dialog.getByRole('button',{name:'Capture replacement source 1',exact:true}).click();
 const response=await captured;assert.ok(response.ok());const body=await response.json();
 assert.equal(body.record.url,replacement);
 assert.equal(body.record.revision,email.batch.manifest[0].publication.revision+1);
 assert.equal(createHash('sha256').update(body.text).digest('hex'),body.record.byte_hash);
 assert.equal(body.record.byte_hash,email.batch.manifest[0].publication.byte_hash);
 for(let i=0;i<45&&await submit.isDisabled();i++)await page.waitForTimeout(1000);
 assert.ok(await submit.isEnabled(),'A captured replacement host must be reviewable');
 await url.fill(replacement+'?changed-after-capture');
 assert.ok(await submit.isDisabled(),'Capture must match the currently displayed URL');
 await url.fill(original);
 const unchanged=page.waitForResponse(r=>new URL(r.url()).pathname==='/api/captures'&&r.request().method()==='POST');
 await dialog.getByRole('button',{name:'Capture replacement source 1',exact:true}).click();
 assert.ok((await unchanged).ok());
 await dialog.getByRole('button',{name:'Capture replacement source 1',exact:true}).waitFor({state:'visible'});
 await page.waitForTimeout(1000);
 assert.ok(await submit.isDisabled(),'Unchanged source bytes and URL cannot buy a revision');
 await page.screenshot({path:'evidence/replacement-browser-v2.png',fullPage:true});
 await fs.writeFile('evidence/replacement-browser-v2.json',JSON.stringify({release_id:email.release_id,classification:'Authentic consumer-owner browser controls and actual public captures; no successor transaction submitted',origin,request_id:email.request_id,finalized_owner_can_open_recovery:true,edited_url_requires_capture:true,captured_replacement_host_enabled:true,changed_url_invalidates_capture:true,unchanged_capture_cannot_reset_revision:true,replacement_capture:body.record},null,2));
 console.log('Authenticated finalized-batch URL recovery and capture controls verified.');
}finally{await browser.close();}
