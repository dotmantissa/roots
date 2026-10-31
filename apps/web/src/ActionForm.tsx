import {useState} from 'react';
import {api} from './api';
import {Dialog} from './components';
import {canonical,configuration,sha256,verifyRequestBindings,type Batch,type Deployment} from '../../../packages/sdk/src/schema';
import type {useTransactions} from './useTransactions';
export function ActionForm({batches,address,deployment,write,onClose,onDone}:{batches:Batch[];address:string|undefined;deployment:Deployment;write:ReturnType<typeof useTransactions>['write'];onClose:()=>void;onDone:()=>void}){
 const [id,setId]=useState(batches[0]?.request_id||'');const [action,setAction]=useState('configure');const [reviewed,setReviewed]=useState(false);const [pending,setPending]=useState(false);const [error,setError]=useState('');const batch=batches.find(b=>b.request_id===id);
 const kind=batch?.consumer.toLowerCase()===deployment.contracts.incident_consumer?.address.toLowerCase()?'incident_consumer':'disclosure_consumer';const owner=deployment.owners[kind==='incident_consumer'?'incident':'disclosure'];const authorized=owner?.toLowerCase()===address?.toLowerCase();
 return <Dialog title="Approve an exact application request" onClose={onClose}><form className="simple-form" onSubmit={async e=>{e.preventDefault();if(!batch)return;setPending(true);setError('');try{
  await verifyRequestBindings(batch);const config=configuration(batch);
  if(action==='configure'){
   if(!reviewed)throw Error('Review the exact claim, decision and every source before approving relevance');
   const state=await api<{configuration:unknown;configuration_operation:string}>(`/consumer-state/${kind}/${encodeURIComponent(batch.request_id)}`);
   const operation=canonical(state.configuration)===canonical(config)&&state.configuration_operation?state.configuration_operation:'configure-'+(await sha256(canonical(config))).slice(0,64);
   // A new API journal can re-emit the same authenticated contract operation.
   await write(kind,'configure',[operation,canonical(config),true]);
  }else{
   const state=await api<{configuration:unknown}>(`/consumer-state/${kind}/${encodeURIComponent(batch.request_id)}`);
   if(canonical(state.configuration)!==canonical(config))throw Error('Approve this generation before admission');
   await write(kind,kind==='incident_consumer'?'admit_incident':'admit_disclosure',[crypto.randomUUID(),batch.request_id,batch.subject_digest,batch.consequence_digest]);
  }
  onDone();
 }catch(e){setError((e as Error).message);}finally{setPending(false);}}}>
 <p>Certificates establish document ancestry. The application owner must separately verify that each admitted publication concerns the exact claim and intended decision. Claim truth remains an application responsibility.</p>
 <label>Registered batch<select required value={id} onChange={e=>{setId(e.target.value);setReviewed(false);}}><option value="" disabled>Choose a batch</option>{batches.map(b=><option key={b.request_id} value={b.request_id}>{b.subject_id} / Revision {b.generation}</option>)}</select></label>
 <label>Application action<select value={action} onChange={e=>setAction(e.target.value)}><option value="configure">Approve configuration or retry subscription</option><option value="admit">Admit using delivered certificate</option></select></label>
 {batch&&<><label>Exact committed claim<textarea readOnly value={batch.subject_text}/></label><label>Exact intended decision<textarea readOnly value={batch.consequence_text}/></label><p>Policy {batch.policy_id}, revision {batch.policy_revision}. Claim digest {batch.subject_digest}. Decision digest {batch.consequence_digest}.</p>{batch.manifest.map((s,i)=><div className="source-input" key={s.publication.record_id}><strong>Source {i+1}: {s.publisher_id}</strong><a href={s.publication.url} target="_blank" rel="noreferrer">Inspect original publication {i+1}</a><a href={s.publication.capture_url} target="_blank" rel="noreferrer">Inspect committed capture {i+1}</a><a href={s.ownership.url} target="_blank" rel="noreferrer">Inspect ownership disclosure {i+1}</a></div>)}{action==='configure'&&<label><input type="checkbox" checked={reviewed} onChange={e=>setReviewed(e.target.checked)}/> I reviewed every publication and confirm its relevance to this exact claim and intended decision.</label>}</>}
 {!authorized&&<p className="form-note">This request must be signed by application owner {owner}. Accept an authorized wallet nomination in Applications to connect your email account.</p>}
 {error&&<p className="error-message" role="alert">{error}</p>}<div className="dialog-footer"><span>Finalized delivery and owner relevance review required.</span><button className="button" disabled={pending||!batch||!authorized||action==='configure'&&!reviewed}>Submit application request</button></div>
 </form></Dialog>;
}
