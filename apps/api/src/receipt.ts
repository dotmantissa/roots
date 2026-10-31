export type NetworkReceipt={statusName?:string;status_name?:string;status:number|string;result_name?:string;resultName?:string;triggered_transactions?:string[];triggeredTransactions?:string[];consensus_data?:{leader_receipt?:{mode:string;execution_result:string}[];votes?:Record<string,string>};consensusData?:{leaderReceipt?:{mode:string;executionResult:string}[];votes?:Record<string,string>}};
export function receiptState(data:NetworkReceipt){
 const status=data.statusName||data.status_name||(typeof data.status==='string'?data.status:data.status===7?'FINALIZED':data.status===5?'ACCEPTED':'PENDING');
 const leader=data.consensus_data?.leader_receipt?.find(r=>r.mode==='leader');const camel=data.consensusData?.leaderReceipt?.find(r=>r.mode==='leader');
 const majority=data.result_name||data.resultName;
 const success=leader?majority==='MAJORITY_AGREE'&&leader.execution_result==='SUCCESS':camel?majority==='MAJORITY_AGREE'&&camel.executionResult==='SUCCESS':null;
 const votes=data.consensus_data?.votes||data.consensusData?.votes||{};
 return {status,success,disagreements:Object.values(votes).filter(x=>x.toLowerCase()==='disagree').length,children:data.triggered_transactions||data.triggeredTransactions||[]};
}
export function retryDelay(attempt:number):number{return Math.min(300,5*2**Math.min(attempt,6));}
