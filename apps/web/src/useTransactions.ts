import {useSignTransaction,useWallets} from '@privy-io/react-auth';
import {createClient} from 'genlayer-js';
import {studionet} from 'genlayer-js/chains';
import type {UnsignedTransactionRequest} from '@privy-io/react-auth';
import {api} from './api';
import type {Deployment} from '../../../packages/sdk/src/schema';
export type Operation={operation_id:string;method:string;transaction_hash:string|null;status:string;execution_success:boolean|null;delivery_status?:string|null;callback_status?:string|null;needs_attention?:boolean;created_at:string};
export function useTransactions(deployment:Deployment|null){
 const {wallets}=useWallets();const {signTransaction}=useSignTransaction();const wallet=wallets.find(w=>w.walletClientType==='privy');
 async function write(contract:keyof Deployment['contracts'],method:string,args:(string|number|boolean)[],operationId:string=crypto.randomUUID()){
  if(!wallet)throw Error('Your account is still getting ready. Try again in a moment');
  const address=deployment?.contracts[contract]?.address;if(!address)throw Error('The application is waiting for its contract connection');
  const prepared=await api<{transaction_hash?:`0x${string}`}>('/operations',{operation_id:operationId,signer_address:wallet.address,contract,method,args},true);
  if(prepared.transaction_hash)return prepared.transaction_hash;
  // Intercept the SDK broadcast so signed bytes reach the journal before the network.
  const provider={request:async({method:rpcMethod,params}:{method:string;params?:unknown})=>{
   if(rpcMethod==='eth_accounts'||rpcMethod==='eth_requestAccounts')return [wallet.address];
   if(rpcMethod!=='eth_sendTransaction')throw Error('Unexpected signing request');
   const raw=(params as Record<string,string>[])[0];
   const transaction:UnsignedTransactionRequest={from:wallet.address,to:raw.to,data:raw.data,nonce:Number(BigInt(raw.nonce)),gasLimit:raw.gas,gasPrice:raw.gasPrice,value:raw.value,chainId:Number(BigInt(raw.chainId)),type:0};
   const {signature}=await signTransaction(transaction,{address:wallet.address,uiOptions:{showWalletUIs:false}});
   const result=await api<{transaction_hash:`0x${string}`}>(`/operations/${operationId}/broadcast`,{signed_transaction:signature},true);
   return result.transaction_hash;
  }};
  const client=createClient({chain:studionet,account:wallet.address as `0x${string}`,provider});
  return await client.writeContract({address,functionName:method,args,value:0n});
 }
 return {write,address:wallet?.address};
}
