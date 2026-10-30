import {decodeFunctionData,parseTransaction,recoverTransactionAddress,type Hex,type TransactionSerialized} from 'viem';
import {decodeInputData} from 'genlayer-js';
import {studionet} from 'genlayer-js/chains';
import {canonical} from '../../../packages/sdk/src/schema';
export async function verifySignedOperation(raw:Hex,expected:{signer_address:string;contract_address:string;method:string;args:unknown[]}){
 const tx=parseTransaction(raw);const signer=await recoverTransactionAddress({serializedTransaction:raw as TransactionSerialized});
 if(signer.toLowerCase()!==expected.signer_address.toLowerCase()||tx.chainId!==61999||tx.to?.toLowerCase()!==studionet.consensusMainContract!.address.toLowerCase()||tx.value!==0n)throw Error('Signed transaction does not match the approved operation');
 const decoded=decodeFunctionData({abi:studionet.consensusMainContract!.abi,data:tx.data!});
 const args=decoded.args as unknown[];
 if(decoded.functionName!=='addTransaction'||String(args[0]).toLowerCase()!==signer.toLowerCase()||String(args[1]).toLowerCase()!==expected.contract_address.toLowerCase()||Number(args[2])<3)throw Error('Consensus transaction binding mismatch');
 const call=decodeInputData(args[4] as Hex,args[1] as Hex);
 if(!call||call.type!=='call'||call.leaderOnly||!('callData'in call))throw Error('A validated contract write is required');
 const data=call.callData as {method?:string;args?:unknown[]};
 if(data.method!==expected.method||canonical(data.args??[])!==canonical(expected.args))throw Error('Signed method or arguments differ from your approved request');
 return signer;
}
