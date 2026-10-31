import test from 'node:test';
import assert from 'node:assert/strict';
import {generatePrivateKey,privateKeyToAccount} from 'viem/accounts';
import {encodeFunctionData} from 'viem';
import {abi} from 'genlayer-js';
import {studionet} from 'genlayer-js/chains';
import {verifySignedOperation} from '../../apps/api/src/journal';
test('signed envelope authenticates signer, contract, method and exact args',async()=>{
 const account=privateKeyToAccount(generatePrivateKey());const contract='0x1111111111111111111111111111111111111111';const args=['assessment-operation','batch',1,0,1];
 const payload=abi.transactions.serialize([abi.calldata.encode(abi.calldata.makeCalldataObject('reserve_assessment',args,undefined)),false]);
 const data=encodeFunctionData({abi:studionet.consensusMainContract!.abi,functionName:'addTransaction',args:[account.address,contract,5n,3n,payload]});
 const raw=await account.signTransaction({chainId:61999,nonce:0,to:studionet.consensusMainContract!.address,value:0n,gas:200000n,gasPrice:0n,data});
 const expected={signer_address:account.address,contract_address:contract,method:'reserve_assessment',args};
 assert.equal(await verifySignedOperation(raw,expected),account.address);
 for(const changed of [{...expected,signer_address:contract},{...expected,method:'seal_batch'},{...expected,args:['assessment-operation','batch',1,0,2]},{...expected,contract_address:account.address}])await assert.rejects(verifySignedOperation(raw,changed));
 const noValidators=encodeFunctionData({abi:studionet.consensusMainContract!.abi,functionName:'addTransaction',args:[account.address,contract,1n,3n,payload]});
 const single=await account.signTransaction({chainId:61999,nonce:1,to:studionet.consensusMainContract!.address,value:0n,gas:200000n,gasPrice:0n,data:noValidators});await assert.rejects(verifySignedOperation(single,expected));
});
