import {PrivyClient} from '@privy-io/node';
import type {FastifyRequest} from 'fastify';
import {env} from './config';
const privy=new PrivyClient({appId:env.PRIVY_APP_ID,appSecret:env.PRIVY_APP_SECRET});
export async function authenticate(req:FastifyRequest){
 const header=req.headers.authorization;if(!header?.startsWith('Bearer '))throw Object.assign(Error('Sign in with your email to continue'),{statusCode:401});
 const user=await privy.utils().auth().verifyIdentityToken(header.slice(7)).catch(()=>{throw Object.assign(Error('Your session has expired. Please sign in again'),{statusCode:401});});
 if(!user.linked_accounts.some(a=>a.type==='email'))throw Object.assign(Error('An email account is required'),{statusCode:403});
 const addresses=user.linked_accounts.filter(a=>a.type==='wallet'&&'wallet_client_type'in a&&a.wallet_client_type==='privy'&&'chain_type'in a&&a.chain_type==='ethereum').map(a=>'address'in a?String(a.address).toLowerCase():'');
 return {id:user.id,addresses};
}
