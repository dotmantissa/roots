import {getIdentityToken} from '@privy-io/react-auth';
export async function api<T>(path:string,body?:unknown,authenticated=false):Promise<T>{
 const token=authenticated?await getIdentityToken():null;
 const response=await fetch('/api'+path,{method:body===undefined?'GET':'POST',headers:{...(body!==undefined?{'Content-Type':'application/json'}:{}),...(token?{Authorization:'Bearer '+token}:{})},...(body!==undefined?{body:JSON.stringify(body)}:{})});
 const data=await response.json();if(!response.ok)throw Error(data.error||'Something interrupted that request. Please try again');return data as T;
}
