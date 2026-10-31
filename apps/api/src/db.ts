import {neon,neonConfig} from '@neondatabase/serverless';
import {setDefaultAutoSelectFamily} from 'node:net';
import {setDefaultResultOrder} from 'node:dns';
import {env} from './config.js';
if(process.env.ROOTS_IPV4_NETWORK==='true'){setDefaultAutoSelectFamily(false);setDefaultResultOrder('ipv4first');}
// Use the project SQL endpoint, avoiding reliance on a separate regional API
// hostname. The original connection string still authenticates every query.
const databaseHost=new URL(env.DATABASE_URL).hostname;
if(databaseHost.endsWith('.neon.tech'))neonConfig.fetchEndpoint=()=>`https://${databaseHost.replace('-pooler','')}/sql`;
export const sql=neon(env.DATABASE_URL);
