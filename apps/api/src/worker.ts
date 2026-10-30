import {readFile} from 'node:fs/promises';
import {reconcile} from './reconciliation';
import {indexRecords} from './indexer';
import type {Deployment} from '../../../packages/sdk/src/schema';
const deployment=JSON.parse(await readFile('deployments/studionet.json','utf8')) as Deployment;
if(process.argv.includes('--rebuild')){await indexRecords(deployment,true);console.log('Contract records rebuilt');}
else {let stopping=false;process.on('SIGTERM',()=>{stopping=true;});process.on('SIGINT',()=>{stopping=true;});while(!stopping){try{await reconcile();await indexRecords(deployment);}catch{console.error('Worker cycle interrupted. The saved checkpoint will resume next cycle');}await new Promise(r=>setTimeout(r,30000));}}
