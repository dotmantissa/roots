import {readFile} from 'node:fs/promises';
import {monitorSources} from './source-monitor.js';
import {reconcile} from './reconciliation.js';
import {indexRecords} from './indexer.js';
import type {Deployment} from '../../../packages/sdk/src/schema.js';
const deployment=JSON.parse(await readFile('deployments/studionet.json','utf8')) as Deployment;
if(process.argv.includes('--rebuild')){await indexRecords(deployment,true);console.log('Contract records rebuilt');}
else {let stopping=false;process.on('SIGTERM',()=>{stopping=true;});process.on('SIGINT',()=>{stopping=true;});while(!stopping){try{await reconcile();await indexRecords(deployment);await monitorSources(deployment);}catch{console.error('Worker cycle interrupted. The saved checkpoint will resume next cycle');}await new Promise(r=>setTimeout(r,60000));}}
