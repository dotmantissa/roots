import {readFile} from 'node:fs/promises';
import {sql} from './db';
const schema=await readFile(new URL('../schema.sql',import.meta.url),'utf8');
for(const statement of schema.split(';').map(x=>x.trim()).filter(Boolean))await sql.query(statement);
console.log('Roots database schema is ready');
