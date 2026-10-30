import {neon} from '@neondatabase/serverless';
import {env} from './config.js';
export const sql=neon(env.DATABASE_URL);
