import {neon} from '@neondatabase/serverless';
import {env} from './config';
export const sql=neon(env.DATABASE_URL);
