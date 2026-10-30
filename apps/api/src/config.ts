import 'dotenv/config';
import {z} from 'zod';
export const env=z.object({PRIVY_APP_ID:z.string().min(1),PRIVY_APP_SECRET:z.string().min(1),DATABASE_URL:z.string().min(1),PORT:z.coerce.number().default(3911),WEB_ORIGIN:z.url().default('http://localhost:5173'),CAPTURE_ORIGIN:z.url().default('http://localhost:3911')}).parse(process.env);
