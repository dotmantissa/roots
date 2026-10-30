import type {IncomingMessage,ServerResponse} from 'node:http';
import app from '../apps/api/src/http.js';
await app.ready();
export default function handler(request:IncomingMessage,response:ServerResponse){app.server.emit('request',request,response);}
