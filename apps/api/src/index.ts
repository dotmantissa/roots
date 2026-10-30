import app from './http.js';
import {env} from './config.js';
await app.listen({port:env.PORT,host:'0.0.0.0'});
