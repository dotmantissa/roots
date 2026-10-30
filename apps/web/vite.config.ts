import {defineConfig} from 'vite';
import react from '@vitejs/plugin-react';
export default defineConfig({root:'apps/web',envDir:'../..',plugins:[react()],build:{outDir:'../../dist/web',emptyOutDir:true,rollupOptions:{onwarn(warning,warn){if(warning.code==='INVALID_ANNOTATION')return;warn(warning);}}},server:{host:'0.0.0.0',port:5173,proxy:{'/api':'http://localhost:3911'}}});
