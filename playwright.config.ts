import {defineConfig} from '@playwright/test';
export default defineConfig({testDir:'tests/browser',use:{baseURL:process.env.BASE_URL||'http://localhost:5173',browserName:'chromium',headless:true},workers:1,reporter:'list',timeout:60000});
