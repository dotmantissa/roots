import {test,expect} from '@playwright/test';
test('public evidence desk, themes, navigation and live API',async({page,request})=>{
 const errors:string[]=[];page.on('pageerror',e=>errors.push(e.message));
 await page.goto('/',{waitUntil:'domcontentloaded'});await expect(page.getByRole('heading',{level:1})).toContainText('More sources.');
 await expect(page.getByRole('button',{name:'Sign in with email',exact:true})).toBeEnabled({timeout:30000});
 const records=await request.get('/api/records');expect(records.ok()).toBeTruthy();const data=await records.json();expect(Array.isArray(data.batches)).toBeTruthy();
 await page.getByRole('button',{name:'Switch to dark mode'}).click();await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
 await page.reload({waitUntil:'domcontentloaded'});await expect(page.locator('html')).toHaveAttribute('data-theme','dark');
 await page.getByRole('link',{name:'Source policies'}).click();await expect(page.getByRole('heading',{level:1})).toContainText('Set the standard.');
 await page.getByRole('link',{name:'Applications',exact:true}).click();await expect(page.getByRole('heading',{name:'Incident evidence',exact:true})).toBeVisible();await expect(page.getByRole('heading',{name:'Provider disclosure',exact:true})).toBeVisible();
 await page.getByRole('button',{name:'A field guide to Roots'}).click();await expect(page.getByRole('dialog')).toBeVisible();await page.keyboard.press('Escape');await expect(page.getByRole('dialog')).not.toBeVisible();
 await page.getByRole('link',{name:'Certificates',exact:true}).click();await expect(page.getByRole('heading',{level:1})).toContainText('Evidence, with');
 expect(errors).toEqual([]);
 await page.screenshot({path:'evidence/browser-desktop.png',fullPage:true});
});
test('small screens retain controls and avoid page overflow',async({page})=>{await page.setViewportSize({width:390,height:844});await page.goto('/',{waitUntil:'domcontentloaded'});await expect(page.getByRole('heading',{level:1})).toBeVisible();await expect(page.getByRole('button',{name:'Sign in with email',exact:true})).toBeEnabled({timeout:30000});expect(await page.evaluate(()=>document.documentElement.scrollWidth<=window.innerWidth)).toBeTruthy();await page.screenshot({path:'evidence/browser-mobile.png',fullPage:true});});
test('writes and captures require authentic email sessions',async({request})=>{for(const path of ['/api/captures','/api/operations']){const response=await request.post(path,{data:{}});expect(response.status()).toBe(401);}const forged=await request.post('/api/operations',{headers:{Authorization:'Bearer invalid'},data:{}});expect(forged.status()).toBe(401);});
