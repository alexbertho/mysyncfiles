// Atlas UI regressions with an isolated, simulated backend. Real TPM proofs,
// cookie isolation and server authorization are covered by the Rust suites.
// NODE_PATH=/path/to/node_modules node tests/web_files_browser.cjs
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const {chromium, firefox} = require("playwright");
const origin = "https://sync.example.test";
const root = path.join(__dirname, "../web");
const csp = fs.readFileSync(path.join(__dirname, "../src/server/web_status.rs"), "utf8").match(/const CSP: &str = "([^"]+)"/)[1];
const id = "a".repeat(64);
const screenshotDir = process.env.MYSYNC_SCREENSHOTS;
const content = Buffer.from("A verified file.\n");
const digest = crypto.createHash("sha256").update(content).digest("hex");
const fixtureTime = Date.parse("2026-10-01T10:00:00Z")/1000;
const file = (name, size = content.length, revision = 1) => ({kind:"file", path:name, size, revision, sha256:digest, updated_at:fixtureTime+revision*60});
const fixtures = [
  file("Configurations/client.example.json",2048,6), file("Configurations/server.example.toml",2048,5), file("Documentation/configuration-du-client.pdf",612*1024,8),
  file("Projets/AgentSync/config.rs",7168,14), file("Versions/release.txt"),
  file("CHANGELOG.md",14*1024,12), file("Cargo.lock",86*1024,9), file("Cargo.toml",2048,16), file("LICENSE",35*1024),
  file("README.md",9216,24), file("architecture-technique.pdf",824*1024,18), file("configuration.example.toml",3072,7), file("notes-de-version.txt",6144,11),
];
function listing(entries, query) {
  const search=query.get("search") || "", directory=query.get("directory") || "", after=query.get("after") || "";
  const prefix=directory ? directory+"/" : "";
  const result=new Map();
  for (const entry of entries) {
    if (search) { if(entry.path.toLowerCase().includes(search.toLowerCase())) result.set(entry.path, entry); continue; }
    if (!entry.path.startsWith(prefix)) continue;
    const suffix=entry.path.slice(prefix.length), separator=suffix.indexOf("/");
    if(separator>=0) { const folder=prefix+suffix.slice(0,separator); result.set(folder,{kind:"directory",path:folder,size:(result.get(folder)?.size || 0)+entry.size,revision:null,sha256:null,updated_at:Math.max(result.get(folder)?.updated_at || 0,entry.updated_at || 0)}); }
    else result.set(entry.path,entry);
  }
  const key=e=>e.kind+":"+e.path;
  const sorted=[...result.values()].sort((a,b)=>key(a)<key(b)?-1:1).filter(e=>key(e)>after);
  return {entries:sorted.slice(0,200), next:sorted.length>200?key(sorted[199]):null};
}
async function run(type,name) {
  const executablePath=name==="chromium"?process.env.MYSYNC_CHROMIUM:process.env.MYSYNC_FIREFOX;
  const browser=await type.launch({headless:true,...(executablePath?{executablePath}:{})});
  console.log(`${name} ${browser.version()}`);
  let counter=0;
  async function setup(options={}) {
    const context=await browser.newContext({viewport:options.mobile?{width:390,height:844}:{width:1240,height:823}, acceptDownloads:true, timezoneId:"Europe/Paris"});
    const page=await context.newPage();
    const errors=[]; const violations=[];
    let navigations=0;
    page.on("framenavigated",frame=>{if(frame===page.mainFrame())navigations++;});
    const pendingListings=[];
    const releaseListings=()=>pendingListings.splice(0).forEach(resolve=>resolve());
    page.on("pageerror", e=>errors.push(e.message));
    page.on("console", msg=>{if(msg.type()==="error" && /Content Security Policy|Refused to|violates/.test(msg.text()))violations.push(msg.text());});
    let authorized=options.authorized!==false, entries=options.entries || fixtures, expires=Math.floor(Date.now()/1000)+1800;
    let mode=options.mode || "normal", calls=0, chunks=0, loggedOut=false;
    if(name==="chromium") await context.grantPermissions(["local-network-access"],{origin}).catch(()=>{});
    await context.route("http://127.0.0.1:47831/**",async route=>{
      const headers={"Access-Control-Allow-Origin":origin,"Access-Control-Allow-Headers":"X-MySync-Bridge, X-MySync-Challenge","Access-Control-Allow-Private-Network":"true"};
      if(route.request().method()==="OPTIONS") {await route.fulfill({status:204,headers});return;}
      if(mode==="denied") {await route.abort();return;}
      if(mode==="waiting") {await new Promise(resolve=>setTimeout(resolve,4500));await route.fulfill({status:401,headers,json:{error:"challenge_required"}}).catch(()=>{});return;}
      if(!route.request().headers()["x-mysync-challenge"]) {await route.fulfill({status:401,headers,json:{error:"challenge_required"}});return;}
      if(mode==="disabled") {await route.fulfill({status:403,headers,json:{error:"files_read_disabled"}});return;}
      if(mode==="rejected" || mode==="misleading_rejection") {
        if(mode==="misleading_rejection")authorized=true;
        await route.fulfill({status:403,headers,json:{error:"invalid_challenge"}});return;
      }
      if(mode!=="impostor")authorized=true;
      if(mode==="lost_ack") {await route.abort();return;}
      await route.fulfill({headers,json:{device_name:"Local impostor",challenge_id:"wrong"}});
    });
    if(mode==="denied")await page.addInitScript(()=>{navigator.permissions.query=async()=>({state:"denied"});});
    const assets={"/files":["index.html","text/html"],"/status":["index.html","text/html"],"/atlas.js":["atlas.js","text/javascript"],"/status.js":["status.js","text/javascript"],"/status.css":["status.css","text/css"],"/atlas-icons.svg":["atlas-icons.svg","image/svg+xml"],"/atlas-brand.png":["atlas-brand.png","image/png"],"/atlas-brand-dark.png":["atlas-brand-dark.png","image/png"]};
    await context.route(`${origin}/**`,async route=>{
      const url=new URL(route.request().url());
      if(assets[url.pathname]) {
        const [asset,contentType]=assets[url.pathname];
        await route.fulfill({contentType,headers:{"Content-Security-Policy":csp,"Cache-Control":"no-store"},body:fs.readFileSync(path.join(root,asset))});return;
      }
      assert.equal(route.request().headers()["x-mysync-web"],"1");
      if(url.pathname.endsWith("/logout")) {authorized=false;loggedOut=true;await route.fulfill({json:{}});return;}
      if(url.pathname.endsWith("/session") && route.request().method()==="POST") {loggedOut=false;await route.fulfill({json:{}});return;}
      if(url.pathname.endsWith("/challenges")) {await route.fulfill({json:{challenge_id:id,ticket:"fixture-ticket",expires_at:Math.floor(Date.now()/1000)+60}});return;}
      if(url.pathname.endsWith(`/challenges/${id}`) && !authorized) {await route.fulfill({status:202,json:{error:"pending"}});return;}
      if(!authorized || expires*1000<=Date.now()) {await route.fulfill({status:401,json:{error:"session_expired"}});return;}
      if(url.pathname.endsWith("/session") || url.pathname.endsWith(`/challenges/${id}`)) {await route.fulfill({json:{device_name:"Approved fixture",expires_at:expires,download_limit:268435456,chunk_bytes:8388608}});return;}
      if(url.pathname.endsWith("/entries")) {
        calls++;
        if(mode==="held")await new Promise(resolve=>pendingListings.push(resolve));
        if(mode==="listing_error") {await route.fulfill({status:503,json:{error:"server_unavailable"}});return;}
        if(mode==="stale" && url.searchParams.get("search")==="README")await new Promise(resolve=>setTimeout(resolve,600));
        await route.fulfill({json:listing(entries,url.searchParams)}).catch(()=>{});return;
      }
      if(url.pathname.endsWith("/chunk")) {
        chunks++;assert.equal(url.searchParams.get("revision"),"1");
        if(mode==="changed")await route.fulfill({status:409,json:{error:"revision_changed"}});
        else if(mode==="download_wait") {await new Promise(resolve=>setTimeout(resolve,1000));await route.fulfill({body:content,contentType:"application/octet-stream"}).catch(()=>{});}
        else await route.fulfill({body:mode==="corrupt"?Buffer.alloc(content.length):content,contentType:"application/octet-stream"});
        return;
      }
      throw Error(`Unexpected URL ${url.pathname}`);
    });
    await page.goto(`${origin}/files`);
    if(authorized)await page.locator("#rows tr").first().waitFor({state:entries.length?"visible":"hidden"});
    async function capture(label) {
      if(screenshotDir){fs.mkdirSync(screenshotDir,{recursive:true});await page.screenshot({path:path.join(screenshotDir,`${name}-${label}.png`)});}
    }
    async function matrix(label, prepare = async () => {}) {
      const oldTheme = await page.locator("html").getAttribute("data-theme");
      const oldClosed = !(await page.locator("#sidebar").isVisible());
      for (const theme of ["light", "dark"]) {
        if (await page.locator("html").getAttribute("data-theme") !== theme) await page.locator("#theme-toggle").click();
        for (const closed of [false, true]) {
          if (!(await page.locator("#sidebar").isVisible()) !== closed) await page.locator("#sidebar-toggle").click();
          await prepare();
          assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `${label}: no horizontal overflow`);
          for (const control of ["#theme-toggle", "#sidebar-toggle"]) {
            const box = await page.locator(control).boundingBox();
            assert.ok(box && box.x >= 0 && box.y >= 0 && box.x + box.width <= (options.mobile ? 390 : 1240));
          }
          await capture(`matrix-${label}-${theme}-${closed ? "closed" : "open"}`);
        }
      }
      if (await page.locator("html").getAttribute("data-theme") !== oldTheme) await page.locator("#theme-toggle").click();
      if (!(await page.locator("#sidebar").isVisible()) !== oldClosed) await page.locator("#sidebar-toggle").click();
    }
    async function finish(label) {
      assert.deepEqual(errors,[],"JavaScript errors");assert.deepEqual(violations,[],"CSP violations");
      releaseListings();
      await context.close();console.log(`  ${++counter}. ${label}: passed`);
    }
    return {page,context,capture,matrix,finish,releaseListings,setMode:v=>mode=v,setEntries:v=>entries=v,setAuthorized:v=>authorized=v,setExpiry:v=>expires=v,calls:()=>calls,chunks:()=>chunks,loggedOut:()=>loggedOut,navigations:()=>navigations};
  }
  try {
    {
      const t=await setup();const {page}=t;
      assert.equal(await page.locator("#rows tr").count(),12);
      assert.equal(await page.locator(".more-button").count(),8,"directories have no action menu");
      assert.equal(await page.getByRole("button",{name:"Configurations",exact:true}).locator("xpath=ancestor::tr").locator("td").nth(1).textContent(),"4 Ko");
      assert.equal(await page.getByRole("button",{name:"Projets",exact:true}).locator("xpath=ancestor::tr").locator("td").nth(1).textContent(),"7 Ko");
      assert.equal(await page.locator("#file-table th").nth(2).textContent(),"Dernière modification");
      const folderTime=page.getByRole("button",{name:"Configurations",exact:true}).locator("xpath=ancestor::tr").locator("time");
      assert.equal(await folderTime.getAttribute("datetime"),"2026-10-01T10:06:00.000Z");
      assert.equal(await folderTime.textContent(),"01/10/2026 12:06");
      const readmeTime=page.getByRole("button",{name:"README.md",exact:true}).locator("xpath=ancestor::tr").locator("time");
      assert.equal(await readmeTime.getAttribute("datetime"),"2026-10-01T10:24:00.000Z");
      assert.equal(await readmeTime.textContent(),"01/10/2026 12:24");
      assert.equal(await page.locator(".toolbar #refresh").count(),1);
      assert.equal(await page.locator(".pagination #refresh").count(),0);
      await t.capture("12-menu-ouvert");
      await t.matrix("explorer");
      await page.locator("#sidebar-toggle").click();assert.equal(await page.locator("#sidebar").isVisible(),false);
      await t.capture("13-menu-ferme");
      await page.locator("#theme-toggle").click();assert.equal(await page.locator("html").getAttribute("data-theme"),"dark");
      await page.reload();await page.locator("#rows tr").first().waitFor();
      assert.equal(await page.locator("#sidebar").isVisible(),false);assert.equal(await page.locator("html").getAttribute("data-theme"),"dark");
      await page.locator("#sidebar-toggle").click();await page.locator("#theme-toggle").click();
      await page.getByRole("button",{name:"Actions pour architecture-technique.pdf",exact:true}).click();
      await t.capture("02-menu");
      await t.matrix("file-menu", async () => {
        if (!(await page.locator("#file-menu").isVisible())) await page.getByRole("button",{name:"Actions pour architecture-technique.pdf",exact:true}).click();
      });
      await page.getByRole("button",{name:"Actions pour architecture-technique.pdf",exact:true}).click();
      await page.keyboard.press("ArrowDown");await page.keyboard.press("Enter");
      assert.equal(await page.locator("#detail-name").textContent(),"architecture-technique.pdf");
      assert.equal(await page.locator("#detail-modified time").getAttribute("datetime"),"2026-10-01T10:18:00.000Z");
      assert.match(await page.locator("#detail-modified").textContent(),/1 octobre 2026.*12:18:00/);
      assert.equal(await page.locator("#detail-hash").textContent(),digest);await t.capture("03-details");
      await t.matrix("details");
      await page.keyboard.press("Escape");assert.equal(await page.locator("#details").isVisible(),false);
      await page.getByRole("button",{name:"Configurations",exact:true}).click();
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Configurations" && document.querySelectorAll("#rows tr").length===2);
      assert.match(await page.locator("#rows").textContent(),/client.example.json/);
      await page.locator("#breadcrumbs button").first().click();await page.locator("#rows tr").nth(11).waitFor();
      await page.locator("#search").fill("config");await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===5);
      await page.locator("#theme-toggle").click();await t.capture("04-recherche-sombre");
      await t.matrix("search");
      assert.ok(await page.locator("#rows mark").count()>0);
      await page.locator("#search").fill("absent");await page.locator("#empty").waitFor();await t.capture("07-sans-resultat");
      await t.matrix("no-result");
      await page.locator("#empty-reset").click();await page.locator("#rows tr").nth(11).waitFor();
      if (name === "chromium") {
        await t.context.grantPermissions(["clipboard-read", "clipboard-write"], {origin});
        await page.getByRole("button", {name:"Actions pour README.md",exact:true}).click();
        await page.getByRole("menuitem", {name:"Copier le chemin"}).click();
        await page.waitForFunction(() => document.querySelector("#toast-message").textContent === "Chemin copié.");
        assert.equal(await page.evaluate(() => navigator.clipboard.readText()), "README.md");
      }
      await page.locator("#logout").click();await page.waitForFunction(()=>document.querySelector("#access-message").textContent==="Vous êtes déconnecté.");
      assert.equal(t.loggedOut(),true);assert.equal(await page.locator("#rows tr").count(),0);assert.equal(await page.locator("#search").inputValue(),"");
      assert.doesNotMatch(await page.locator("body").innerText(),/architecture-technique|client.example/);
      await t.finish("navigation, themes, menus, details, folder, search, logout");
    }
    for(const mode of ["normal","lost_ack","impostor","disabled","rejected","misleading_rejection","denied","waiting"]) {
      const t=await setup({authorized:false,mode});const {page}=t;
      assert.equal(t.calls(),0);await t.capture(mode==="normal"?"05-verification":"access-"+mode);
      if(mode==="normal")await t.matrix("verification");
      await page.locator("#file-verify").click();
      if(mode==="normal" || mode==="lost_ack" || mode==="misleading_rejection") {await page.locator("#rows tr").first().waitFor();assert.equal(t.calls(),1);}
      else if(mode==="waiting") {await page.waitForFunction(()=>document.querySelector("#access-message").textContent.includes("En attente"));await page.locator("#file-cancel").click();await page.waitForFunction(()=>document.querySelector("#access-message").textContent.includes("annulée"));}
      else {await page.waitForFunction(()=>!document.querySelector("#file-verify").disabled);assert.equal(t.calls(),0);assert.equal(await page.locator("#rows tr").count(),0);if(mode==="disabled")assert.match(await page.locator("#access-title").textContent(),/non autorisée/);if(mode==="rejected") {assert.match(await page.locator("#access-title").textContent(),/Vérification locale refusée/);assert.doesNotMatch(await page.locator("body").innerText(),/architecture-technique|client.example/);}if(mode==="denied")assert.match(await page.locator("#access-title").textContent(),/refusée/);}
      if(mode==="denied")await t.capture("10-permission-refusee");
      if(mode==="denied" || mode==="disabled")await t.matrix(mode);
      await t.finish(`verification ${mode}`);
    }
    {
      const long="rapport-"+"documentation-".repeat(13)+"final.pdf";
      const unsafe="<img src=x onerror=alert(1)>.txt";
      const t=await setup({entries:[file(long),file(unsafe)],mobile:true});const {page}=t;
      assert.equal(await page.locator("#sidebar").isVisible(),false);
      assert.equal(await page.locator("#rows img").count(),0);
      await page.getByRole("button",{name:long,exact:true}).click();assert.equal(await page.locator("#detail-name").textContent(),long);
      await t.capture("09-nom-long-mobile");
      await t.matrix("long-name-mobile");
      assert.equal(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),true);
      await page.locator("#details-close").focus();
      for (let i=0;i<6;i++) {
        await page.keyboard.press("Tab");
        assert.equal(await page.evaluate(()=>document.querySelector(".file-list").contains(document.activeElement)),false,"covered rows must not receive keyboard focus");
      }
      await page.keyboard.press("Escape");
      t.setAuthorized(false);await page.locator("#refresh").click();await page.waitForFunction(()=>document.querySelector("#access-title").textContent==="Session expirée");
      assert.doesNotMatch(await page.locator("body").innerText(),/rapport-|onerror/);await t.capture("11-session-expiree-mobile");
      await t.finish("mobile, long names, text escaping, revoked session");
    }
    {
      const t=await setup({entries:[]});await t.page.locator("#empty").waitFor();await t.capture("08-espace-vide");
      await t.matrix("empty");
      assert.match(await t.page.locator("#empty-title").textContent(),/Aucun fichier/);await t.finish("empty space");
    }
    {
      const legacy=file("legacy.txt");delete legacy.updated_at;
      const t=await setup({entries:[legacy,{...file("unknown.txt"),updated_at:null}]});const {page}=t;
      assert.equal(await page.locator("#rows time").count(),0);
      for(const row of await page.locator("#rows tr").all())assert.equal(await row.locator("td").nth(2).textContent(),"—");
      await page.getByRole("button",{name:"legacy.txt",exact:true}).click();
      assert.equal(await page.locator("#detail-modified").textContent(),"—");
      await t.finish("missing modification dates remain unknown");
    }
    {
      const t=await setup();const {page}=t;
      const title=await page.locator("#listing-title").textContent();
      const rows=await page.locator("#rows").textContent();
      t.setMode("held");
      await page.getByRole("button",{name:"Configurations",exact:true}).click();
      await page.locator("#refresh.is-loading").waitFor();
      assert.equal(await page.locator("#rows").textContent(),rows,"keep the previous listing while waiting");
      assert.equal(await page.locator("#listing-title").textContent(),title,"commit title and rows together");
      assert.equal(await page.locator("#listing-message").isVisible(),false);
      assert.equal(await page.locator("#refresh").getAttribute("aria-disabled"),"true");
      await page.emulateMedia({reducedMotion:"reduce"});
      assert.equal(await page.locator("#refresh svg").evaluate(el=>getComputedStyle(el).animationName),"none");
      await t.capture("navigation-pending");
      t.setMode("normal");t.releaseListings();
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Configurations");
      assert.equal(await page.locator("#rows tr").count(),2);
      assert.equal(await page.locator("#listing-title").evaluate(el=>el===document.activeElement),true,"navigation keeps focus in the file view");
      await page.locator("#files-nav").click();
      await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===12);
      assert.equal(t.navigations(),1,"the Files link must not reload the document");
      await page.getByRole("button",{name:"README.md",exact:true}).click();
      await page.evaluate(()=>{window.savedRow=document.querySelector("#rows tr");});
      t.setMode("held");await page.locator("#refresh").click();
      await page.locator("#refresh.is-loading").waitFor();
      assert.equal(await page.locator("#details").isVisible(),true);
      t.setMode("normal");t.releaseListings();
      await page.waitForFunction(()=>document.querySelector("#refresh").getAttribute("aria-disabled")==="false");
      assert.equal(await page.evaluate(()=>window.savedRow===document.querySelector("#rows tr")),true,"unchanged refresh preserves DOM nodes");
      assert.equal(await page.locator("#details").isVisible(),true);
      assert.equal(await page.locator("#detail-name").textContent(),"README.md");
      const refreshedEntries=fixtures.map(entry=>entry.path==="README.md"?{...entry,size:2048,revision:25}:entry);
      t.setEntries(refreshedEntries);
      await page.locator("#refresh").click();
      await page.waitForFunction(()=>document.querySelector("#detail-revision").textContent==="25");
      assert.equal(await page.locator("#detail-size").textContent(),"2 Ko");
      assert.equal(await page.locator("#refresh").evaluate(el=>el===document.activeElement),true,"refresh must retain keyboard focus");
      t.setEntries(refreshedEntries.map(entry=>entry.path==="README.md"?{...entry,updated_at:fixtureTime+3600}:entry));
      await page.locator("#refresh").click();
      await page.waitForFunction(()=>document.querySelector("#detail-modified time")?.dateTime==="2026-10-01T11:00:00.000Z");
      assert.equal(await page.getByRole("button",{name:"README.md",exact:true}).locator("xpath=ancestor::tr").locator("time").textContent(),"01/10/2026 13:00","a date-only change must refresh the row");
      await page.locator("#details-close").click();
      t.setMode("listing_error");await page.getByRole("button",{name:"Configurations",exact:true}).click();
      await page.locator("#listing-message").waitFor();
      assert.equal(await page.locator("#rows tr").count(),12,"a failed navigation keeps the previous view");
      assert.equal(await page.locator("#listing-title").textContent(),"Tous les fichiers");
      t.setMode("normal");await page.locator("#refresh").click();
      await page.waitForFunction(()=>document.querySelector("#listing-title").textContent==="Configurations");
      await page.locator(".brand").click();
      await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===12);
      assert.equal(t.navigations(),1,"the brand link must not reload the document");
      await t.finish("stable navigation, refresh, details and retry after failure");
    }
    {
      const t=await setup({entries:Array.from({length:201},(_,i)=>file(`page-${String(i).padStart(3,"0")}.txt`))});const {page}=t;
      assert.equal(await page.locator("#rows tr").count(),200);await page.locator("#next-page").click();
      await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===1);assert.match(await page.locator("#rows").textContent(),/page-200/);
      await page.locator("#refresh").click();
      await page.waitForFunction(()=>document.querySelector("#refresh").getAttribute("aria-disabled")==="false");
      assert.equal(await page.locator("#rows tr").count(),1,"refresh keeps the current page");
      assert.match(await page.locator("#count").textContent(),/page 2/);
      await page.locator("#previous-page").click();await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===200);await t.finish("pagination");
    }
    {
      const t=await setup({mode:"stale"});const {page}=t;
      await page.locator("#search").fill("README");await page.waitForTimeout(250);await page.locator("#search").fill("Cargo");
      await page.waitForFunction(()=>document.querySelectorAll("#rows tr").length===2);await page.waitForTimeout(700);
      assert.doesNotMatch(await page.locator("#rows").textContent(),/README/);await t.finish("stale search responses");
    }
    for(const mode of ["normal","corrupt","changed","download_wait"]) {
      const t=await setup({entries:[file("sample.txt")],mode});const {page}=t;
      await page.getByRole("button",{name:"sample.txt",exact:true}).click();
      let received=false;page.on("download",()=>received=true);
      const downloading=mode==="normal"?page.waitForEvent("download"):undefined;
      await page.locator("#detail-download").click();
      if(mode==="download_wait") {await page.locator("#download-cancel").click();await page.waitForFunction(()=>document.querySelector("#toast-message").textContent.includes("annulé"));}
      else if(mode==="normal") {const download=await downloading;assert.equal(download.suggestedFilename(),"sample.txt");const stream=await download.createReadStream();const chunks=[];for await(const chunk of stream)chunks.push(chunk);assert.deepEqual(Buffer.concat(chunks),content);await t.capture("06-telechargement");}
      else {await page.waitForFunction(()=>document.querySelector("#download-cancel").hidden);assert.equal(received,false);assert.match(await page.locator("#toast-message").textContent(),mode==="corrupt"?/empreinte/:/changé/);}
      await t.finish(`download ${mode}`);
    }
    {
      const t=await setup();const {page}=t;
      await page.clock.install();t.setExpiry(Math.floor(Date.now()/1000)+2);await page.reload();await page.locator("#rows tr").first().waitFor();
      t.setMode("held");await page.locator("#refresh").click();
      await page.clock.fastForward(3000);await page.waitForFunction(()=>document.querySelector("#access-title").textContent==="Session expirée");
      t.setMode("normal");t.releaseListings();await page.clock.runFor(100);
      assert.equal(await page.locator("#rows tr").count(),0);await t.capture("11-session-expiree");await t.matrix("expired");await t.finish("automatic session expiry");
    }
  } finally {await browser.close();}
}
(async()=>{
  if(process.env.MYSYNC_BROWSER!=="firefox")await run(chromium,"chromium");
  if(process.env.MYSYNC_BROWSER!=="chromium")await run(firefox,"firefox");
})().catch(e=>{console.error(e);process.exitCode=1;});
