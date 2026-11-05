import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { ApiError, analysisCoverageSections, apiEvidenceSections, artifactFormat, assessmentWorkflowLabel, auditExportPath, coverageMatrixMarkup, comparisonArtifactMarkup, createApi, detailTabsMarkup, dynamicScenarioOptions, dynamicDeviceLabel, endpointsFromForm, escapeHTML, exactHTTPSURL, formatBytes, kpiCards, makeQuery, methodologyFrameworksMarkup, methodologyReferencesMarkup, metricCount, overviewActivityMarkup, overviewPendingActionsMarkup, overviewFilterPanel, pager, parseRoute, reportSnapshotMarkup, riskTrendMarkup, runtimeEvidenceSections, splitTargets, valuesFromFields, viewAction, workspaceSettingsMarkup, workspaceSettingsPayload, workspaceSecretStatusMarkup, workspaceUserRow } from "../backend/droidshield/web/app.js";

test("client and project detail tabs expose accessible selected-tab relationships",()=>{
  const tabs=[["overview","Overview"],["findings","Findings <script>"]];
  const client=detailTabsMarkup("client",tabs,"findings");
  assert.match(client,/role="tablist" aria-label="Client details"/);
  assert.match(client,/id="client-tab-findings" role="tab" aria-selected="true" aria-controls="client-panel" tabindex="0"/);
  assert.match(client,/Findings &lt;script&gt;/);
  assert.match(client,/aria-selected="false" aria-controls="client-panel" tabindex="-1"/);
  const project=detailTabsMarkup("project",[["reports","Reports"]],"reports");
  assert.match(project,/aria-label="Project details"/);
  assert.match(project,/id="project-tab-reports"/);
  assert.doesNotMatch(detailTabsMarkup('<img>',[["activity","Activity"]],"activity"),/<img/);
});

test("untrusted markup is encoded in text and attribute contexts", () => {
  assert.equal(escapeHTML('<img src=x onerror="alert(1)"> & \'x\''), "&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; &#39;x&#39;");
  assert.equal(escapeHTML(null), "");
});

test("navigation accepts known pages and bounded record identities only", () => {
  assert.deepEqual(parseRoute("#projects/01970000-1234-1234-1234-123456789abc"), {page:"projects",id:"01970000-1234-1234-1234-123456789abc"});
  assert.deepEqual(parseRoute("#users"), {page:"users",id:null});
  assert.deepEqual(parseRoute("#https://example.com"), {page:"overview",id:null});
  assert.equal(parseRoute('#findings/<script>').id, null);
  assert.equal(parseRoute('').page, "overview");
});

test("workspace user rows escape identities and expose only admin actions",()=>{
  const user={id:'01970000-1234-1234-1234-123456789abc',full_name:'<img src=x onerror="bad">',email:'member"><script>alert(1)</script>@example.test',role:"SECURITY_ANALYST",status:"disabled",created_at:"2026-10-28T12:00:00Z",password_hash:"never-render",session_token:"never-render"};
  const row=workspaceUserRow(user,{canManage:true,currentUserId:"another-user"});
  assert.match(row,/&lt;img src=x onerror=&quot;bad&quot;&gt;/);
  assert.match(row,/member&quot;&gt;&lt;script&gt;alert\(1\)&lt;\/script&gt;@example\.test/);
  assert.match(row,/data-action="edit-user"/);
  assert.match(row,/data-action="revoke-user-sessions"/);
  assert.doesNotMatch(row,/<img|<script|password_hash|session_token|never-render/);
  const self=workspaceUserRow(user,{canManage:true,currentUserId:user.id});
  assert.match(self,/Current account/);
  assert.doesNotMatch(self,/data-action="revoke-user-sessions"/);
  const readOnly=workspaceUserRow(user);
  assert.doesNotMatch(readOnly,/data-action="edit-user|data-action="revoke-user-sessions/);
});

test("Team and Access checks the role before loading the supported user directory",async()=>{
  const source=await readFile(new URL("../backend/droidshield/web/app.js",import.meta.url),"utf8");
  const page=source.slice(source.indexOf("async function usersPage"),source.indexOf("function userForm"));
  assert.match(page,/if\(!admin\(\)\)return pageHeader\("Team & Access"/);
  assert.match(page,/api\(`\/users\$\{makeQuery\(\{limit:25,offset:f\.offset\|\|0,role:f\.role,status:f\.status\}\)\}`/);
  assert.match(source,/Set a password through the trusted local CLI/i);
  const form=source.slice(source.indexOf("function userForm"),source.indexOf("function revokeUserSessionsForm"));
  assert.doesNotMatch(form,/textField\("password"|name:\s*"password"/);
});

test("workspace settings form sends only validated presentation fields and the current revision",()=>{
  const data=new FormData();
  data.set("workspace_name","  <script>Client workspace</script>  ");
  data.set("display_timezone"," America/New_York ");
  data.set("date_format","mdy");
  data.set("default_report_template","technical");
  data.set("report_branding_name","  ");
  data.set("secret_references","forged");data.set("api_key","should-not-serialize");
  const payload=workspaceSettingsPayload(data,7);
  assert.deepEqual(payload,{revision:7,workspace_name:"<script>Client workspace</script>",display_timezone:"America/New_York",date_format:"mdy",default_report_template:"technical",report_branding_name:null});
  assert.deepEqual(Object.keys(payload).sort(),["date_format","default_report_template","display_timezone","report_branding_name","revision","workspace_name"]);
  assert.throws(()=>workspaceSettingsPayload(data,0),/Reload workspace settings/);
  data.set("workspace_name","  ");assert.throws(()=>workspaceSettingsPayload(data,7),/workspace name/);
  data.set("workspace_name","Workspace");data.set("date_format","custom");assert.throws(()=>workspaceSettingsPayload(data,7),/date format/);
});

test("workspace settings markup escapes values and exposes integration status without secret values",()=>{
  const settings={workspace_name:'<img src=x onerror="bad">',display_timezone:"UTC",date_format:"iso",default_report_template:"combined",report_branding_name:"<script>brand</script>",updated_at:null};
  const summary=workspaceSettingsMarkup(settings);
  assert.match(summary,/&lt;img src=x onerror=&quot;bad&quot;&gt;/);
  assert.match(summary,/&lt;script&gt;brand&lt;\/script&gt;/);
  assert.doesNotMatch(summary,/<img|<script/);
  const status=workspaceSecretStatusMarkup({mobsf_service:{configured:true,api_key:"top-secret"},api_secret_store:{configured:false,token:"top-secret"},frida_runtime:{configured:true},proxy_certificate_authority:{configured:false},private_key:"top-secret"});
  assert.match(status,/MobSF analysis service/);assert.match(status,/Configuration present/);assert.match(status,/No configuration detected/);assert.match(status,/does not verify runtime readiness/);
  assert.doesNotMatch(status,/top-secret|api_key|private_key|token/);
});

test("workspace settings are fetched and edited only in the administrator interface",async()=>{
  const source=await readFile(new URL("../backend/droidshield/web/app.js",import.meta.url),"utf8");
  const page=source.slice(source.indexOf("async function settingsPage"),source.indexOf("const multiField"));
  assert.match(page,/if\(admin\(\)\)\{\s*const settings=await api\("\/settings",\{signal\}\)/);
  assert.match(page,/workspaceSecretStatusMarkup\(settings\.secret_references\)/);
  const form=source.slice(source.indexOf("function workspaceSettingsForm"),source.indexOf("async function settingsPage"));
  assert.match(form,/kind:"workspace-settings"[\s\S]*?path:"\/settings",method:"PATCH",revision:settings\.revision/);
  assert.match(form,/workspaceSettingsPayload\(data,settings\.revision\)/);
  assert.doesNotMatch(form,/secret_references|api_key|proxy_certificate_authority/);
  assert.match(source,/spec\.kind==="workspace-settings"\)\{currentWorkspaceSettings=record;workspaceSettingsForm\(record\);\}/);
});

test("record table actions render an accessible eye icon and View label", () => {
  const html=viewAction("clients",'record-<img src=x onerror="bad">');
  assert.match(html,/type="button"/);
  assert.match(html,/data-action="record-view"/);
  assert.match(html,/data-page="clients"/);
  assert.match(html,/data-id="record-&lt;img src=x onerror=&quot;bad&quot;&gt;"/);
  assert.doesNotMatch(html,/href=/);
  assert.match(html,/<svg[^>]*aria-hidden="true"><path d="M2 12s3\.5-7/);
  assert.match(html,/<span>View<\/span>/);
  assert.match(html,/aria-label="View record"/);
});

test("form serialization keeps optional nulls, exact targets and integer revisions separate", () => {
  const data=new FormData();
  data.set("name","  Client name  "); data.set("email","  "); data.set("scope","package:com.example.app\n\nhttps://api.example.com/v1\n"); data.set("timeout","90");
  data.set("valid_from","2026-10-28T12:00"); data.set("created_by","forged");
  const fields=[{name:"name"},{name:"email",nullable:true},{name:"scope",kind:"targets"},{name:"timeout",type:"number",label:"Timeout"},{name:"valid_from",type:"datetime-local",label:"Start"}];
  const values=valuesFromFields(fields,data);
  assert.equal(values.name,"Client name"); assert.equal(values.email,null); assert.equal(values.timeout,90);
  assert.deepEqual(values.scope,["package:com.example.app","https://api.example.com/v1"]);
  assert.match(values.valid_from,/Z$/); assert.equal("created_by" in values,false);
  data.set("timeout","90.2"); assert.throws(()=>valuesFromFields(fields,data),/whole number/);
});

test("query filters preserve zero offsets and safely encode user search terms", () => {
  assert.equal(makeQuery({q:"App & Client",offset:0,status:"",project_id:null}),"?q=App+%26+Client&offset=0");
  assert.deepEqual(splitTargets("package:com.test.app\r\n \r\nhttps://example.com/"),["package:com.test.app","https://example.com/"]);
  assert.equal(formatBytes(0),"0 B"); assert.equal(formatBytes(1048576),"1.0 MB");
});

test("audit export preserves the current supported filters and excludes pagination or unknown fields", () => {
  const path=auditExportPath({action:"  assessment.created&format=json ",resource_type:" project ",result:"failure",actor_id:"actor-uuid",resource_id:"resource-uuid",date_from:"2026-11-01",date_to:"2026-11-04",offset:75,project_id:"not-supported",secret:"never-export"},"csv");
  assert.equal(path,"/audit-events/export?format=csv&action=assessment.created%26format%3Djson&resource_type=project&result=failure&actor_id=actor-uuid&resource_id=resource-uuid&date_from=2026-11-01&date_to=2026-11-04");
  const params=new URLSearchParams(path.split("?")[1]);
  assert.equal(params.get("action"),"assessment.created&format=json");
  assert.equal(params.get("format"),"csv");
  assert.equal(params.has("offset"),false);
  assert.equal(params.has("project_id"),false);
  assert.equal(params.has("secret"),false);
  assert.throws(()=>auditExportPath({},"xml"),/Choose CSV or JSON/);
});

test("audit page offers both filtered exports and explains the export bounds", async () => {
  const source=await readFile(new URL("../backend/droidshield/web/app.js",import.meta.url),"utf8");
  const page=source.slice(source.indexOf("async function auditPage"),source.indexOf("export function workspaceUserRow"));
  assert.match(page,/btn\("export-audit","Export CSV"[\s\S]*?data-format="csv"/);
  assert.match(page,/btn\("export-audit","Export JSON"[\s\S]*?data-format="json"/);
  assert.match(page,/Action \(exact\)/);
  assert.match(page,/Resource type \(exact\)/);
  assert.match(page,/From date \(UTC\)/);
  assert.match(page,/Through date \(UTC\)/);
  assert.match(page,/10,000 records \/ 10 MiB/);
  assert.match(source,/if\(action==="export-audit"\)[\s\S]*?if\(!admin\(\)\)/);
});

test("shared pager follows the APISentinel range and previous/next page layout", () => {
  const page=pager({items:Array.from({length:25},(_,i)=>i),total:63,limit:25,offset:25},"Client directory","clients");
  assert.match(page,/class="client-pagination table-foot"/);
  assert.match(page,/<b>26–50<\/b><span>\/ Total 63<\/span>/);
  assert.match(page,/Page <b>2<\/b> of 3/);
  assert.match(page,/data-page-key="clients" data-offset="0" aria-label="Previous page"/);
  assert.match(page,/data-page-key="clients" data-offset="50" aria-label="Next page"/);
  assert.match(page,/chevron-left|m15 18-6-6 6-6/);
  const first=pager({items:[1],total:26,limit:25,offset:0},"Clients","clients");
  assert.match(first,/Page <b>1<\/b> of 2/);
  assert.match(first,/aria-label="Previous page" disabled/);
  const last=pager({items:[1,2,3],total:53,limit:25,offset:50},"Clients","clients");
  assert.match(last,/Page <b>3<\/b> of 3/);
  assert.match(last,/aria-label="Next page" disabled/);
  const empty=pager({items:[],total:0,limit:25,offset:0},"<script>","clients");
  assert.match(empty,/aria-label="&lt;script&gt; pages"/);
  assert.match(empty,/<b>0–0<\/b><span>\/ Total 0<\/span>/);
  assert.match(empty,/Page <b>0<\/b> of 0/);
  assert.match(empty,/aria-label="Previous page" disabled/);
  assert.match(empty,/aria-label="Next page" disabled/);
  const stale=pager({items:[],total:20,limit:25,offset:25},"Clients","clients");
  assert.match(stale,/<b>0–0<\/b><span>\/ Total 20<\/span>/);
  assert.match(stale,/Page <b>1<\/b> of 1/);
});

test("KPI values are database counts, labels are escaped, and color tones are semantic", async () => {
  assert.equal(metricCount({total_projects:12},"total_projects"),"12");
  assert.equal(metricCount({},"missing"),"—");
  assert.equal(metricCount({total_projects:-1},"total_projects"),"—");
  const html=kpiCards([["Critical <issue>","3","Confirmed and unresolved","bug","red"],["Reports",0,"All versions","download","blue"]]);
  assert.match(html,/class="kpi tone-red"/);assert.match(html,/class="kpi tone-blue"/);assert.match(html,/Critical &lt;issue&gt;/);assert.match(html,/class="kpi-value">3</);
  const css=await readFile(new URL("../backend/droidshield/web/styles.css",import.meta.url),"utf8");
  for(const tone of ["cyan","teal","blue","purple","orange","amber","red","green"])assert.match(css,new RegExp(`\\.kpi\\.tone-${tone}`));
  assert.doesNotMatch(css,/\.kpi:nth-child\(\d+\).*\.kpi-icon/);
});

test("overview filters expose project, assessment and date scopes with automatic reset layout", () => {
  const html=overviewFilterPanel();
  for(const name of ["project_id","assessment_type","assessment_status","date_from","date_to","trend_days"])assert.match(html,new RegExp(`name="${name}"`));
  assert.match(html,/<option value="30" selected>Last 30 days<\/option>/);assert.match(html,/Last 7 days/);assert.match(html,/Last 90 days/);
  assert.match(html,/Reset filters/);assert.match(html,/Results update automatically/);
});

test("overview risk trend shows severity counts, overdue retests and accessible daily data", () => {
  const markup=riskTrendMarkup([
    {date:"2026-11-03",critical:1,high:2,medium:0,low:1,info:0,total:999},
    {date:"2026-11-04",critical:0,high:0,medium:1,low:0,info:0,total:1},
    {date:"<img src=x>",critical:50,high:0,medium:0,low:0,info:0},
    {date:"2026-02-31",critical:50,high:0,medium:0,low:0,info:0}
  ],7,2);
  assert.match(markup,/role="region" tabindex="0" aria-label="Scrollable risk trend chart"/);
  assert.match(markup,/last 7 days/i);
  assert.match(markup,/Currently open findings in this window/);
  assert.match(markup,/Overdue retests/);
  assert.match(markup,/<strong>2<\/strong>/);
  assert.match(markup,/Critical/);assert.match(markup,/High/);assert.match(markup,/Medium/);assert.match(markup,/Low/);assert.match(markup,/Info/);
  assert.match(markup,/View daily data/);assert.match(markup,/2026-11-03/);
  assert.doesNotMatch(markup,/<img src=x>/);
  assert.doesNotMatch(markup,/2026-02-31/);
  assert.doesNotMatch(markup,/>999</);
  assert.match(markup,/not a historical snapshot/);
  assert.match(riskTrendMarkup([],30,0),/No trend data available/);
});

test("overview renders scoped activity and API-backed review queues safely", () => {
  const id="01970000-1234-1234-1234-123456789abc";
  const activity=overviewActivityMarkup([
    {id,actor_id:id,action:"finding.reviewed",resource_type:"finding",resource_id:id,result:"success",timestamp:"2026-11-04T12:00:00Z"},
    {id,actor_id:null,action:"assessment.<img src=x>",resource_type:"unknown",resource_id:"unsafe",result:"failure",timestamp:"2026-11-04T12:01:00Z"}
  ]);
  assert.match(activity,/Finding Reviewed/);
  assert.match(activity,/href="#findings\/01970000-1234-1234-1234-123456789abc"/);
  assert.match(activity,/&lt;Img Src=X&gt;/);
  assert.match(activity,/class="tag failure"/);
  assert.doesNotMatch(activity,/<img src=x>/);
  assert.match(overviewActivityMarkup([]),/No recent activity/);

  const pending=overviewPendingActionsMarkup({assessment_reviews:2,report_reviews:1,retest_reviews:3,total:6});
  assert.match(pending,/<strong>6<\/strong>/);
  assert.match(pending,/Assessment review/);
  assert.match(pending,/href="#reports"/);
  assert.match(pending,/href="#retesting"/);
  assert.match(overviewPendingActionsMarkup({assessment_reviews:0,report_reviews:0,retest_reviews:0,total:0}),/You're up to date/);
});

test("service delivery forms serialize selected evidence and strict booleans without extra fields", () => {
  const data=new FormData();data.append("evidence_ids","evidence-a");data.append("evidence_ids","evidence-b");data.set("include_evidence","false");data.set("include_remediation","true");data.set("forged_reviewer","someone-else");
  const body=valuesFromFields([{name:"evidence_ids",type:"multi"},{name:"include_evidence",kind:"boolean"},{name:"include_remediation",kind:"boolean"},{name:"finding_ids",type:"multi"}],data);
  assert.deepEqual(body,{evidence_ids:["evidence-a","evidence-b"],include_evidence:false,include_remediation:true,finding_ids:[]});
  assert.equal("forged_reviewer" in body,false);
});

test("cross-platform artifact selection permits only supported intake formats", () => {
  for(const [name,format] of [["release.APK","apk"],["Application.IPA","ipa"],["bundle.aab","aab"]])assert.equal(artifactFormat(name),format);
  for(const name of ["artifact.zip","application.apk.exe","ipa",""])assert.throws(()=>artifactFormat(name),/APK, AAB or IPA/);
  for(const page of ["methodology","retesting","reports"])assert.equal(parseRoute(`#${page}`).page,page);
});

test("coverage matrix preserves unrun gaps and encodes analyst content without executing it", () => {
  const coverage={summary:{pass:1,fail:0,not_run:2,na:0,blocked:0},cases:[{id:"DS-STORAGE-01",title:'<img src=x onerror="unsafe">',objective:"Keychain & Keystore",category:"storage",status:"not_run",execution:null},{id:"DS-AUTH-01",title:"Session lifecycle",category:"authentication",status:"pass",execution:{tool:"<script>bad</script>",tool_version:"1",evidence_ids:["id"]}}]};
  const html=coverageMatrixMarkup(coverage);
  assert.match(html,/Not Run/);assert.match(html,/<strong>2<\/strong><span>Not Run<\/span>/);assert.match(html,/DS-STORAGE-01/);assert.match(html,/Keychain &amp; Keystore/);assert.match(html,/&lt;script&gt;/);assert.doesNotMatch(html,/<img|<script>|data-action="coverage-execution"/);
  assert.match(coverageMatrixMarkup(coverage,{editable:true}),/data-action="coverage-execution"/);
  const filtered=coverageMatrixMarkup(coverage,{status:"not_run",category:"storage",query:"Keychain"});
  assert.match(filtered,/<strong>1<\/strong><span>Not Run<\/span>/);assert.match(filtered,/DS-STORAGE-01/);assert.doesNotMatch(filtered,/DS-AUTH-01/);
  assert.match(coverageMatrixMarkup({summary:{pass:-4,not_run:"unknown"},cases:[]}),/No applicable test cases/);
});

test("methodology shows pinned standards sources as safe external links",()=>{
  const refs=methodologyReferencesMarkup([{id:"MASVS-STORAGE-1",version:"2.1.0",source_revision:"v2.1.0",url:"https://mas.owasp.org/MASVS/controls/MASVS-STORAGE-1/"},{id:"bad\"><img src=x>",version:"1",url:"javascript:alert(1)"},{id:"evil",version:"1",url:"https://attacker.example/"}]);
  assert.match(refs,/href="https:\/\/mas\.owasp\.org\/MASVS\/controls\/MASVS-STORAGE-1\/"/);
  assert.match(refs,/rel="noopener noreferrer"/);assert.match(refs,/v2\.1\.0/);assert.match(refs,/&lt;img src=x&gt;/);
  assert.doesNotMatch(refs,/javascript:|attacker\.example|<img/);
  const frameworks=methodologyFrameworksMarkup([{id:"MASVS",version:"2.1.0",source_revision:"v2.1.0",source_url:"https://github.com/OWASP/masvs/releases/tag/v2.1.0"}],"1.1.0");
  assert.match(frameworks,/Local procedures 1\.1\.0/);assert.match(frameworks,/github\.com\/OWASP\/masvs/);
  assert.match(frameworks,/target="_blank" rel="noopener noreferrer"/);
});

test("report snapshots remain escaped review content and protected exports use authenticated reads", async () => {
  assert.doesNotMatch(reportSnapshotMarkup({executive_summary:"<svg onload=evil>"}),/<svg/);
  assert.match(reportSnapshotMarkup({limitations:"Not run"}),/Not run/);
  const screenshotReview=reportSnapshotMarkup({findings:[{title:"Reviewed screenshot",severity:"low",evidence:[{id:"evidence-id",title:"Access proof",text:"Sanitized screenshot digest attached.",attachment:{display_name:"screenshot.png",sha256:"a".repeat(64),file_size:512,pdf_inclusion:"embedded"}}]}]});
  assert.match(screenshotReview,/Included in technical\/combined PDF/);assert.match(screenshotReview,/Download screenshot/);
  const attachment=reportSnapshotMarkup({findings:[{title:"Screenshot proof",severity:"low",evidence:[{id:"proof-id",title:"Sanitized screenshot",text:"PNG attachment metadata",attachment:{display_name:"screenshot.png",sha256:"a".repeat(64),file_size:42,media_type:"image/png"}}]}]});
  assert.match(attachment,/Download screenshot/);assert.match(attachment,/screenshot\.png/);assert.doesNotMatch(attachment,/<img|data:image/);
  let options;const api=createApi({getToken:()=>"memory-credential",fetcher:async(_url,received)=>{options=received;return new Response("%PDF-fixture",{headers:{"Content-Type":"application/pdf"}});}});
  const file=await api("/report-exports/01970000-1234-1234-1234-123456789abc/download",{blob:true});
  assert.equal(await file.text(),"%PDF-fixture");assert.equal(options.headers.has("Authorization"),false);assert.equal(options.redirect,"error");assert.equal(options.credentials,"same-origin");
});

test("API requests use same-origin sessions and do not expose a bearer credential", async () => {
  let captured;
  const api=createApi({getCsrfToken:()=>"csrf-value-held-in-memory-only",fetcher:async(url,options)=>{captured={url,options};return new Response('{"items":[]}',{status:200});}});
  await api(`/projects${makeQuery({q:"Client App",offset:0})}`);
  assert.equal(captured.url,"/api/v1/projects?q=Client+App&offset=0");
  assert.equal(captured.options.headers.has("Authorization"),false);
  assert.equal(captured.options.credentials,"same-origin"); assert.equal(captured.options.cache,"no-store"); assert.equal(captured.options.redirect,"error");
  assert.equal(captured.options.headers.has("X-CSRF-Token"),false);
  await api("/clients",{method:"POST",body:{name:"App"},key:"create-client"});
  assert.equal(captured.options.headers.get("X-CSRF-Token"),"csrf-value-held-in-memory-only");
  await assert.rejects(api("https://elsewhere.example/api"),/workspace API paths/);
  await assert.rejects(api("//elsewhere.example/api"),/workspace API paths/);
});

test("POST retries reuse their caller's idempotency key and multipart gets a browser boundary", async () => {
  const calls=[];
  const api=createApi({getCsrfToken:()=>"csrf-token",fetcher:async(url,options)=>{calls.push(options);return new Response('{"id":"saved"}',{status:201});}});
  const body={name:"Application"}; await api("/clients",{method:"POST",body,key:"retry-key"}); await api("/clients",{method:"POST",body,key:"retry-key"});
  assert.equal(calls[0].headers.get("Idempotency-Key"),calls[1].headers.get("Idempotency-Key"));
  assert.equal(calls[0].body,JSON.stringify(body));
  const multipart=new FormData();multipart.set("revision","2");multipart.set("file",new Blob(["apk-bytes"]),"application.apk");
  await api("/assessments/abc/apk",{method:"POST",body:multipart,key:"upload-key"});
  assert.equal(calls[2].headers.has("Content-Type"),false);assert.equal(calls[2].body,multipart);
});

test("expired credentials trigger disconnect and errors preserve field paths and request correlation", async () => {
  let expired;
  const api=createApi({getCsrfToken:()=>"csrf-old",onUnauthorized:token=>expired=token,fetcher:async()=>new Response(JSON.stringify({error:{code:"unauthenticated",message:"Valid authentication is required"},request_id:"req-123"}),{status:401})});
  await assert.rejects(api("/me"),error=>error instanceof ApiError&&error.status===401&&error.requestId==="req-123");
  assert.equal(expired,"csrf-old");
  const validation=createApi({getCsrfToken:()=>"csrf-token",fetcher:async()=>new Response(JSON.stringify({error:{message:"Check the indicated fields",details:[{location:["body","contact_email"],type:"value_error"}]}}),{status:422})});
  await assert.rejects(validation("/clients",{method:"POST",body:{}}),error=>error.details[0].location[1]==="contact_email");
});

test("interrupted writes describe an unknown outcome; navigation abort remains recognizable", async () => {
  const network=createApi({getCsrfToken:()=>"csrf-token",fetcher:async()=>{throw new TypeError("offline");}});
  await assert.rejects(network("/clients",{method:"POST",body:{}}),/outcome is unknown/);
  const aborted=createApi({getCsrfToken:()=>"csrf-token",fetcher:async()=>{throw new DOMException("aborted","AbortError");}});
  await assert.rejects(aborted("/clients"),error=>error.name==="AbortError");
});

test("responses completing after disconnect cannot expose a previous workspace", async () => {
  let csrf="csrf-previous-workspace";
  const api=createApi({getCsrfToken:()=>csrf,fetcher:async()=>({ok:true,status:200,json:async()=>{csrf="csrf-new-workspace";return {name:"Private previous client"};}})});
  await assert.rejects(api("/clients"),error=>error.name==="AbortError");
  const session=new AbortController();let passedSignal;
  const scoped=createApi({getCsrfToken:()=>csrf,getSignal:()=>session.signal,fetcher:async(_url,options)=>{passedSignal=options.signal;return new Response("{}");}});
  await scoped("/me");session.abort();assert.equal(passedSignal.aborted,true);
});

test("analysis summaries make incomplete MobSF coverage visible and retain actual DEX counts", () => {
  const {details,warning}=analysisCoverageSections({dex_summary:{dex_files:2,classes:11,methods:31,analyzed_methods:19,strings:87,code_units:104},mobsf_summary:{service_version:"4.5.3",manifest_findings:3,code_findings:7,certificate_findings:0,binary_findings:0,secret_candidates:2,tool_error_count:1,analysis_complete:false}});
  assert.match(warning,/MobSF analysis is incomplete/);assert.match(warning,/engine tools reported an error/);
  for(const label of ["DEX files","Classes","Method references","Analyzed methods","String references","Code units","Service version","Manifest candidates","Code candidates","Certificate candidates","Binary candidates","Secret-like candidates","Tool errors"])assert.ok(details.includes(label));
  assert.match(details,/<dd>19<\/dd>/);assert.match(details,/<dd>87<\/dd>/);assert.match(details,/Incomplete — tool errors/);
  assert.equal(analysisCoverageSections({mobsf_summary:{analysis_complete:true}}).warning,"");
  const hostile=analysisCoverageSections({mobsf_summary:{service_version:'<script>alert(1)</script>',tool_error_count:'<img src=x>'}});
  assert.doesNotMatch(hostile.details,/<script>|<img/);assert.match(hostile.details,/&lt;script&gt;/);assert.match(hostile.details,/Not reported/);
});

test("runtime scenarios require explicit configured capabilities", () => {
  assert.deepEqual(dynamicScenarioOptions({dynamic:{configured:false,frida:{configured:true}}}),[]);
  assert.deepEqual(dynamicScenarioOptions({dynamic:{configured:true}}).map(([id])=>id),["package_inspection","launch_observe"]);
  assert.deepEqual(dynamicScenarioOptions({dynamic:{configured:true,frida:{configured:true},proxy:{configured:true}}}).map(([id])=>id),["package_inspection","launch_observe","frida_observe","proxy_observe"]);
  assert.equal(dynamicScenarioOptions({dynamic:{configured:true,frida:{configured:"true"}}}).length,2);
});

test("Frida evidence uses built-in counters and describes its bounded coverage", () => {
  const html=runtimeEvidenceSections({frida:{version:"17.9.10",observation_seconds:3,hooked_apis:["socket_connect"],counters:{socket_connect:5,filesystem_open:0,unexpected_secret:"never-render"}}});
  assert.match(html,/Frida API observation/);assert.match(html,/<td>Native socket connect<\/td><td>Yes<\/td><td>5<\/td>/);
  assert.match(html,/bounded launch only/);assert.match(html,/does not establish unsafe use/);assert.doesNotMatch(html,/unexpected_secret|never-render/);
  const hostile=runtimeEvidenceSections({frida:{version:'<script>alert(1)</script>',observation_seconds:-3,counters:{socket_connect:"secret"}}});
  assert.doesNotMatch(hostile,/<script>|<td>secret<\/td>/);assert.match(hostile,/&lt;script&gt;/);assert.match(hostile,/Not reported/);
});

test("structured API endpoints preserve expected authentication and reject ambiguous requests", () => {
  const form=new FormData();form.set("endpoint_url_0"," https://api.example.com/v1/profile ");form.set("endpoint_method_0","GET");form.set("endpoint_auth_0","on");form.set("endpoint_url_4","https://api.example.com/v1/status");form.set("endpoint_method_4","HEAD");form.set("token","never collect this");
  assert.deepEqual(endpointsFromForm(form),[{url:"https://api.example.com/v1/profile",method:"GET",expect_authentication:true},{url:"https://api.example.com/v1/status",method:"HEAD",expect_authentication:false}]);
  assert.deepEqual(valuesFromFields([{name:"endpoints",kind:"endpoints"}],form).endpoints,endpointsFromForm(form));
  for(const url of ["http://api.example.com/","https://token@api.example.com/","https://api.example.com/?token=secret","https://api.example.com/#fragment","javascript:alert(1)"])assert.throws(()=>exactHTTPSURL(url),/HTTPS/);
  form.set("endpoint_method_0","POST");assert.throws(()=>endpointsFromForm(form),/GET or HEAD/);
  assert.throws(()=>endpointsFromForm(new FormData()),/between 1 and 20/);
});

test("API baseline results show independent account observations and no raw response fields", () => {
  const observation={status:200,response_bytes:35,truncated:true,tls_verified:true,hsts_present:false,content_type_present:true};
  const html=apiEvidenceSections({engine_version:"droidshield-api-1",requests_sent:3,endpoints:[{endpoint_index:0,method:"GET",anonymous:observation,primary:observation,secondary:observation,comparison:"same_bounded_response",unexpected_anonymous_success:true,response_body:"private-data-must-not-render"}],limitations:["Manual review required"]});
  assert.match(html,/Endpoint 1/);assert.match(html,/Primary account/);assert.match(html,/Secondary account/);assert.match(html,/200 · 35 B · bounded/);assert.match(html,/Anonymous success requires review/);assert.match(html,/Manual review required/);assert.doesNotMatch(html,/private-data-must-not-render/);
  const hostile=apiEvidenceSections({engine_version:"<img src=x>",requests_sent:"secret",endpoints:[{endpoint_index:0,method:"<script>",anonymous:{status:200,response_bytes:"secret"},comparison:"<script>"}],limitations:["<script>alert(1)</script>"]});
  assert.doesNotMatch(hostile,/<script>|<img/);assert.match(hostile,/&lt;script&gt;/);assert.match(hostile,/Not reported/);
});

test("proxy evidence retains bounded counters and an indexed approved-target view", () => {
  const html=runtimeEvidenceSections({traffic:{requests_forwarded:1,blocked_requests:2,tls_failures:0,response_bytes:20,observations:[{target_index:0,method:"HEAD",status_code:204,tls_version:"TLSv1.3",response_bytes:20,request_headers:{authorization:"never-render"}}]}});
  assert.match(html,/Target 1/);assert.match(html,/TLSv1.3/);assert.match(html,/certificate pinning is not bypassed/);assert.doesNotMatch(html,/never-render|authorization/);
});

test("distributed browser assets do not persist tokens or load executable third-party content", async () => {
  const [html,js,css]=await Promise.all([readFile(new URL("../backend/droidshield/web/index.html",import.meta.url),"utf8"),readFile(new URL("../backend/droidshield/web/app.js",import.meta.url),"utf8"),readFile(new URL("../backend/droidshield/web/styles.css",import.meta.url),"utf8")]);
  assert.doesNotMatch(js,/localStorage|sessionStorage|document\.cookie|eval\(/);
  assert.match(js,/name="email"/);assert.match(js,/name="password"/);assert.match(js,/\/auth\/session/);
  assert.doesNotMatch(js,/name="token"|Workspace access token|Authorization:\s*`Bearer/);
  assert.match(js,/credentials:"same-origin"/);
  assert.match(html,/<script type="module" src="\/assets\/app\.js\?v=0\.5\.19"><\/script>/);
  assert.match(js,/<caption class="visually-hidden">\$\{e\(columns\[0\]\)\} records<\/caption>/);
  assert.doesNotMatch(js,/Portfolio preview · synthetic records\./);
  assert.match(css,/dialog\.record-drawer\s*\{/);
  assert.match(js,/event\.target!==dialog\|\|!dialog\.classList\.contains\("record-drawer"\)/);
  assert.match(js,/clientX<rect\.left\|\|event\.clientX>rect\.right\|\|event\.clientY<rect\.top\|\|event\.clientY>rect\.bottom/);
  assert.match(css,/\.record-summary/);assert.match(css,/\.record-section \.detail-list/);
  assert.doesNotMatch(html+css,/https?:\/\//);
  assert.doesNotMatch(html,/\bon(?:click|submit|load)\s*=/i);
  assert.doesNotMatch(js,/\bon(?:click|submit|error)\s*=/i);
  assert.match(js,/filter-controls/);assert.match(js,/Reset filters/);assert.match(js,/filterTimer=setTimeout/);
  assert.doesNotMatch(js,/Apply filters|View targets|View sessions|View assessment<\/button>/);
  assert.match(css,/\.filter-footer[\s\S]*justify-content:\s*space-between/);
  assert.match(css,/\.client-pagination\.table-foot[\s\S]*justify-content:\s*center/);
  assert.match(css,/\.client-pagination-controls \{ width: auto; justify-content: center; \}/);
  assert.match(css,/\.card:has\(\.table-wrap\) \.card-head h2 \{ color: #f0fbfc; \}/);
  assert.match(css,/\.table-wrap th:nth-child\(4n \+ 3\) \{ color: #d4baff; border-bottom-color: #a980ed; \}/);
  assert.match(css,/\.table-wrap tbody tr:nth-child\(4n \+ 2\) td:first-child \{ box-shadow: inset 3px 0 #58a9f6; \}/);
  assert.match(css,/\.table-wrap \.view-action:hover[\s\S]*box-shadow: 0 0 14px/);
  assert.match(js,/data-page-key=/);
});


test("assessment workflow labels distinguish real automation from manual engagements",()=>{
  assert.equal(assessmentWorkflowLabel({assessment_type:"full",engine:"manifest"}),"Manual engagement");
  assert.equal(assessmentWorkflowLabel({assessment_type:"static",engine:"dex",execution_mode:"analyst_record"}),"Manual engagement");
  assert.equal(assessmentWorkflowLabel({assessment_type:"api",engine:"manifest"}),"HTTPS API baseline");
  assert.equal(assessmentWorkflowLabel({assessment_type:"dynamic",engine:"manifest"}),"Android lab");
  assert.equal(assessmentWorkflowLabel({assessment_type:"dynamic",status:"cancelled"}),"Workflow cancelled");
  assert.equal(assessmentWorkflowLabel({assessment_type:"static",engine:"dex"}),"Dex analysis");
});

test("cancelled dynamic records do not imply a launched lab device",()=>{
  assert.equal(dynamicDeviceLabel("not-launched"),"Not launched");
  assert.equal(dynamicDeviceLabel("pixel-7-api34"),"pixel-7-api34");
});


test("retest comparison shows full build provenance and preserves API-only release identity",()=>{
  const hash="abcdef0123456789".repeat(4),html=comparisonArtifactMarkup({id:"artifact-id",original_filename:"Client <release>.ipa",version_name:"2.4.1",version_code:null,metadata:{build_number:"142"},build_type:"release",artifact_format:"ipa",sha256:hash,storage_ref:"must-not-render"});
  for(const value of [hash,"2.4.1","142","IPA","artifact-id","Client &lt;release&gt;.ipa"])assert.ok(html.includes(value));
  assert.doesNotMatch(html,/storage_ref|must-not-render|<release>/);
  const apiOnly=comparisonArtifactMarkup(null,{releaseRef:"deployment-2026.11"});
  assert.match(apiOnly,/deployment-2026.11/);assert.match(apiOnly,/Analyst-declared release/);assert.doesNotMatch(apiOnly,/SHA-256|Artifact ID/);
});
