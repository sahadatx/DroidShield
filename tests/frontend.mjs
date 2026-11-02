import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { ApiError, analysisCoverageSections, apiEvidenceSections, artifactFormat, assessmentWorkflowLabel, coverageMatrixMarkup, comparisonArtifactMarkup, createApi, dynamicScenarioOptions, dynamicDeviceLabel, endpointsFromForm, escapeHTML, exactHTTPSURL, formatBytes, kpiCards, makeQuery, metricCount, overviewFilterPanel, pager, parseRoute, reportSnapshotMarkup, runtimeEvidenceSections, splitTargets, valuesFromFields, viewAction } from "../backend/droidshield/web/app.js";

test("untrusted markup is encoded in text and attribute contexts", () => {
  assert.equal(escapeHTML('<img src=x onerror="alert(1)"> & \'x\''), "&lt;img src=x onerror=&quot;alert(1)&quot;&gt; &amp; &#39;x&#39;");
  assert.equal(escapeHTML(null), "");
});

test("navigation accepts known pages and bounded record identities only", () => {
  assert.deepEqual(parseRoute("#projects/01970000-1234-1234-1234-123456789abc"), {page:"projects",id:"01970000-1234-1234-1234-123456789abc"});
  assert.deepEqual(parseRoute("#https://example.com"), {page:"overview",id:null});
  assert.equal(parseRoute('#findings/<script>').id, null);
  assert.equal(parseRoute('').page, "overview");
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
  for(const name of ["project_id","assessment_type","assessment_status","date_from","date_to"])assert.match(html,new RegExp(`name="${name}"`));
  assert.match(html,/Reset filters/);assert.match(html,/Results update automatically/);
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

test("report snapshots remain escaped review content and protected exports use authenticated reads", async () => {
  assert.doesNotMatch(reportSnapshotMarkup({executive_summary:"<svg onload=evil>"}),/<svg/);
  assert.match(reportSnapshotMarkup({limitations:"Not run"}),/Not run/);
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
  assert.match(html,/<script type="module" src="\/assets\/app\.js\?v=0\.5\.16"><\/script>/);
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
