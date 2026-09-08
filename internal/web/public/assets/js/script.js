let activationBaseUrl="";let pendingToken=false;
// First-run database selection state machine (pure, no DOM access).
// The dashboard DOM layer maps computeState()'s result onto hidden/disabled
// attributes; the Node regression suite drives computeState() through every
// transition without a browser. State contracts:
//
//   mode        "first-run" | "sign-in"
//   selectable  whether the provider may still be chosen (false after a
//               connection is persisted or when startup fixed the provider)
//   provider    "sqlite" | "postgres"
//   url         the PostgreSQL URL field value
//
// Invariants covered by the regression suite:
//   - an empty PostgreSQL URL leaves the test button disabled;
//   - a non-empty URL enables it;
//   - the first-administrator form is never shown together with the
//     PostgreSQL configuration form;
//   - after the connection is persisted (selectable=false) the interface
//     returns to administrator creation, never to a sign-in form, because the
//     auth gate copy is single-sourced and mutually exclusive.
globalThis.TrestleDatabaseSetup = (() => {
  function computeState(state) {
    const firstRun = state.mode === "first-run";
    const pendingPostgres = firstRun && state.selectable && state.provider === "postgres";
    const urlNonEmpty = Boolean(state.url && state.url.trim());
    return {
      previewVisible: firstRun,
      postgresConfigVisible: pendingPostgres,
      applyVisible: pendingPostgres,
      applyEnabled: pendingPostgres && urlNonEmpty,
      adminFormVisible: !pendingPostgres,
      registrationPolicyVisible: firstRun && !pendingPostgres,
      adminEmailRequired: !pendingPostgres,
      adminPasswordRequired: !pendingPostgres
    };
  }
  function authGateCopy(setupRequired) {
    return setupRequired
      ? {
          kicker: "First-run setup",
          title: "Create the administrator account",
          description:
            "This deployment has no administrator yet. The account you create grants access to every administration surface.",
          submitLabel: "Create administrator",
          autocomplete: "new-password"
        }
      : {
          kicker: "",
          title: "",
          description: "",
          submitLabel: "Sign in",
          autocomplete: "current-password"
        };
  }
  function restartNotice(version) {
    return {
      heading: "Restart required",
      body: `PostgreSQL ${version} is configured. Stop and start Trestle, then reload this page to create the administrator account.`
    };
  }
  // connectionState maps the process/database readiness probe to operator
  // copy: a clear heading, a consequence, and a next action. States: connecting
  // (initial), ready, starting (not_ready), databaseUnavailable (degraded) and
  // unreachable (network/process). Recovery is the transition back to ready on
  // a later successful probe.
  function connectionState(phase, errorCode) {
    if (phase === "connecting") {
      return {
        heading: "Connecting to Trestle",
        description: "Checking process and database readiness.",
        stateLabel: "Checking",
        kind: "connecting",
        nextAction: "This is a startup check. It resolves on its own."
      };
    }
    if (phase === "ready") {
      return {
        heading: "Trestle is ready",
        description: "The process and database are accepting work.",
        stateLabel: "Ready",
        kind: "ready",
        nextAction: "Nothing to do."
      };
    }
    if (phase === "databaseUnavailable") {
      return {
        heading: "Database unavailable",
        description: "The process is up but the database connection failed.",
        stateLabel: "Unavailable",
        kind: "databaseUnavailable",
        nextAction: "Check the database and the server logs, then retry."
      };
    }
    if (phase === "starting") {
      return {
        heading: "Trestle is starting",
        description: "Startup has not finished yet.",
        stateLabel: "Starting",
        kind: "starting",
        nextAction: "Check back shortly."
      };
    }
    return {
      heading: "Trestle is unreachable",
      description: "The server did not respond to the readiness probe.",
      stateLabel: "Unreachable",
      kind: "unreachable",
      nextAction: "Check the process, network and logs, then retry."
    };
  }
  return { computeState, authGateCopy, restartNotice, connectionState, viewState, staleState };
})();

// viewState is a reusable degraded-state component for dashboard panes. It
// maps a state kind and optional detail to plain-language operator copy: what
// happened, the operational consequence, and a specific next action. Kinds:
// loading, empty, error (permission-denied / partial-failure / unavailable),
// retrying, dead, deletionPending, stale. It never includes credentials or
// internal secrets.
// staleState is the documented realtime staleness rule: stale means a missing
// transport heartbeat, not merely "no business events recently". The server
// emits an observable `heartbeat` SSE event every 15 seconds and the client
// refreshes its activity time on every heartbeat, so an otherwise idle stream
// never goes stale. A stream is stale when no heartbeat (or business event)
// has arrived within the 30-second window and the stream is not paused. It is
// pure so a clock-controlled regression can prove the inactivity/recovery
// transitions without a browser.
function staleState(lastActivity, now, paused) {
  if (paused) return false;
  return now - lastActivity > 30000;
}
function viewState(kind, opts) {
  opts = opts || {};
  switch (kind) {
    case "loading":
      return { kind, title: "Loading", message: "Loading this view.", consequence: "No data is shown yet.", nextAction: "This resolves on its own." };
    case "empty":
      return { kind, title: "Nothing here yet", message: opts.message || "This view has no data yet.", consequence: "Nothing to show.", nextAction: "Create the first item to see it here." };
    case "error":
      const code = opts.code || "";
      if (code === "permissionDenied" || code === "authorization_denied") {
        return { kind, title: "Permission denied", message: "You do not have permission to view or change this.", consequence: "The action was not applied.", nextAction: "Ask an administrator for the required access." };
      }
      if (code === "database_unavailable") {
        return { kind, title: "Database unavailable", message: "The database connection failed.", consequence: "This view cannot load data right now.", nextAction: "Check the database and server logs, then retry." };
      }
      return { kind, title: "Could not load this view", message: opts.message || "The request could not be completed.", consequence: "The requested operation did not finish.", nextAction: "Check server logs, then retry." };
    case "retrying":
      return { kind, title: "Job is retrying", message: opts.message || "The job failed and is scheduled to retry.", consequence: "It is not complete yet.", nextAction: "You can wait for the retry or cancel the job." };
    case "dead":
      return { kind, title: "Job failed permanently", message: opts.message || "The job exhausted its retries.", consequence: "It will not run again automatically.", nextAction: "Retry the job or investigate the last error." };
    case "deletionPending":
      return { kind, title: "File deletion is pending", message: "The file is marked for deletion and is unavailable.", consequence: "The stored object has not been removed yet.", nextAction: "Trestle retries automatically; you can also trigger cleanup." };
    case "stale":
      return { kind, title: "Realtime connection is stale", message: "The live event stream has not delivered recently.", consequence: "Events may be delayed.", nextAction: "Check the connection and re-open the stream." };
    default:
      return { kind: "error", title: "Could not load this view", message: "The request could not be completed.", consequence: "The requested operation did not finish.", nextAction: "Check server logs, then retry." };
  }
}
const statusCard=document.querySelector("#status-card");const databaseState=document.querySelector("#database-state");const databaseProvider=document.querySelector("#database-provider");const connection=document.querySelector("#connection");const retry=document.querySelector("#retry");function renderViewState(host,state){host.className="view-state "+state.kind;host.tabIndex=-1;host.setAttribute("role","status");host.innerHTML=`<div class="view-state-body"><h3>${escapeHTML(state.title)}</h3><p class="view-message">${escapeHTML(state.message)}</p><p class="view-consequence">${escapeHTML(state.consequence)}</p><p class="view-next-action"><strong>Next:</strong> ${escapeHTML(state.nextAction)}</p></div>`;host.focus({preventScroll:true})}
function applyConnection(state){statusCard.className="status-card "+state.kind;statusCard.querySelector("h2").textContent=state.heading;statusCard.querySelector("p").textContent=state.description;statusCard.querySelector(".next-action").textContent=state.nextAction;databaseState.textContent=state.stateLabel;databaseProvider.textContent=window.trestleProvider||"Configured";connection.className="connection "+state.kind;connection.querySelector("span").textContent=state.stateLabel}async function check(){const connecting=TrestleDatabaseSetup.connectionState("connecting");statusCard.className="status-card";statusCard.querySelector("h2").textContent=connecting.heading;statusCard.querySelector("p").textContent=connecting.description;databaseState.textContent=connecting.stateLabel;retry.disabled=true;let state;try{const response=await fetch("/system/ready",{headers:{Accept:"application/json"}});if(response.ok){state=TrestleDatabaseSetup.connectionState("ready")}else{const body=await response.json().catch(()=>null);state=body&&body.error&&body.error.code==="database_unavailable"?TrestleDatabaseSetup.connectionState("databaseUnavailable"):TrestleDatabaseSetup.connectionState("starting")}}catch{state=TrestleDatabaseSetup.connectionState("unreachable")}applyConnection(state);retry.disabled=false}retry.addEventListener("click",check);const mobile=document.querySelector(".mobile-nav");const rail=document.querySelector("#primary-nav");mobile.addEventListener("click",()=>{const open=mobile.getAttribute("aria-expanded")==="true";mobile.setAttribute("aria-expanded",String(!open));rail.classList.toggle("open",!open)});document.addEventListener("keydown",event=>{if(event.key==="Escape"&&rail.classList.contains("open")){rail.classList.remove("open");mobile.setAttribute("aria-expanded","false");mobile.focus()}});document.querySelectorAll("[data-route]").forEach(link=>link.addEventListener("click",event=>{event.preventDefault();selectDashboardRoute(link.dataset.route,link.textContent,link.getAttribute("href"))}));check();
const authGate=document.querySelector("#auth-gate");const authForm=document.querySelector("#auth-form");const authTitle=document.querySelector("#auth-title");const authDescription=document.querySelector("#auth-description");const authKicker=document.querySelector("#auth-kicker");const authEmail=document.querySelector("#auth-email");const authPassword=document.querySelector("#auth-password");const authError=document.querySelector("#auth-error");let setupRequired=false;let csrfToken="";async function jsonRequest(url,options={}){const response=await fetch(url,{...options,headers:{Accept:"application/json","Content-Type":"application/json",...(options.headers||{})}});const body=response.status===204?null:await response.json().catch(()=>null);if(response.status===401){await handleSessionExpired()}if(!response.ok){const error=new Error(body?.error?.message||`The request could not be completed (${response.status}).`);error.code=body?.error?.code||"unknown";error.status=response.status;throw error}return body}async function handleSessionExpired(){try{const session=await jsonRequest("/admin/v1/session");if(!session.authenticated){const view=document.querySelector("#view-content");if(view){view.hidden=true}document.querySelector("#overview-content")?.setAttribute("hidden","");const copy=TrestleDatabaseSetup.authGateCopy(false);authKicker.textContent="Session expired";authTitle.hidden=false;authDescription.hidden=false;authTitle.textContent="Session expired";authDescription.textContent="Your session ended. Sign in again to continue.";authPassword.autocomplete=copy.autocomplete;authForm.querySelector("#auth-submit").textContent=copy.submitLabel;authForm.classList.remove("first-run");authGate.classList.remove("hidden");authEmail.focus();return true}}catch{}return false}
async function initializeAuth(){try{const session=await jsonRequest("/admin/v1/session");window.trestleProvider=session.provider||"";if(session.authenticated){authGate.classList.add("hidden");check();window.dispatchEvent(new Event("trestle:authenticated"));return}const setup=await jsonRequest("/admin/v1/setup/status");setupRequired=setup.setupRequired;authForm.classList.toggle("first-run",setupRequired);const copy=TrestleDatabaseSetup.authGateCopy(setupRequired);authKicker.textContent=copy.kicker;authKicker.hidden=!setupRequired;authTitle.hidden=!setupRequired;authDescription.hidden=!setupRequired;authTitle.textContent=copy.title;authDescription.textContent=copy.description;authPassword.autocomplete=copy.autocomplete;authForm.querySelector("#auth-submit").textContent=copy.submitLabel;syncDatabaseFields();authEmail.focus()}catch{authTitle.textContent="Trestle is unavailable";authDescription.textContent="Check the server and database, then reload this page.";authForm.querySelector("button").disabled=true}}authForm.addEventListener("submit",async event=>{event.preventDefault();authError.textContent="";if(setupRequired&&databaseSelectable&&selectedDatabase()==="postgres"){authError.textContent="Test and save the PostgreSQL connection before creating the administrator.";databasePreview.querySelector('[name="database-url"]').focus();return}const button=authForm.querySelector("#auth-submit");button.disabled=true;try{const body=setupRequired?{email:authEmail.value,password:authPassword.value,applicationRegistrationPolicy:document.getElementById("auth-policy").value}:{email:authEmail.value,password:authPassword.value};const session=await jsonRequest(setupRequired?"/admin/v1/setup":"/admin/v1/session",{method:"POST",body:JSON.stringify(body)});csrfToken=session.csrfToken||"";authPassword.value="";authGate.classList.add("hidden");check();window.dispatchEvent(new Event("trestle:authenticated"))}catch(error){authError.textContent=error.message;authPassword.focus();authPassword.select()}finally{button.disabled=false}});initializeAuth();
const collectionDraftKey="trestle-collection-draft";
const fieldTypeOptions=["text","number","boolean","datetime","json","select","relation","email","url"].map(type=>`<option value="${type}">${type}</option>`).join("");
function collectionFieldRow(values={}){const row=document.createElement("div");row.className="collection-field-row";row.innerHTML=`<label>Field name<input name="field" pattern="[a-z][a-z0-9_]{0,62}" placeholder="title" value="${escapeHTML(values.name||"")}" required></label><label>Type<select name="type">${fieldTypeOptions}</select></label><div class="field-options"><label class="check"><input name="required" type="checkbox"> <span>Required</span></label><label class="check"><input name="unique" type="checkbox"> <span>Unique</span></label></div><button type="button" data-remove-field aria-label="Remove field">Remove</button>`;row.querySelector("select").value=values.type||"text";row.querySelector('[name="required"]').checked=Boolean(values.required);row.querySelector('[name="unique"]').checked=Boolean(values.unique);row.querySelector("[data-remove-field]").addEventListener("click",()=>{if(row.parentElement.children.length>1){const form=row.closest("form");row.remove();saveCollectionDraft(form)}});return row}
function readCollectionDraft(form){return{name:form.elements.collection.value,fields:[...form.querySelectorAll(".collection-field-row")].map(row=>({name:row.querySelector('[name="field"]').value,type:row.querySelector('[name="type"]').value,required:row.querySelector('[name="required"]').checked,unique:row.querySelector('[name="unique"]').checked}))}}
function saveCollectionDraft(form){if(form)localStorage.setItem(collectionDraftKey,JSON.stringify(readCollectionDraft(form)))}
function restoreCollectionDraft(form,fields){let draft;try{draft=JSON.parse(localStorage.getItem(collectionDraftKey)||"null")}catch{}form.elements.collection.value=draft?.name||"";fields.replaceChildren(...(draft?.fields?.length?draft.fields:[{}]).map(collectionFieldRow))}
async function renderCollections(collection){document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;const host=document.getElementById("view-content");host.hidden=false;host.className="collection-view";host.innerHTML='<div class="collection-toolbar"><div><p class="eyebrow">Base collections</p><h2>Collection metadata</h2></div></div><form class="collection-form"><label class="collection-name">Collection name<input name="collection" pattern="[a-z][a-z0-9_]{0,62}" placeholder="issues" required></label><div class="collection-fields"></div><div class="collection-actions"><button type="button" data-add-field>Add field</button><button type="submit">Create collection</button></div></form><p class="view-error" role="alert"></p><div class="collection-list">Loading collections…</div>';const form=host.querySelector("form");const fields=form.querySelector(".collection-fields");restoreCollectionDraft(form,fields);form.addEventListener("input",()=>saveCollectionDraft(form));form.addEventListener("change",()=>saveCollectionDraft(form));form.querySelector("[data-add-field]").addEventListener("click",()=>{fields.append(collectionFieldRow());saveCollectionDraft(form);fields.lastElementChild.querySelector("input").focus()});form.addEventListener("submit",async event=>{event.preventDefault();const draft=readCollectionDraft(form);try{await jsonRequest("/admin/v1/collections",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({name:draft.name,fields:draft.fields})});localStorage.removeItem(collectionDraftKey);form.reset();fields.replaceChildren(collectionFieldRow());await loadCollections(host)}catch(error){host.querySelector(".view-error").textContent=error.message}});await loadCollections(host);if(collection)renderRecords(collection)}
async function loadCollections(host){try{const response=await jsonRequest("/admin/v1/collections");const list=host.querySelector(".collection-list");if(response.items.length===0){list.innerHTML='<section class="empty"><h2>No collections yet</h2><p>Add as many typed fields as the collection needs, then create it above.</p></section>';return}list.innerHTML='<div class="table-scroll"><table class="collection-table"><thead><tr><th>Name</th><th>Kind</th><th>Updated</th><th></th></tr></thead><tbody>'+response.items.map(item=>`<tr><td><button class="text-action" data-open="${item.name}" type="button">${item.name}</button></td><td>${item.kind}</td><td>${new Date(item.updatedAt).toLocaleString()}</td><td><button class="danger-action" data-delete="${item.name}" type="button">Delete</button></td></tr>`).join("")+'</tbody></table></div>';list.querySelectorAll("[data-open]").forEach(button=>button.addEventListener("click",()=>openCollectionRoute(button.dataset.open)));list.querySelectorAll("[data-delete]").forEach(button=>button.addEventListener("click",async()=>{if(!confirm(`Delete ${button.dataset.delete} and every record it contains?`))return;try{await jsonRequest(`/admin/v1/collections/${button.dataset.delete}`,{method:"DELETE",headers:{"X-Trestle-CSRF":csrfToken}});await loadCollections(host)}catch(error){host.querySelector(".view-error").textContent=error.message}}))}catch(error){host.querySelector(".view-error").textContent=error.message}}

const databasePreview=document.querySelector("#database-preview");
const postgresConfiguration=document.querySelector("#postgres-configuration");
const databaseResult=document.querySelector("#database-result");
const databaseApply=document.querySelector("#database-apply");
const databaseUrlInput=databasePreview.querySelector('[name="database-url"]');
function selectedDatabase(){return databasePreview.querySelector('[name="database-provider"]:checked').value}
const administratorFields=document.querySelector("#administrator-fields");
let databaseSelectable=false;
function databaseSetupState(){return TrestleDatabaseSetup.computeState({mode:authForm.classList.contains("first-run")?"first-run":"sign-in",selectable:databaseSelectable,provider:selectedDatabase(),url:databaseUrlInput.value})}
function syncDatabaseFields(){const state=databaseSetupState();databasePreview.hidden=!state.previewVisible;postgresConfiguration.hidden=!state.postgresConfigVisible;databaseApply.hidden=!state.applyVisible;databaseApply.disabled=!state.applyEnabled;administratorFields.hidden=!state.adminFormVisible;document.querySelector("#registration-policy-field").hidden=!state.registrationPolicyVisible;authEmail.required=state.adminEmailRequired;authPassword.required=state.adminPasswordRequired;authForm.querySelector("#auth-submit").textContent=TrestleDatabaseSetup.authGateCopy(setupRequired).submitLabel;if(!state.postgresConfigVisible){databaseResult.textContent="";databaseResult.className=""}}
function syncDatabaseApply(){databaseApply.disabled=!databaseSetupState().applyEnabled}
new MutationObserver(syncDatabaseFields).observe(authForm,{attributes:true,attributeFilter:["class"]});
databaseUrlInput.addEventListener("input",syncDatabaseApply);
databasePreview.addEventListener("change",syncDatabaseFields);
databaseApply.addEventListener("click",async()=>{databaseResult.textContent="Testing PostgreSQL…";databaseResult.className="";databaseApply.disabled=true;try{const result=await jsonRequest("/admin/v1/database/setup",{method:"POST",body:JSON.stringify({provider:"postgres",url:databaseUrlInput.value})});databaseSelectable=false;databasePreview.disabled=true;const notice=TrestleDatabaseSetup.restartNotice(result.version);databaseResult.className="restart-notice";databaseResult.innerHTML=`<strong>${escapeHTML(notice.heading)}</strong><span>${escapeHTML(notice.body)}</span>`;administratorFields.hidden=true;postgresConfiguration.hidden=true}catch(error){databaseResult.textContent=error.message;databaseResult.className=""}finally{syncDatabaseApply()}});
async function loadDatabaseSetup(){try{const result=await jsonRequest("/admin/v1/database/setup");databaseSelectable=Boolean(result.selectable);const radio=databasePreview.querySelector(`[value="${result.provider}"]`);if(radio)radio.checked=true;databasePreview.disabled=!databaseSelectable;syncDatabaseFields()}catch{}}
loadDatabaseSetup();syncDatabaseFields();
async function refreshCSRF(){try{const session=await jsonRequest("/admin/v1/session");if(session.csrfToken)csrfToken=session.csrfToken}catch{}}refreshCSRF();

const recordPageSize=25;
async function renderRecords(collection){
  document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;
  const host=document.getElementById("view-content");host.hidden=false;
  renderViewState(host,TrestleDatabaseSetup.viewState("loading"));document.getElementById("view-title").textContent=collection;host.className="record-view";host._recordState={cursor:"",history:[],page:1,blockedNext:""};
  try{
    const schema=await jsonRequest(`/admin/v1/collections/${encodeURIComponent(collection)}`);
    host.innerHTML=`<div class="record-toolbar"><div><p class="eyebrow">Collection records</p><h2>${escapeHTML(collection)}</h2></div><button type="button" data-new-record>New record</button></div><form class="query-bar"><label>Filter expression<input name="filter" placeholder='status = "open" && score >= 3'></label><label>Sort<input name="sort" placeholder="id"></label><button>Apply</button><button type="button" data-copy-query>Copy request</button></form><p class="view-error" role="alert"></p><div class="record-list">Loading records…</div><dialog class="record-dialog"><form method="dialog"><div class="dialog-heading"><div><p class="eyebrow">JSON editor</p><h2>Record values</h2></div></div><div class="json-editor"><pre aria-hidden="true"><code></code></pre><textarea name="record-json" aria-label="Record JSON" autocomplete="off" autocapitalize="off" spellcheck="false"></textarea></div><p class="dialog-hint">Field names come from the collection schema. Values are validated when saved.</p><p class="dialog-error" role="alert"></p><div class="dialog-actions"><button value="cancel">Cancel</button><button value="save">Save record</button></div></form></dialog>`;
    const dialog=host.querySelector("dialog");setupJSONEditor(dialog);
    host.querySelector("[data-new-record]").addEventListener("click",()=>openRecordDialog(dialog,schema.fields,{},"",""));
    dialog.addEventListener("close",async()=>{if(dialog.returnValue!=="save")return;try{const values=readRecordJSON(dialog);const id=dialog.dataset.id;const options={method:id?"PATCH":"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({values})};if(id)options.headers["If-Match"]=`"${dialog.dataset.version}"`;await jsonRequest(`/admin/v1/data/${encodeURIComponent(collection)}/records${id?`/${encodeURIComponent(id)}`:""}`,options);dialog.querySelector(".dialog-error").textContent="";await loadRecords(collection,host,schema)}catch(error){dialog.querySelector(".dialog-error").textContent=error.message;dialog.showModal()}});
    const queryForm=host.querySelector(".query-bar");const saved=JSON.parse(localStorage.getItem(`trestle-query:${collection}`)||"{}");queryForm.elements.filter.value=saved.filter||"";queryForm.elements.sort.value=saved.sort||"";queryForm.addEventListener("submit",event=>{event.preventDefault();localStorage.setItem(`trestle-query:${collection}`,JSON.stringify({filter:queryForm.elements.filter.value,sort:queryForm.elements.sort.value}));host._recordState={cursor:"",history:[],page:1,blockedNext:""};loadRecords(collection,host,schema)});host.querySelector("[data-copy-query]").addEventListener("click",()=>navigator.clipboard.writeText(location.origin+recordListURL(collection,host)));
    await loadRecords(collection,host,schema);
  }catch(error){renderViewState(host,TrestleDatabaseSetup.viewState("error",{code:error.code,message:error.message}))}
}
function recordTemplate(fields){return Object.fromEntries(fields.map(field=>[field.name,field.type==="boolean"?false:field.type==="number"?0:field.type==="json"?{}:""]))}
function openRecordDialog(dialog,fields,values,id,version){dialog.dataset.id=id;dialog.dataset.version=version;dialog.returnValue="";dialog.querySelector("textarea").value=JSON.stringify(id?values:recordTemplate(fields),null,2);dialog.querySelector(".dialog-error").textContent="";updateJSONHighlight(dialog);dialog.showModal();dialog.querySelector("textarea").focus()}
function setupJSONEditor(dialog){const textarea=dialog.querySelector("textarea");textarea.addEventListener("input",()=>updateJSONHighlight(dialog));textarea.addEventListener("scroll",()=>{const pre=dialog.querySelector("pre");pre.scrollTop=textarea.scrollTop;pre.scrollLeft=textarea.scrollLeft});textarea.addEventListener("keydown",event=>{if(event.key!=="Tab")return;event.preventDefault();const start=textarea.selectionStart;textarea.setRangeText("  ",start,textarea.selectionEnd,"end");updateJSONHighlight(dialog)})}
function updateJSONHighlight(dialog){const textarea=dialog.querySelector("textarea");dialog.querySelector("code").innerHTML=highlightJSON(textarea.value)+"\n"}
function highlightJSON(source){const token=/("(?:\\.|[^"\\])*")(?=\s*:)|("(?:\\.|[^"\\])*")|\b(true|false)\b|\b(null)\b|-?\b\d+(?:\.\d+)?(?:e[+-]?\d+)?\b/gi;let output="",last=0;for(const match of source.matchAll(token)){output+=escapeHTML(source.slice(last,match.index));const kind=match[1]?"key":match[2]?"string":match[3]?"boolean":match[4]?"null":"number";output+=`<span class="json-${kind}">${escapeHTML(match[0])}</span>`;last=match.index+match[0].length}return output+escapeHTML(source.slice(last))}
function readRecordJSON(dialog){let values;try{values=JSON.parse(dialog.querySelector("textarea").value)}catch(error){throw new Error(`Invalid JSON: ${error.message}`)}if(!values||Array.isArray(values)||typeof values!=="object")throw new Error("Record values must be a JSON object.");return values}
async function loadRecords(collection,host,schema){try{host.querySelector(".view-error").textContent="";const response=await jsonRequest(recordListURL(collection,host));const list=host.querySelector(".record-list");if(!response.items.length&&host._recordState.page>1){const state=host._recordState;state.blockedNext=state.cursor;state.cursor=state.history.pop()||"";state.page--;await loadRecords(collection,host,schema);return}if(!response.items.length){list.innerHTML='<section class="empty"><h2>No records yet</h2><p>Create the first record using the JSON editor above.</p></section>';return}renderRecordTable(collection,host,schema,response)}catch(error){host.querySelector(".view-error").textContent=error.message}}
function renderRecordTable(collection,host,schema,response){const list=host.querySelector(".record-list");const state=host._recordState;list.innerHTML=`<div class="records-actions"><div><button type="button" data-delete-selected disabled>Delete selected</button><span data-selection-count>0 selected</span></div><span>Page ${state.page}</span></div><div class="table-scroll record-table-scroll"><table class="collection-table record-table"><thead><tr><th class="select-column"><input type="checkbox" data-select-page aria-label="Select this page"></th><th>ID</th>${schema.fields.map(field=>`<th>${escapeHTML(field.name)}</th>`).join("")}<th>Updated</th><th></th></tr></thead><tbody>${response.items.map(item=>`<tr><td class="select-column" data-label="Select"><input type="checkbox" data-select-record="${escapeHTML(item.id)}" aria-label="Select ${escapeHTML(item.id)}"></td><td data-label="ID"><code title="${escapeHTML(item.id)}">${escapeHTML(item.id)}</code></td>${schema.fields.map(field=>`<td data-label="${escapeHTML(field.name)}">${escapeHTML(displayRecordValue(item.values[field.name]))}</td>`).join("")}<td data-label="Updated">${new Date(item.updatedAt).toLocaleString()}</td><td class="row-actions"><button type="button" data-edit="${escapeHTML(item.id)}">Edit</button></td></tr>`).join("")}</tbody></table></div><div class="pagination"><button type="button" data-previous-page ${state.history.length?"":"disabled"}>Previous</button><span>Page ${state.page}</span><button type="button" data-next-page ${response.nextCursor&&response.nextCursor!==state.blockedNext&&cursorCompatible(host)?"":"disabled"}>Next</button></div>`;
  const selected=()=>[...list.querySelectorAll("[data-select-record]:checked")];const syncSelection=()=>{const count=selected().length;list.querySelector("[data-selection-count]").textContent=`${count} selected`;list.querySelector("[data-delete-selected]").disabled=count===0;const all=list.querySelectorAll("[data-select-record]");const page=list.querySelector("[data-select-page]");page.checked=all.length>0&&count===all.length;page.indeterminate=count>0&&count<all.length};list.querySelector("[data-select-page]").addEventListener("change",event=>{list.querySelectorAll("[data-select-record]").forEach(box=>box.checked=event.target.checked);syncSelection()});list.querySelectorAll("[data-select-record]").forEach(box=>box.addEventListener("change",syncSelection));
  list.querySelectorAll("[data-edit]").forEach(button=>button.addEventListener("click",()=>{const record=response.items.find(item=>item.id===button.dataset.edit);openRecordDialog(host.querySelector("dialog"),schema.fields,record.values,record.id,record.version)}));
  list.querySelector("[data-delete-selected]").addEventListener("click",async()=>{const ids=selected().map(box=>box.dataset.selectRecord);if(!ids.length||!confirm(`Delete ${ids.length} selected record${ids.length===1?"":"s"}?`))return;const button=list.querySelector("[data-delete-selected]");button.disabled=true;try{for(const id of ids){const record=response.items.find(item=>item.id===id);await jsonRequest(`/admin/v1/data/${encodeURIComponent(collection)}/records/${encodeURIComponent(id)}`,{method:"DELETE",headers:{"X-Trestle-CSRF":csrfToken,"If-Match":`"${record.version}"`}})}await loadRecords(collection,host,schema)}catch(error){host.querySelector(".view-error").textContent=error.message}});
  list.querySelector("[data-next-page]").addEventListener("click",()=>{state.history.push(state.cursor);state.cursor=response.nextCursor;state.page++;loadRecords(collection,host,schema)});list.querySelector("[data-previous-page]").addEventListener("click",()=>{state.cursor=state.history.pop()||"";state.page=Math.max(1,state.page-1);loadRecords(collection,host,schema)});
}
function cursorCompatible(host){const sort=host.querySelector(".query-bar").elements.sort.value.trim();return sort===""||sort==="id"}
function displayRecordValue(value){if(value==null)return "-";if(typeof value==="object")return JSON.stringify(value);return String(value)}
function recordListURL(collection,host){const form=host.querySelector(".query-bar");const params=new URLSearchParams({limit:String(cursorCompatible(host)?recordPageSize:100)});if(form?.elements.filter.value)params.set("filter",form.elements.filter.value);if(form?.elements.sort.value)params.set("sort",form.elements.sort.value);if(host._recordState?.cursor)params.set("cursor",host._recordState.cursor);return `/admin/v1/data/${encodeURIComponent(collection)}/records?${params}`}
function escapeHTML(value){return String(value).replace(/[&<>"']/g,char=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[char]))}
document.getElementById("logout").addEventListener("click",async()=>{const button=document.getElementById("logout");button.disabled=true;try{await jsonRequest("/admin/v1/session",{method:"DELETE",headers:{"X-Trestle-CSRF":csrfToken}});pendingToken=false;discardToken();window.location.assign("/")}catch(error){authError.textContent=error.message;authGate.classList.remove("hidden");authEmail.focus()}finally{button.disabled=false}});
function decorateSelects(root=document){root.querySelectorAll("select:not(.select-ready)").forEach(select=>{select.classList.add("select-ready");const wrapper=document.createElement("span");wrapper.className="select-control";select.before(wrapper);wrapper.append(select)})}decorateSelects();new MutationObserver(records=>records.forEach(record=>record.addedNodes.forEach(node=>{if(node.nodeType===1)decorateSelects(node)}))).observe(document.body,{childList:true,subtree:true});

function activationLink(token){if(!activationBaseUrl)return "";try{const u=new URL(activationBaseUrl);u.hash="invite="+token;return u.toString()}catch{return ""}}
function showToken(host, label, token){pendingToken=true;const link=activationBaseUrl?`<a class="text-link" href="${escapeHTML(activationLink(token))}">${escapeHTML(activationLink(token))}</a><br>`:"";host.querySelector(".provision-result").innerHTML=`<section class="secret-once"><strong>${escapeHTML(label)}</strong><p>Copy this now - it will not be shown again.</p>${link}<code>${escapeHTML(token)}</code> <button data-copy-inv="${escapeHTML(token)}">Copy token</button> <button data-dismiss-token>Dismiss</button></section>`;const copy=host.querySelector("[data-copy-inv]");if(copy)copy.addEventListener("click",()=>navigator.clipboard.writeText(copy.dataset.copyInv));const dismiss=host.querySelector("[data-dismiss-token]");if(dismiss)dismiss.addEventListener("click",()=>{dismissToken(host)})}

async function refreshLists(host){try{const [invitations,requests,users]=await Promise.all([jsonRequest("/admin/v1/app-registration/invitations"),jsonRequest("/admin/v1/app-registration/requests"),jsonRequest("/admin/v1/app-users")]);renderInvitations(host,invitations.items);renderRequests(host,requests.items);renderActivations(host,invitations.items);renderUsersList(host,users.items)}catch(error){host.querySelector(".view-error").textContent=error.message}}

function dismissToken(host){pendingToken=false;const p=host.querySelector(".provision-result");if(p)p.innerHTML="";}
function canIssueToken(host){if(pendingToken){const e=host.querySelector(".view-error");if(e)e.textContent="Dismiss the current activation token before issuing another.";return false}return true}
async function renderUsers(){document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;const host=document.getElementById("view-content");host.hidden=false;host.className="record-view users-view";host.innerHTML='<div class="record-toolbar"><div><p class="eyebrow">Application registration</p><h2>Users & registration</h2></div><button data-refresh-users>Refresh</button></div><p class="view-error" role="alert"></p><section class="settings-card"><h3>Your administrator account</h3><p>Change the password used to sign in to this administration console.</p><form class="admin-password-form user-settings-form"><label>Current password<input name="currentPassword" type="password" autocomplete="current-password" required></label><label>New password<input name="newPassword" type="password" autocomplete="new-password" minlength="7" required></label><label>Confirm new password<input name="confirmPassword" type="password" autocomplete="new-password" minlength="7" required></label><button>Change password</button><p class="password-note" role="status"></p></form></section><section class="settings-card"><h3>Registration policy</h3><form class="policy-form user-settings-form"><label>Policy<select name="policy"><option value="open">Open - anyone may register</option><option value="invite">Invite - registration requires an invitation</option><option value="approval">Approval - requests require administrator approval</option><option value="closed">Closed - only administrators can provision accounts</option></select></label><button data-save-policy>Save policy</button><p class="policy-note"></p></form></section><section class="settings-card"><h3>Activation link</h3><form class="baseurl-form user-settings-form"><label>Activation base URL<input name="baseurl" type="url" placeholder="https://app.example.com/register"></label><button class="baseurl-save">Save base URL</button><p class="baseurl-note"></p></form><p>When set, activation invites render as <code>#invite=&lt;token&gt;</code> fragment links on that origin; the raw token is always shown and never sent in request targets, proxy logs or referrer headers.</p></section><section class="settings-card"><h3>Provision a user</h3><form class="provision-form user-settings-form"><label>Email<input name="email" type="email" required></label><button class="provision-submit">Create activation token</button></form><p class="provision-result"></p></section><section class="settings-card"><h3>Invitations</h3><div class="invitation-list">Loading invitations…</div></section><section class="settings-card"><h3>Access requests</h3><div class="request-list">Loading requests…</div></section><section class="settings-card"><h3>Pending activations</h3><div class="activation-list">Loading activations…</div></section><section class="settings-card"><h3>Application users</h3><div class="user-list">Loading users…</div></section>';const passwordForm=host.querySelector(".admin-password-form");passwordForm.addEventListener("submit",async event=>{event.preventDefault();const note=passwordForm.querySelector(".password-note");const button=passwordForm.querySelector("button");note.textContent="";button.disabled=true;try{await jsonRequest("/admin/v1/password",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({currentPassword:passwordForm.elements.currentPassword.value,newPassword:passwordForm.elements.newPassword.value,confirmPassword:passwordForm.elements.confirmPassword.value})});passwordForm.reset();note.textContent="Password changed. Other administrator sessions have been signed out."}catch(error){note.textContent=error.message}finally{button.disabled=false}});host.querySelector("[data-refresh-users]").addEventListener("click",()=>refreshLists(host));await loadRegistration(host)}
async function loadRegistration(host){
  try{
    const [reg,invitations,requests,users]=await Promise.all([
      jsonRequest("/admin/v1/app-registration"),
      jsonRequest("/admin/v1/app-registration/invitations"),
      jsonRequest("/admin/v1/app-registration/requests"),
      jsonRequest("/admin/v1/app-users"),
    ]);
    const policyForm=host.querySelector(".policy-form");
    policyForm.elements.policy.value=reg.policy;
    policyForm.querySelector(".policy-note").textContent="Set at "+new Date(reg.setAt).toLocaleString()+".";
    policyForm.addEventListener("submit",async ev=>{
      ev.preventDefault();
      const value=policyForm.elements.policy.value;
      if(value==="open"&&!confirm("Open registration lets anyone on the Internet create an application account. Continue?"))return;
      try{const r=await jsonRequest("/admin/v1/app-registration/policy",{method:"PUT",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({policy:value,confirmOpen:value==="open"})});policyForm.querySelector(".policy-note").textContent="Saved as "+r.policy+".";await refreshLists(host)}catch(error){host.querySelector(".view-error").textContent=error.message}
    });
    try{const bu=await jsonRequest("/admin/v1/app-registration/activation-base-url");activationBaseUrl=bu.activationBaseUrl||"";const buf=host.querySelector(".baseurl-form");buf.elements.baseurl.value=activationBaseUrl;buf.querySelector(".baseurl-note").textContent=activationBaseUrl?"Fragment links enabled on "+activationBaseUrl+".":"No base URL - raw tokens only.";buf.addEventListener("submit",async ev=>{ev.preventDefault();try{const r=await jsonRequest("/admin/v1/app-registration/activation-base-url",{method:"PUT",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({activationBaseUrl:buf.elements.baseurl.value})});activationBaseUrl=r.activationBaseUrl||"";buf.elements.baseurl.value=activationBaseUrl;buf.querySelector(".baseurl-note").textContent=activationBaseUrl?"Fragment links enabled on "+activationBaseUrl+".":"No base URL - raw tokens only.";await refreshLists(host)}catch(error){buf.querySelector(".baseurl-note").textContent=error.message}})}catch(e){}
    const prov=host.querySelector(".provision-form");
    prov.addEventListener("submit",async ev=>{ev.preventDefault();if(!canIssueToken(host))return;try{const inv=await jsonRequest("/admin/v1/app-registration/invitations",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({kind:"activate",email:prov.elements.email.value})});showToken(host,"Activation token",inv.token);prov.reset();await refreshLists(host)}catch(error){host.querySelector(".view-error").textContent="Could not issue the activation token: "+error.message}});
    renderInvitations(host,invitations.items);
    renderRequests(host,requests.items);
    renderActivations(host,invitations.items);
    renderUsersList(host,users.items);
  }catch(error){host.querySelector(".view-error").textContent=error.message}
}
function renderInvitations(host,items){
  const list=host.querySelector(".invitation-list");
  const open=items.filter(i=>!i.usedAt&&!i.revokedAt&&new Date(i.expiresAt)>new Date());
  list.innerHTML=items.length?'<table class="collection-table"><thead><tr><th>Email</th><th>Kind</th><th>Expires</th><th>Status</th><th></th></tr></thead><tbody>'+items.slice(0,100).map(inv=>`<tr><td>${escapeHTML(inv.email)}</td><td>${inv.kind}</td><td>${new Date(inv.expiresAt).toLocaleString()}</td><td>${inv.usedAt?"Used":inv.revokedAt?"Revoked":new Date(inv.expiresAt)<new Date()?"Expired":"Valid"}</td><td>${!inv.usedAt&&!inv.revokedAt?`<button data-revoke-inv="${inv.id}">Revoke</button>`:""}</td></tr>`).join("")+'</tbody></table>':'<section class="empty"><h2>No invitations</h2><p>Create one above, or provision a user to generate an activation link.</p></section>';
  list.querySelectorAll("[data-revoke-inv]").forEach(button=>button.addEventListener("click",async()=>{if(!confirm("Revoke this invitation?"))return;try{await jsonRequest(`/admin/v1/app-registration/invitations/${button.dataset.revokeInv}/revoke`,{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:"{}"});await refreshLists(host)}catch(error){host.querySelector(".view-error").textContent=error.message}}));
  void open;
}
function renderRequests(host,items){
  const list=host.querySelector(".request-list");
  list.innerHTML=items.length?'<table class="collection-table"><thead><tr><th>Email</th><th>Status</th><th>Created</th><th></th></tr></thead><tbody>'+items.slice(0,100).map(req=>`<tr><td>${escapeHTML(req.email)}</td><td>${req.status}</td><td>${new Date(req.createdAt).toLocaleString()}</td><td>${req.status==="pending"?`<button data-approve="${req.id}">Approve</button> <button data-reject="${req.id}">Reject</button>`:req.status==="approved"?`<button data-reissue="${req.id}">Reissue activation</button>`:""}</td></tr>`).join("")+'</tbody></table>':'<section class="empty"><h2>No access requests</h2><p>Requests appear here when the policy is Approval.</p></section>';
  list.querySelectorAll("[data-approve]").forEach(button=>button.addEventListener("click",async()=>{if(!canIssueToken(host))return;try{const inv=await jsonRequest(`/admin/v1/app-registration/requests/${button.dataset.approve}/approve`,{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:"{}"});showToken(host,"Approved - activation token",inv.token);await refreshLists(host)}catch(error){host.querySelector(".view-error").textContent=error.message}}));
  list.querySelectorAll("[data-reject]").forEach(button=>button.addEventListener("click",async()=>{if(!confirm("Reject this access request?"))return;try{await jsonRequest(`/admin/v1/app-registration/requests/${button.dataset.reject}/reject`,{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:"{}"});await refreshLists(host)}catch(error){host.querySelector(".view-error").textContent=error.message}}));
  list.querySelectorAll("[data-reissue]").forEach(button=>button.addEventListener("click",async()=>{if(!canIssueToken(host))return;try{const inv=await jsonRequest(`/admin/v1/app-registration/requests/${button.dataset.reissue}/reissue`,{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:"{}"});showToken(host,"Reissued activation token",inv.token);await refreshLists(host)}catch(error){host.querySelector(".view-error").textContent=error.message}}));
}
function renderActivations(host,invitations){
  const list=host.querySelector(".activation-list");
  const pending=invitations.filter(i=>i.kind==="activate"&&!i.usedAt&&!i.revokedAt&&new Date(i.expiresAt)>new Date());
  list.innerHTML=pending.length?'<table class="collection-table"><thead><tr><th>Email</th><th>Issued</th><th>Expires</th></tr></thead><tbody>'+pending.map(inv=>`<tr><td>${escapeHTML(inv.email)}</td><td>${new Date(inv.createdAt).toLocaleString()}</td><td>${new Date(inv.expiresAt).toLocaleString()}</td></tr>`).join("")+'</tbody></table>':'<section class="empty"><h2>No pending activations</h2><p>Users are created when an activation token is accepted with a password.</p></section>';
}
function renderUsersList(host,items){
  const list=host.querySelector(".user-list");
  list.innerHTML=items.length?'<table class="collection-table"><thead><tr><th>Email</th><th>Status</th><th>Created</th><th></th></tr></thead><tbody>'+items.map(user=>`<tr><td>${escapeHTML(user.email)}</td><td>${user.disabled?"Disabled":"Active"}</td><td>${new Date(user.createdAt).toLocaleString()}</td><td>${user.disabled?"":`<button data-disable-user="${user.id}">Disable & revoke</button>`}</td></tr>`).join("")+'</tbody></table>':'<section class="empty"><h2>No application users</h2><p>Users are created by registration, invitation, or administrator activation.</p></section>';
  list.querySelectorAll("[data-disable-user]").forEach(button=>button.addEventListener("click",async()=>{if(!confirm("Disable this user and revoke every session?"))return;try{await jsonRequest(`/admin/v1/app-users/${button.dataset.disableUser}/disable`,{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:"{}"});await refreshLists(host)}catch(error){host.querySelector(".view-error").textContent=error.message}}));
}

async function renderCredentials(section){section.innerHTML='<div class="record-toolbar"><div><p class="eyebrow">Trusted identities</p><h2>Credentials</h2></div></div><form class="credential-form collection-form"><label>Name<input name="name" required></label><label>Kind<select name="kind"><option value="service">Service account</option><option value="personal">Personal token</option></select></label><label>Scopes<input name="scopes" value="records:read,records:write" required></label><button>Create credential</button></form><div class="secret-once" hidden></div><p class="credential-error view-error" role="alert"></p><div class="credential-list"></div>';section.querySelector("form").addEventListener("submit",async event=>{event.preventDefault();const form=event.currentTarget;try{const created=await jsonRequest("/admin/v1/credentials",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({name:form.elements.name.value,kind:form.elements.kind.value,scopes:form.elements.scopes.value.split(",").map(value=>value.trim())})});const secret=section.querySelector(".secret-once");secret.hidden=false;secret.innerHTML=`<strong>Copy this secret now</strong><p>It will not be shown again.</p><code>${escapeHTML(created.secret)}</code> <button data-copy-secret>Copy</button>`;secret.querySelector("button").addEventListener("click",()=>navigator.clipboard.writeText(created.secret));form.reset();await loadCredentials(section)}catch(error){section.querySelector(".credential-error").textContent=error.message}});await loadCredentials(section)}
async function loadCredentials(section){try{const response=await jsonRequest("/admin/v1/credentials");const list=section.querySelector(".credential-list");if(!list)return;list.innerHTML=response.items.length?'<table class="collection-table"><thead><tr><th>Name</th><th>Kind</th><th>Scopes</th><th>Last used</th><th></th></tr></thead><tbody>'+response.items.map(item=>`<tr><td>${escapeHTML(item.name)}</td><td>${item.kind}</td><td>${item.scopes.join(", ")}</td><td>${item.lastUsedAt?new Date(item.lastUsedAt).toLocaleString():"Never"}</td><td>${item.revoked?"Revoked":`<button data-revoke="${item.id}">Revoke</button>`}</td></tr>`).join("")+'</tbody></table>':'<section class="empty"><h2>No credentials</h2><p>Create a scoped identity above.</p></section>';section.querySelectorAll("[data-revoke]").forEach(button=>button.addEventListener("click",async()=>{await jsonRequest(`/admin/v1/credentials/${button.dataset.revoke}`,{method:"DELETE",headers:{"X-Trestle-CSRF":csrfToken}});loadCredentials(section)}))}catch(error){const target=section.querySelector(".credential-error");if(target)target.textContent=error.message}}
async function renderRules(){document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;const host=document.getElementById("view-content");host.hidden=false;host.className="record-view";host.innerHTML='<section class="settings-card"><div><p class="eyebrow">Server enforcement</p><h2>Collection access rules</h2></div><form class="rule-form"><label>Collection<input name="collection" placeholder="issues" required></label><label>List<input name="list" value="false"></label><label>View<input name="view" value="false"></label><label>Create<input name="create" value="false"></label><label>Update<input name="update" value="false"></label><label>Delete<input name="delete" value="false"></label><button>Save rules</button></form></section><section class="settings-card"><form class="rule-simulator"><h3>Simulator</h3><p>Simulation helps debug rules; only server enforcement authorizes requests.</p><label>Operation<select name="operation"><option>list</option><option>view</option><option>create</option><option>update</option><option>delete</option></select></label><label>Actor kind<select name="kind"><option>user</option><option>service</option></select></label><label>Actor ID<input name="actor" value="usr_example"></label><label>Values JSON<textarea name="values">{}</textarea></label><button>Explain</button><pre class="json-block" data-explanation></pre></form></section><p class="view-error" role="alert"></p>';const rulesForm=host.querySelector(".rule-form");rulesForm.addEventListener("submit",async event=>{event.preventDefault();try{const collection=rulesForm.elements.collection.value;const rules={};["list","view","create","update","delete"].forEach(op=>rules[op]=rulesForm.elements[op].value);await jsonRequest(`/admin/v1/collection-rules/${encodeURIComponent(collection)}`,{method:"PUT",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({rules})});host.querySelector(".view-error").textContent="Rules saved."}catch(error){host.querySelector(".view-error").textContent=error.message}});const simulator=host.querySelector(".rule-simulator");simulator.addEventListener("submit",async event=>{event.preventDefault();try{const collection=rulesForm.elements.collection.value;const result=await jsonRequest(`/admin/v1/collection-rules/${encodeURIComponent(collection)}/explain`,{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({operation:simulator.elements.operation.value,actor:{kind:simulator.elements.kind.value,id:simulator.elements.actor.value},values:JSON.parse(simulator.elements.values.value)})});simulator.querySelector("pre").innerHTML=highlightJSON(JSON.stringify(result,null,2))}catch(error){host.querySelector(".view-error").textContent=error.message}})}

async function renderDeploymentSummary(){
  const host=document.getElementById("view-content");
  try{
    const deployment=await jsonRequest("/admin/v1/deployment");
    const card=document.createElement("section");
    card.className="settings-card deployment-card";
    card.innerHTML=`<div class="record-toolbar"><div><p class="eyebrow">Deployment</p><h2>Runtime and release</h2></div><a class="button-link" href="/admin/v1/support-bundle">Download support bundle</a></div><div class="api-summary"><article><span>Version</span><strong>${escapeHTML(deployment.version.version)}</strong><small>${escapeHTML(deployment.version.commit)}</small></article><article><span>Platform</span><strong>${escapeHTML(deployment.version.os)}/${escapeHTML(deployment.version.arch)}</strong><small>${escapeHTML(deployment.version.go)}</small></article><article><span>Trusted proxies</span><strong>${deployment.trustedProxies.length}</strong><small>${deployment.trustedProxies.length?escapeHTML(deployment.trustedProxies.join(", ")):"Forwarded headers ignored"}</small></article></div><p class="dialog-hint">Listening on ${escapeHTML(deployment.listen)} with ${escapeHTML(deployment.storageBackend)} storage. Support bundles exclude secrets.</p>`;
    host.prepend(card);
  }catch(error){ host.querySelector(".view-error").textContent=error.message }
}
const settingsObserver=new MutationObserver(()=>{const host=document.getElementById("view-content");if(host.querySelector(".rule-form")&&!host.querySelector(".deployment-card"))renderDeploymentSummary()});
settingsObserver.observe(document.getElementById("view-content"),{childList:true});
async function renderFiles(){document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;const host=document.getElementById("view-content");host.hidden=false;host.className="record-view";host.innerHTML='<div class="record-toolbar"><div><p class="eyebrow">Local storage</p><h2>Files</h2></div><button data-clean-files>Clean orphans</button></div><p class="storage-provider">Checking storage provider…</p><form class="file-upload"><label>Choose file<input name="file" type="file" required></label><label>Collection binding<input name="collection" placeholder="issues"></label><label>Record ID<input name="recordId" placeholder="rec_..."></label><button>Upload</button><progress value="0" max="100" hidden></progress></form><p class="storage-usage"></p><p class="view-error" role="alert"></p><div class="file-list"></div>';jsonRequest("/admin/v1/storage/status").then(status=>{host.querySelector(".storage-provider").textContent="Storage: "+status.provider+" · "+formatBytes(status.quota)+" quota"}).catch(()=>{host.querySelector(".storage-provider").textContent="Storage status unavailable"});const form=host.querySelector("form");form.addEventListener("submit",async event=>{event.preventDefault();const button=form.querySelector("button");button.disabled=true;try{const response=await fetch("/api/v1/files",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:new FormData(form)});const body=await response.json();if(!response.ok)throw new Error(body?.error?.message||"Upload failed");form.reset();await loadFiles(host)}catch(error){host.querySelector(".view-error").textContent=error.message}finally{button.disabled=false}});host.querySelector("[data-clean-files]").addEventListener("click",async()=>{const result=await jsonRequest("/admin/v1/files/cleanup",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:"{}"});host.querySelector(".view-error").textContent=`Removed ${result.removed} orphaned files.`});await loadFiles(host)}
async function loadFiles(host){try{const response=await jsonRequest("/admin/v1/files");const used=response.items.reduce((sum,item)=>sum+item.size,0);host.querySelector(".storage-usage").textContent=`${formatBytes(used)} used of ${formatBytes(response.quota)}`;host.querySelector(".file-list").innerHTML=response.items.length?'<table class="collection-table"><thead><tr><th>Name</th><th>Type</th><th>Size</th><th>Binding</th><th></th></tr></thead><tbody>'+response.items.map(item=>`<tr><td>${escapeHTML(item.name)}</td><td>${escapeHTML(item.contentType)}</td><td>${formatBytes(item.size)}</td><td>${escapeHTML(item.collection||"-")} ${escapeHTML(item.recordId||"")}</td><td><a href="/api/v1/files/${item.id}" target="_blank">Preview</a> <button data-delete-file="${item.id}">Delete</button></td></tr>`).join("")+'</tbody></table>':'<section class="empty"><h2>No files</h2><p>Upload a file above. Client filenames are metadata, never storage paths.</p></section>';host.querySelectorAll("[data-delete-file]").forEach(button=>button.addEventListener("click",async()=>{try{await jsonRequest(`/api/v1/files/${button.dataset.deleteFile}`,{method:"DELETE",headers:{"X-Trestle-CSRF":csrfToken}})}catch(error){if(error.code==="deletion_pending"){host.querySelector(".view-error").innerHTML="<strong>File deletion is pending</strong> - the file is marked for deletion and Trestle retries automatically; you can also trigger cleanup."}else{host.querySelector(".view-error").textContent=error.message}}loadFiles(host)}))}catch(error){host.querySelector(".view-error").textContent=error.message}
}
function formatBytes(value){if(value<1024)return `${value} B`;if(value<1048576)return `${(value/1024).toFixed(1)} KiB`;return `${(value/1048576).toFixed(1)} MiB`}

// Realtime transport resource controller (DOM-free, clock/registry-injectable).
//
// A Realtime visit can own at most three resources: the EventSource, the
// staleness interval, and a last-activity timestamp. This controller is a
// module-level singleton in realtime.js, so cleanup() always clears the
// *current* pair of resources. A route-change listener registered once against
// the stable cleanup() can therefore never leak a later visit's resources
// (CP12R4: after any enter/leave cycle there are zero sources and zero
// intervals, and during a visit there is exactly one of each).
//
// env is injectable (globalThis by default) so a regression can count real
// setInterval/clearInterval traffic and EventSource instances instead of
// trusting the controller's own counters.
globalThis.TrestleRealtimeController = (() => {
  function createController(env) {
    env = env || globalThis;
    let source = null;
    let timer = null;
    let lastActivity = 0;
    let paused = false;
    return {
      setSource(s) { source = s; },
      source() { return source; },
      setTimer(t) { timer = t; },
      timer() { return timer; },
      setActivity(t) { lastActivity = t; },
      activity() { return lastActivity; },
      setPaused(v) { paused = v; },
      paused() { return paused; },
      // cleanup returns the closed source so a caller can null its handlers
      // before/after close if it wants; the resource itself is always released.
      // paused is intentionally NOT reset here: connect() reuses cleanup() for
      // reconnects within a visit, so pausing must survive a reconnect. A fresh
      // visit resets paused through setPaused(false) at render time, so the
      // controller and the per-visit "Pause" button copy always agree.
      cleanup() {
        const s = source;
        source = null;
        if (s && typeof s.close === "function") { s.close(); }
        if (timer) { env.clearInterval(timer); timer = null; }
        return s;
      },
      active() { return source !== null || timer !== null; }
    };
  }
  return { createController };
})();
// Realtime transport view (CP12R3/CP12R4).
//
// Resource ownership is delegated to one module-level TrestleRealtimeController
// singleton so a single route-change listener registered once always cleans up
// the *current* visit's EventSource and staleness interval (CP12R4 blocker 1).
//
// Staleness means "missing transport heartbeat", not merely "no business events
// recently" (CP12R4 blocker 2): the server emits an observable `heartbeat` SSE
// event every 15 seconds; the client's heartbeat listener calls mark() without
// adding an item to the event inspector, so a healthy idle stream stays live.
const rt = TrestleRealtimeController.createController();

function realtimeCleanup() {
  const s = rt.cleanup();
  if (s) { s.onopen = null; s.onerror = null; }
}
window.addEventListener("trestle:viewchange", realtimeCleanup);

function renderRealtime() {
  document.getElementById("overview-content").hidden = true;
  document.getElementById("retry").hidden = true;
  const host = document.getElementById("view-content");
  host.hidden = false;
  host.className = "record-view";
  host.innerHTML = '<div class="record-toolbar"><div><p class="eyebrow">Durable event journal</p><h2>Realtime</h2></div><button type="button" data-pause>Pause</button></div><form class="query-bar realtime-filter"><label>Topic filter<input name="topic" placeholder="record.created"><span>Leave empty to listen to record.created, record.updated and record.deleted.</span></label><button>Reconnect</button></form><p class="connection-state">Connecting…</p><div class="event-inspector" aria-live="polite"></div>';
  const inspector = host.querySelector(".event-inspector");
  // Paused is a per-visit choice (CP12R5): reset it at the start of every
  // Realtime visit so the controller always agrees with the fresh "Pause"
  // button copy, instead of inheriting a previous visit's pause. cleanup()
  // deliberately does not reset it because reconnect() reuses cleanup() and a
  // reconnect within the same visit must preserve the pause state.
  rt.setPaused(false);

  const mark = () => {
    rt.setActivity(Date.now());
    const state = host.querySelector(".connection-state");
    if (state.textContent.indexOf("Stale") === 0) {
      state.textContent = "Connected · live";
    }
  };

  const connect = () => {
    realtimeCleanup();
    const topic = host.querySelector('[name="topic"]').value.trim();
    const source = new EventSource("/api/v1/realtime" + (topic ? "?topic=" + encodeURIComponent(topic) : ""));
    rt.setSource(source);
    rt.setActivity(Date.now());
    source.onopen = () => {
      rt.setActivity(Date.now());
      host.querySelector(".connection-state").textContent = "Connected · replay resumes from the last delivered sequence";
    };
    source.onerror = () => host.querySelector(".connection-state").textContent = "Reconnecting…";
    source.addEventListener("ready", () => {
      mark();
      host.querySelector(".connection-state").textContent = topic
        ? "Connected · listening to " + topic
        : "Connected · listening to all record topics";
    });
    // Transport health: an observable heartbeat keeps the stream live without
    // polluting the event inspector. Business events refresh activity too.
    source.addEventListener("heartbeat", mark);
    ["record.created", "record.updated", "record.deleted"].forEach((name) =>
      source.addEventListener(name, (event) => {
        mark();
        if (rt.paused()) return;
        const item = JSON.parse(event.data);
        const article = document.createElement("article");
        article.innerHTML = `<div><strong>${escapeHTML(item.topic)}</strong><span>#${item.sequence} · ${new Date(item.occurredAt).toLocaleString()}</span></div><pre class="json-block">${highlightJSON(JSON.stringify(item, null, 2))}</pre>`;
        inspector.prepend(article);
        while (inspector.children.length > 200) inspector.lastElementChild.remove();
      })
    );
    rt.setTimer(setInterval(() => {
      if (TrestleDatabaseSetup.staleState(rt.activity(), Date.now(), rt.paused())) {
        host.querySelector(".connection-state").textContent = "Stale · no heartbeat for a while; the connection may have dropped - check it and re-open the stream";
      }
    }, 10000));
  };

  host.querySelector("form").addEventListener("submit", (event) => {
    event.preventDefault();
    inspector.replaceChildren();
    connect();
  });
  host.querySelector("[data-pause]").addEventListener("click", (event) => {
    rt.setPaused(!rt.paused());
    event.currentTarget.textContent = rt.paused() ? "Resume" : "Pause";
  });
  connect();

  // Test/browser-harness hook: lets an external driver force the stale and
  // recovered transitions deterministically without fault-injecting the server.
  window.__trestleRealtime = {
    mark,
    setActivity: (t) => rt.setActivity(t),
    activity: () => rt.activity(),
    paused: () => rt.paused(),
    sourceActive: () => rt.source() !== null
  };
}


async function renderAudit(){document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;const host=document.getElementById("view-content");host.hidden=false;host.className="record-view";host.innerHTML='<div class="record-toolbar"><div><p class="eyebrow">Append-oriented facts</p><h2>Audit</h2></div><button type="button" data-export-audit>Export JSON</button></div><form class="query-bar"><label>Action filter<input name="action" placeholder="record.update"></label><button>Apply</button></form><div class="operations-summary"></div><p class="view-error" role="alert"></p><div class="audit-list"></div>';const load=async()=>{try{const action=host.querySelector('[name="action"]').value.trim();const [facts,ops]=await Promise.all([jsonRequest("/admin/v1/audit"+(action?"?action="+encodeURIComponent(action):"")),jsonRequest("/admin/v1/operations")]);host.querySelector(".operations-summary").innerHTML=`<article><span>Provider</span><strong>${escapeHTML(ops.provider)}</strong></article><article><span>Database</span><strong>${ops.databaseBytes===null||ops.databaseBytes===undefined?"Not reported":formatBytes(ops.databaseBytes)}</strong></article>${Object.entries(ops.counts).map(([name,value])=>`<article><span>${escapeHTML(name)}</span><strong>${value}</strong></article>`).join("")}`;host.querySelector(".audit-list").innerHTML=facts.items.length?facts.items.map(item=>`<article class="audit-item"><div><strong>${escapeHTML(item.action)}</strong><span>${escapeHTML(item.outcome)} · ${new Date(item.occurredAt).toLocaleString()}</span></div><div><code>${escapeHTML(item.target||"system")}</code><small>${escapeHTML(item.requestId||"")}</small></div><pre class="json-block">${highlightJSON(JSON.stringify(item.details,null,2))}</pre></article>`).join(""):'<section class="empty"><h2>No audit facts</h2><p>Security and administrative activity appears here.</p></section>'}catch(error){host.querySelector(".view-error").textContent=error.message}};host.querySelector("form").addEventListener("submit",event=>{event.preventDefault();load()});host.querySelector("[data-export-audit]").addEventListener("click",async()=>{const data=await jsonRequest("/admin/v1/audit");const blob=new Blob([JSON.stringify(data,null,2)],{type:"application/json"});const link=document.createElement("a");link.href=URL.createObjectURL(blob);link.download="trestle-audit.json";link.click();URL.revokeObjectURL(link.href)});await load()}

async function renderJobs(){document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;const host=document.getElementById("view-content");host.hidden=false;host.className="record-view";host.innerHTML='<div class="record-toolbar"><div><p class="eyebrow">Durable delivery</p><h2>Jobs</h2></div><button type="button" data-refresh-jobs>Refresh</button></div><form class="query-bar jobs-filter"><label>Status<select name="status"><option value="">All states</option><option>pending</option><option>running</option><option>succeeded</option><option>dead</option><option>cancelled</option></select></label><button>Apply filter</button></form><p class="view-error"></p><div class="job-list"></div>';const statusLabel=(job)=>job.status==="dead"?TrestleDatabaseSetup.viewState("dead").title:job.status==="pending"&&job.attempts>0?TrestleDatabaseSetup.viewState("retrying").title:job.status;
const load=async()=>{try{const status=host.querySelector('[name="status"]').value;const response=await jsonRequest("/admin/v1/jobs"+(status?"?status="+status:""));host.querySelector(".job-list").innerHTML=response.items.length?response.items.map(job=>`<article class="job-item"><div><strong>${escapeHTML(job.kind)}</strong><span>${statusLabel(job)} · ${job.attempts}/${job.maxAttempts} attempts</span></div><code>${escapeHTML(job.id)}</code><pre class="json-block">${highlightJSON(JSON.stringify(job.payload,null,2))}</pre><div>${["dead","cancelled"].includes(job.status)?`<button data-job-action="retry" data-job="${job.id}">Retry</button>`:job.status==="pending"||job.status==="running"?`<button data-job-action="cancel" data-job="${job.id}">Cancel</button>`:""}</div>${job.lastError?`<p>${escapeHTML(job.lastError)}</p>`:""}</article>`).join(""):'<section class="empty"><h2>No jobs</h2><p>Transactional deliveries and function invocations appear here.</p></section>';host.querySelectorAll("[data-job-action]").forEach(button=>button.addEventListener("click",async()=>{await jsonRequest(`/admin/v1/jobs/${button.dataset.job}`,{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({action:button.dataset.jobAction})});load()}))}catch(error){host.querySelector(".view-error").textContent=error.message}};host.querySelector("form").addEventListener("submit",event=>{event.preventDefault();load()});host.querySelector("[data-refresh-jobs]").addEventListener("click",load);await load()}

async function renderIntegrations(){document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;const host=document.getElementById("view-content");host.hidden=false;host.className="record-view";host.innerHTML='<div class="record-toolbar"><div><p class="eyebrow">Signed delivery</p><h2>Webhooks</h2></div></div><form class="rule-form webhook-form"><label>Name<input name="name" required placeholder="Incident automation"></label><label>HTTPS endpoint<input name="url" type="url" required placeholder="https://hooks.example.com/trestle"></label><label>Topics<input name="topics" required value="record.created" placeholder="record.created,record.updated"></label><button>Create webhook</button></form><div class="webhook-secret"></div><p class="view-error"></p><div class="webhook-list"></div><section class="lambda-section"></section><section class="credentials-section"></section>';renderLambdaSection(host);renderCredentials(host.querySelector(".credentials-section"));const load=async()=>{const response=await jsonRequest("/admin/v1/webhooks");const list=host.querySelector(".webhook-list");if(!list)return;list.innerHTML=response.items.length?response.items.map(item=>`<article class="job-item"><div><strong>${escapeHTML(item.name)}</strong><span>${item.enabled?"enabled":"disabled"}</span></div><code>${escapeHTML(item.url)}</code><span>${item.topics.map(escapeHTML).join(", ")}</span><button data-webhook="${item.id}" data-action="${item.enabled?"disable":"enable"}">${item.enabled?"Disable":"Enable"}</button></article>`).join(""):'<section class="empty"><h2>No webhooks</h2><p>Create a signed, event-filtered endpoint above.</p></section>';host.querySelectorAll("[data-webhook]").forEach(button=>button.addEventListener("click",async()=>{await jsonRequest(`/admin/v1/webhooks/${button.dataset.webhook}`,{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({action:button.dataset.action})});load()}))};host.querySelector(".webhook-form").addEventListener("submit",async event=>{event.preventDefault();const form=event.currentTarget;try{const result=await jsonRequest("/admin/v1/webhooks",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({name:form.elements.name.value,url:form.elements.url.value,topics:form.elements.topics.value.split(",").map(value=>value.trim()).filter(Boolean)})});host.querySelector(".webhook-secret").innerHTML=`<section class="secret-once"><strong>Copy the signing secret now</strong><p>It will not be returned again.</p><code>${escapeHTML(result.secret)}</code></section>`;form.reset();await load()}catch(error){host.querySelector(".view-error").textContent=error.message}});await load()}

async function renderLambdaSection(host){const section=host.querySelector(".lambda-section");section.innerHTML='<div class="record-toolbar"><div><p class="eyebrow">Asynchronous functions</p><h2>AWS Lambda</h2></div></div><form class="rule-form lambda-form"><label>Name<input name="name" required></label><label>Function ARN<input name="target" required placeholder="arn:aws:lambda:us-east-1:123456789012:function:handler"></label><label>Region<input name="region" required value="us-east-1"></label><label>Topics<input name="topics" required value="record.created"></label><label>Callback scopes<input name="scopes" placeholder="records:read"></label><button>Create function target</button></form><p class="lambda-status"></p><div class="lambda-list"></div>';const load=async()=>{const response=await jsonRequest("/admin/v1/functions");section.querySelector(".lambda-status").textContent=response.credentialsConfigured?"AWS credentials configured · 202 means accepted, not completed":"AWS credentials are not configured; targets remain inspectable but invocations will retry";section.querySelector(".lambda-list").innerHTML=response.items.map(item=>`<article class="job-item"><div><strong>${escapeHTML(item.name)}</strong><span>${item.enabled?"enabled":"disabled"}</span></div><code>${escapeHTML(item.target)}</code><span>${item.topics.map(escapeHTML).join(", ")}</span><button data-function="${item.id}" data-action="${item.enabled?"disable":"enable"}">${item.enabled?"Disable":"Enable"}</button></article>`).join("");section.querySelectorAll("[data-function]").forEach(button=>button.addEventListener("click",async()=>{await jsonRequest(`/admin/v1/functions/${button.dataset.function}`,{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({action:button.dataset.action})});load()}))};section.querySelector("form").addEventListener("submit",async event=>{event.preventDefault();const form=event.currentTarget;try{await jsonRequest("/admin/v1/functions",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:JSON.stringify({name:form.elements.name.value,target:form.elements.target.value,region:form.elements.region.value,topics:form.elements.topics.value.split(",").map(v=>v.trim()).filter(Boolean),callbackScopes:form.elements.scopes.value.split(",").map(v=>v.trim()).filter(Boolean)})});form.reset();await load()}catch(error){section.querySelector(".lambda-status").textContent=error.message}});await load()}
async function renderAPIExplorer(){document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;const host=document.getElementById("view-content");host.hidden=false;host.className="record-view";host.innerHTML='<div class="record-toolbar"><div><p class="eyebrow">Developer and AI DX</p><h2>API explorer</h2></div><a class="button-link" href="/api/v1/openapi.json" target="_blank">OpenAPI JSON</a></div><div class="api-summary"></div><label class="api-request">Generated curl<textarea readonly></textarea></label><div class="schema-explorer"></div>';const schema=await jsonRequest("/admin/v1/api/schema");const caps=schema.capabilities;host.querySelector(".api-summary").innerHTML=`<article><span>API version</span><strong>${escapeHTML(caps.apiVersion)}</strong></article><article><span>Features</span><strong>${caps.features.length}</strong></article><article><span>Record limit</span><strong>${caps.limits.recordPageMax}</strong></article>`;const curl=host.querySelector("textarea");curl.value=`curl ${location.origin}/api/v1/collections/issues/records \\\n  -H 'Authorization: Bearer $TRESTLE_TOKEN'`;makeVerticalResizable(curl);host.querySelector(".schema-explorer").innerHTML=Object.entries(schema.collections).map(([name,fields])=>`<article><h3>${escapeHTML(name)}</h3><pre class="json-block">${highlightJSON(JSON.stringify(fields,null,2))}</pre></article>`).join("")||'<section class="empty"><h2>No schemas yet</h2><p>Create a collection to inspect its machine-readable contract.</p></section>'}

function makeVerticalResizable(textarea){const handle=textarea.closest(".api-request");let startY=0,startHeight=0;handle.addEventListener("pointerdown",event=>{const rect=handle.getBoundingClientRect();if(Math.abs(rect.bottom-event.clientY)>8)return;event.preventDefault();startY=event.clientY;startHeight=textarea.getBoundingClientRect().height;handle.dataset.resizeActive="true";handle.setPointerCapture(event.pointerId)});handle.addEventListener("pointermove",event=>{if(!handle.dataset.resizeActive)return;textarea.style.height=Math.max(70,startHeight+event.clientY-startY)+"px"});const stop=event=>{if(!handle.dataset.resizeActive)return;delete handle.dataset.resizeActive;if(handle.hasPointerCapture(event.pointerId))handle.releasePointerCapture(event.pointerId)};handle.addEventListener("pointerup",stop);handle.addEventListener("pointercancel",stop)}
async function renderBackups(){document.getElementById("overview-content").hidden=true;document.getElementById("retry").hidden=true;const host=document.getElementById("view-content");host.hidden=false;host.className="record-view";host.innerHTML='<div class="record-toolbar"><div><p class="eyebrow">Recovery</p><h2>Backups</h2></div><button type="button" data-create-backup>Create backup</button></div><p class="backup-status"></p><div class="backup-list"></div><section class="backup-tools"><form class="restore-form"><h3>Restore preflight</h3><p>Validate an archive before the documented offline restore.</p><input name="backup" type="file" accept=".zip" required><button>Validate backup</button></form><form class="import-form"><h3>Import dry run</h3><p>Validate a native JSON export without writing.</p><input name="export" type="file" accept=".json" required><button>Run dry check</button></form></section>';const load=async()=>{const response=await jsonRequest("/admin/v1/backups");host.querySelector(".backup-list").innerHTML=response.items.length?response.items.map(item=>`<article class="job-item"><div><strong>${escapeHTML(item.id)}</strong><span>${new Date(item.createdAt).toLocaleString()}</span></div><span>${formatBytes(item.size)}</span><a class="button-link" href="/admin/v1/backups/${encodeURIComponent(item.id)}">Download</a></article>`).join(""):'<section class="empty"><h2>No backups</h2><p>Create the first consistent archive above.</p></section>'};host.querySelector("[data-create-backup]").addEventListener("click",async event=>{event.currentTarget.disabled=true;host.querySelector(".backup-status").textContent="Creating a consistent database and file archive…";try{const result=await jsonRequest("/admin/v1/backups",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:"{}"});host.querySelector(".backup-status").textContent=`Created ${result.id}`;await load()}catch(error){host.querySelector(".backup-status").textContent=error.message}finally{event.currentTarget.disabled=false}});host.querySelector(".restore-form").addEventListener("submit",async event=>{event.preventDefault();const response=await fetch("/admin/v1/restores/preflight",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:new FormData(event.currentTarget)});const result=await response.json();host.querySelector(".backup-status").textContent=result.valid?result.next:(result.issues||[]).join(" · ")});host.querySelector(".import-form").addEventListener("submit",async event=>{event.preventDefault();const file=event.currentTarget.elements.export.files[0];try{const result=await jsonRequest("/admin/v1/imports/dry-run",{method:"POST",headers:{"X-Trestle-CSRF":csrfToken},body:await file.text()});host.querySelector(".backup-status").textContent=result.valid?`Dry run passed for ${result.collections} collections; 0 writes performed`:(result.issues||[]).join(" · ")}catch(error){host.querySelector(".backup-status").textContent=error.message}});await load()}

const dashboardRenderers={overview:()=>{document.getElementById("view-content").hidden=true;document.getElementById("overview-content").hidden=false;document.getElementById("retry").hidden=false;check()},collections:renderCollections,users:renderUsers,settings:renderRules,files:renderFiles,realtime:renderRealtime,audit:renderAudit,jobs:renderJobs,integrations:renderIntegrations,api:renderAPIExplorer,backups:renderBackups};
function discardToken(){pendingToken=false;const panel=document.querySelector(".provision-result");if(panel)panel.innerHTML=""}
// Indexed history-state contract: every Trestle-owned entry carries a
// position in history.state equal to its stack distance from the initial
// entry, so positions remain contiguous with the actual history indexes even
// after the browser truncates a forward branch when a new route is pushed.
// Ordinary route navigation derives the next position from the rendered
// position (renderedPosition+1) rather than a global high-water mark, so a
// one-entry Back after branching is still delta -1. On a browser traversal
// (writeHistory=false) the delta between the traversed-to entry's position and
// the rendered position is computed; an accepted traversal renders the entry
// the browser moved to without writing history, and a rejected traversal
// returns to the rendered entry with history.go(-delta), suppressing exactly
// the resulting restorative popstate - never adding, replacing, duplicating or
// truncating entries, and never requesting an out-of-range history.go because
// the target entry always exists.
const positionKey="trestle:position";
let renderedPosition=history.state&&typeof history.state[positionKey]==="number"?history.state[positionKey]:0;
let suppressPopstate=false;
function entryPosition(state){return state&&typeof state[positionKey]==="number"?state[positionKey]:0}
function selectDashboardRoute(route,title,href,writeHistory=true,traversalDelta=0,...renderArgs){if(pendingToken){if(!confirm("An activation token has not been dismissed yet. Leave this view? The token cannot be shown again.")){if(traversalDelta!==0){suppressPopstate=true;history.go(-traversalDelta)}return}discardToken()}window.dispatchEvent(new Event("trestle:viewchange"));document.querySelectorAll("[data-route]").forEach(item=>{const active=item.dataset.route===route;item.classList.toggle("active",active);if(active)item.setAttribute("aria-current","page");else item.removeAttribute("aria-current")});document.querySelector("#view-title").textContent=title;rail.classList.remove("open");mobile.setAttribute("aria-expanded","false");if(href){if(writeHistory){const nextPosition=renderedPosition+1;history.pushState({[positionKey]:nextPosition},"",href);renderedPosition=nextPosition}else{renderedPosition=entryPosition(history.state)}}const render=dashboardRenderers[route]||dashboardRenderers.overview;render(...renderArgs)}
function openCollectionRoute(collection,writeHistory=true){selectDashboardRoute("collections",collection,writeHistory?`/collections/${encodeURIComponent(collection)}`:null,writeHistory,0,collection)}
function restoreDashboardRoute(){if(suppressPopstate){suppressPopstate=false;return}const delta=entryPosition(history.state)-renderedPosition;const parts=location.pathname.split("/").filter(Boolean);if(parts[0]==="collections"&&parts.length===2){let collection="";try{collection=decodeURIComponent(parts[1])}catch{}if(/^[a-z][a-z0-9_]{0,62}$/.test(collection)){selectDashboardRoute("collections",collection,location.pathname,false,delta,collection);return}}const route=parts.length===1?parts[0]:"overview";const link=document.querySelector(`[data-route="${CSS.escape(route)}"]`)||document.querySelector('[data-route="overview"]');selectDashboardRoute(route,link?link.textContent:route,location.pathname,false,delta)}
window.addEventListener("trestle:authenticated",restoreDashboardRoute);window.addEventListener("popstate",restoreDashboardRoute);
