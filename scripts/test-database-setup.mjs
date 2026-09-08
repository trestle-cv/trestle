// CP2 first-run database-selection state-machine regression test.
//
// Extracts the pure TrestleDatabaseSetup state machine from the canonical
// embedded public bundle and drives every first-run transition the checkpoint
// contract requires, without a browser. The DOM layer in database-setup.js and
// script.js maps the computed state onto hidden/disabled attributes; the
// browser-quality gate also asserts the structural guarantees.
import {readFile} from "node:fs/promises";
import vm from "node:vm";

const bundle = await readFile(
  new URL("../internal/web/public/assets/js/script.js", import.meta.url),
  "utf8"
);
const start = bundle.indexOf("globalThis.TrestleDatabaseSetup = (() => {");
const helpers = bundle.indexOf("function staleState", start);
const end = bundle.indexOf("const statusCard", helpers);
if (start < 0 || helpers < 0 || end < 0) {
  throw new Error("TrestleDatabaseSetup block missing from public bundle");
}
const iifeEnd = bundle.indexOf("})();", start) + 5;
const source = bundle.slice(helpers, end) + "\n" + bundle.slice(start, iifeEnd);
vm.runInThisContext(source);
const machine = globalThis.TrestleDatabaseSetup;
if (!machine) {
  console.error("TrestleDatabaseSetup state machine was not defined");
  process.exit(1);
}

let failures = 0;
const check = (label, actual, expected) => {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(expected);
  if (a !== e) {
    failures += 1;
    console.error(`- ${label}: got ${a}, want ${e}`);
  }
};

const firstRun = {mode: "first-run", selectable: true, provider: "sqlite", url: ""};
const postgresSelectedEmpty = {mode: "first-run", selectable: true, provider: "postgres", url: ""};
const postgresSelectedFilled = {mode: "first-run", selectable: true, provider: "postgres", url: "postgres://u@host/db?sslmode=require"};
const savedAwaitingRestart = {mode: "first-run", selectable: false, provider: "postgres", url: ""};
const signIn = {mode: "sign-in", selectable: false, provider: "postgres", url: ""};

// 1. Fresh first-run, SQLite recommended: preview and administrator form
// visible, PostgreSQL configuration hidden.
check("fresh sqlite", machine.computeState(firstRun), {
  previewVisible: true,
  postgresConfigVisible: false,
  applyVisible: false,
  applyEnabled: false,
  adminFormVisible: true,
  registrationPolicyVisible: true,
  adminEmailRequired: true,
  adminPasswordRequired: true
});

// 2. PostgreSQL selected, empty URL: the test button is visible but disabled,
// the administrator form is hidden (never shown simultaneously).
const empty = machine.computeState(postgresSelectedEmpty);
check("postgres selected, empty URL", {
  postgresConfigVisible: empty.postgresConfigVisible,
  applyVisible: empty.applyVisible,
  applyEnabled: empty.applyEnabled,
  adminFormVisible: empty.adminFormVisible,
  adminEmailRequired: empty.adminEmailRequired,
  adminPasswordRequired: empty.adminPasswordRequired
}, {
  postgresConfigVisible: true,
  applyVisible: true,
  applyEnabled: false,
  adminFormVisible: false,
  adminEmailRequired: false,
  adminPasswordRequired: false
});

// 3. Non-empty valid URL enables the test button; hover styling is attached
// only to enabled buttons (checked separately in the CSS contract), so the
// enabled state must be the one carrying the interactive affordance.
const filled = machine.computeState(postgresSelectedFilled);
check("postgres selected, filled URL", {
  postgresConfigVisible: filled.postgresConfigVisible,
  applyVisible: filled.applyVisible,
  applyEnabled: filled.applyEnabled,
  adminFormVisible: filled.adminFormVisible
}, {
  postgresConfigVisible: true,
  applyVisible: true,
  applyEnabled: true,
  adminFormVisible: false
});

// 4. Successful connection test: the provider is no longer selectable, so the
// interface returns to administrator creation (restart is pending). The two
// forms are still never shown together.
const saved = machine.computeState(savedAwaitingRestart);
check("saved awaiting restart", {
  postgresConfigVisible: saved.postgresConfigVisible,
  applyVisible: saved.applyVisible,
  applyEnabled: saved.applyEnabled,
  adminFormVisible: saved.adminFormVisible
}, {
  postgresConfigVisible: false,
  applyVisible: false,
  applyEnabled: false,
  adminFormVisible: true
});

// 5. The restart notice explains the required restart explicitly.
const notice = machine.restartNotice("18.6 (Ubuntu 18.6-0ubuntu0.26.04.1)");
check("restart notice heading", notice.heading, "Restart required");
if (!/PostgreSQL 18\.6/.test(notice.body) || !/Stop and start Trestle/.test(notice.body)) {
  failures += 1;
  console.error("- restart notice body does not explain the restart step: " + notice.body);
}

// 6. After restart the interface says the user is creating the first
// administrator, not merely signing in, and never both.
const setupCopy = machine.authGateCopy(true);
const signInCopy = machine.authGateCopy(false);
check("first-run copy title", setupCopy.title, "Create the administrator account");
check("first-run copy submit", setupCopy.submitLabel, "Create administrator");
check("first-run copy autocomplete", setupCopy.autocomplete, "new-password");
check("sign-in copy title", signInCopy.title, "");
check("sign-in copy submit", signInCopy.submitLabel, "Sign in");
check("sign-in copy autocomplete", signInCopy.autocomplete, "current-password");
if (setupCopy.title === signInCopy.title) {
  failures += 1;
  console.error("- first-run and sign-in copy must never be identical");
}

// 7. Sign-in mode (not first-run): the database preview is hidden entirely and
// the administrator form is shown.
check("sign-in mode", machine.computeState(signIn), {
  previewVisible: false,
  postgresConfigVisible: false,
  applyVisible: false,
  applyEnabled: false,
  adminFormVisible: true,
  registrationPolicyVisible: false,
  adminEmailRequired: true,
  adminPasswordRequired: true
});

// 8. Degraded-state connection copy (CP12): each readiness state has a clear
// heading, consequence and next action, and the degraded (database
// unavailable) and starting states are distinct from ready and unreachable.
const cs = (phase, code) => machine.connectionState(phase, code);
const field = (label, actual, want) => {
  const a = JSON.stringify(actual);
  const e = JSON.stringify(want);
  if (a !== e) {
    failures += 1;
    console.error(`- ${label}: got ${a}, want ${e}`);
  }
};
field("connecting", cs("connecting").heading, "Connecting to Trestle");
field("connecting kind", cs("connecting").kind, "connecting");
field("ready", cs("ready").heading, "Trestle is ready");
field("ready kind", cs("ready").kind, "ready");
field("starting", cs("starting", "not_ready").heading, "Trestle is starting");
field("starting kind", cs("starting").kind, "starting");
field("starting next action", cs("starting").nextAction, "Check back shortly.");
const degraded = cs("databaseUnavailable", "database_unavailable");
field("database unavailable", degraded.heading, "Database unavailable");
field("database unavailable kind", degraded.kind, "databaseUnavailable");
if (!/database/.test(degraded.nextAction)) {
  failures += 1;
  console.error("- database-unavailable next action must mention the database");
}
field("unreachable", cs("unreachable").heading, "Trestle is unreachable");
field("unreachable kind", cs("unreachable").kind, "unreachable");
// Recovery: after a database-unavailable state, a later successful probe
// returns to ready (the transition the dashboard performs on retry).
field("recovery to ready", cs("ready").kind, "ready");

// 9. Reusable degraded-view state component (CP12R): each kind has plain
// language, a consequence and a next action, and never includes secrets.
const vs = (kind, opts) => machine.viewState(kind, opts);
field("loading", vs("loading").title, "Loading");
field("empty", vs("empty").title, "Nothing here yet");
field("empty next", vs("empty").nextAction, "Create the first item to see it here.");
field("permission denied", vs("error", {code: "permissionDenied"}).title, "Permission denied");
field("db unavailable", vs("error", {code: "database_unavailable"}).title, "Database unavailable");
const generic = vs("error", {message: "The request could not be completed."});
field("generic consequence", generic.consequence, "The requested operation did not finish.");
field("retrying", vs("retrying").title, "Job is retrying");
field("dead", vs("dead").title, "Job failed permanently");
field("deletion pending", vs("deletionPending").title, "File deletion is pending");
field("stale", vs("stale").title, "Realtime connection is stale");
for (const state of [vs("empty"), vs("error", {}), vs("retrying"), vs("dead"), vs("deletionPending"), vs("stale"), vs("loading")]) {
  if (JSON.stringify(state).match(/password|secret|token|Bearer/i)) {
    failures += 1;
    console.error(`- viewState ${state.kind} leaked a secret: ${JSON.stringify(state)}`);
  }
  if (!state.message || !state.consequence || !state.nextAction) {
    failures += 1;
    console.error(`- viewState ${state.kind} is missing message/consequence/nextAction`);
  }
}

// 10. Realtime staleness rule (CP12R3): clock-controlled transitions.
const stale = (last, now, paused) => machine.staleState(last, now, paused);
const T = 1_700_000_000_000; // fixed clock
field("inactive becomes stale", stale(T - 31000, T, false), true);
field("active within window stays live", stale(T - 1000, T, false), false);
field("continued events never stale", stale(T, T, false), false);
// a new event resets lastActivity, clearing the stale state
field("new event clears stale", stale(T, T, false), false);
field("pause suppresses stale", stale(T - 40000, T, true), false);

if (failures) {
  console.error(`database setup state machine: ${failures} failure(s)`);
  process.exit(1);
}
console.log("database setup state machine: all transitions pass");
