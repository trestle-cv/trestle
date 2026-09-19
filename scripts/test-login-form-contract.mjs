import fs from "node:fs";

const code = fs.readFileSync("internal/web/public/assets/js/script.js", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

// The sign-in (non-first-run) auth form hides the email and confirm fields.
// They must not be marked `required`: constraint validation runs on hidden
// inputs too, so an empty required hidden field makes the form permanently
// invalid and the admin/sign-in POST can never be submitted in any browser.
a(code.includes("adminEmailRequired: firstRun && !pendingPostgres"),
  "adminEmailRequired must be gated on first-run mode so the sign-in form is satisfiable");
a(code.includes("authConfirm.required=state.adminEmailRequired"),
  "confirm required must follow the (first-run-only) email requirement");
a(code.includes("authEmail.required=setupRequired"),
  "initializeAuth must clear email required outside first-run setup");

// The main password field is always required (it is shown in both modes).
a(code.includes("adminPasswordRequired: !pendingPostgres"),
  "adminPasswordRequired must remain required outside first-run");

console.log("trestle login-form frontend contract: PASS");