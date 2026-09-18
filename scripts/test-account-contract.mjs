import fs from "node:fs";

const html = fs.readFileSync("internal/web/public/index.html", "utf8");
const js = fs.readFileSync("internal/web/public/assets/js/script.js", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

// First-run administrator form: Username, Email, Password, Confirm password.
const admin = html.split('id="administrator-fields"')[1];
for (const id of ["auth-username", "auth-email", "auth-password", "auth-confirm"]) {
  a(admin.includes('id="' + id + '"'), "administrator form missing " + id);
}
a(!admin.includes("Display name") && !admin.includes("display"), "administrator form requests a display name");
// Login gate remains username-or-email.
a(js.includes("Username or email"), "login must accept username or email");
// Frontend validates password confirmation before submission.
a(js.includes('"Passwords do not match."'), "setup frontend must validate password confirmation");
console.log("trestle account-creation contract: ok");