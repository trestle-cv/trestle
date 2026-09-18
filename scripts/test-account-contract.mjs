import fs from "node:fs";

const html = fs.readFileSync("internal/web/public/index.html", "utf8");
const js = fs.readFileSync("internal/web/public/assets/js/script.js", "utf8");
const manageJs = fs.readFileSync("internal/web/public/assets/js/manage.js", "utf8");
function a(cond, msg) { if (!cond) throw new Error(msg); }

// First-run administrator form: Username, Email, Password, Confirm password.
const admin = html.split('id="administrator-fields"')[1];
for (const id of ["auth-username", "auth-email", "auth-password", "auth-confirm"]) {
  a(admin.includes('id="' + id + '"'), "administrator form missing " + id);
}
a(!/Display name|display/.test(admin), "administrator form requests a display name");
a(js.includes("Username or email"), "login must accept username or email");
a(js.includes("Passwords do not match."), "setup frontend must validate password confirmation");

// /manage user creation: Username, Email, Password, Confirm password, Roles.
const newUser = manageJs.split('<form id="new-user">')[1].split('</form>')[0];
for (const id of ["username", "email", "password", "confirm"]) {
  a(newUser.includes('name="' + id + '"'), "/manage new-user form missing " + id);
}
a(/Display name|display/.test(newUser) === false, "/manage new-user form requests a display name");
a(manageJs.includes("Passwords do not match."), "/manage frontend must validate password confirmation");
a(manageJs.includes('action:"create",username:f.get("username")'), "/manage create payload must send username");

console.log("trestle account-creation contract: ok");