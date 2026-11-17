const COOKIE_NAME = "noire_admin_session";
const SESSION_HOURS = 8;
async function sign(value, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(value)
  );
  return btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
async function validSession(request, secret) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(COOKIE_NAME + "=([^;]+)"));
  if (!match) return false;
  const parts = match[1].split(".");
  if (parts.length !== 2) return false;
  const timestamp = Number(parts[0]);
  if (!Number.isFinite(timestamp)) return false;
  const age = Date.now() - timestamp;
  if (age < 0 || age > SESSION_HOURS * 60 * 60 * 1000) return false;
  const expected = await sign(parts[0], secret);
  return expected === parts[1];
}
function loginPage(error = "") {
  return `<!DOCTYPE html>
  <html lang="ar" dir="rtl">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>NOIRÉ | Admin Login</title>
    <style>
      *{box-sizing:border-box}
      body{
        margin:0;min-height:100vh;display:grid;place-items:center;
        background:#100e0b;color:#f5ead8;font-family:Arial,sans-serif;
      }
      .box{
        width:min(90%,390px);padding:35px;background:#1c1812;
        border:1px solid #b99a61;text-align:center;
      }
      h1{color:#d6b77c;letter-spacing:5px}
      p{color:#b9aa95}
      input,button{
        width:100%;padding:15px;margin-top:15px;border-radius:5px;
      }
      input{background:#100e0b;border:1px solid #493a25;color:white}
      button{background:#c6a56b;border:0;font-weight:bold;cursor:pointer}
      .error{color:#ff8b75}
    </style>
  </head>
  <body>
    <form class="box" method="POST" action="/admin/login">
      <h1>NOIRÉ</h1>
      <p>ADMINISTRATION ACCESS</p>
      <input type="password" name="password" placeholder="كلمة المرور" required>
      <button type="submit">دخول</button>
      ${error ? '<p class="error">كلمة المرور غير صحيحة</p>' : ''}
    </form>
  </body>
  </html>`;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (!env.ADMIN_PASSWORD) {
      return new Response("Admin password secret is not configured.", {
        status: 500
      });
    }
    if (path === "/admin/login" && request.method === "POST") {
      const form = await request.formData();
      const password = form.get("password");
      if (typeof password !== "string" ||
          password !== env.ADMIN_PASSWORD) {
        return new Response(loginPage(true), {
          status: 401,
          headers: { "Content-Type": "text/html; charset=UTF-8" }
        });
      }
      const timestamp = String(Date.now());
      const signature = await sign(timestamp, env.ADMIN_PASSWORD);
      const token = timestamp + "." + signature;
      return new Response(null, {
        status: 303,
        headers: {
          "Location": "/admin",
          "Set-Cookie":
            `${COOKIE_NAME}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_HOURS * 3600}`
        }
      });
    }
    if (path === "/admin/logout") {
      return new Response(null, {
        status: 303,
        headers: {
          "Location": "/admin",
          "Set-Cookie":
            `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
        }
      });
    }
    if (path === "/admin" || path === "/admin/") {
      if (!(await validSession(request, env.ADMIN_PASSWORD))) {
        return new Response(loginPage(), {
          headers: { "Content-Type": "text/html; charset=UTF-8" }
        });
      }
      return env.ASSETS.fetch(
        new Request(new URL("/admin.html", request.url), request)
      );
    }
    if (path === "/admin.html") {
      if (!(await validSession(request, env.ADMIN_PASSWORD))) {
        return new Response(null, {
          status: 302,
          headers: { "Location": "/admin" }
        });
      }
    }
    return env.ASSETS.fetch(request);
  }
};
