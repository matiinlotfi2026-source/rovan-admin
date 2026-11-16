export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return api(request, env, url);
    if (url.pathname === "/admin") {
      return env.ASSETS.fetch(new Request(new URL("/admin.html", url), request));
    }
    return env.ASSETS.fetch(request);
  }
};

const json = (data, status=200, headers={}) =>
  new Response(JSON.stringify(data), {status, headers: {"content-type":"application/json; charset=utf-8", ...headers}});
const cookieName = "rovan_admin";

async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replaceAll("+","-").replaceAll("/","_").replaceAll("=","");
}
async function validSession(req, env) {
  const raw = req.headers.get("Cookie") || "";
  const token = raw.split(";").map(x=>x.trim()).find(x=>x.startsWith(cookieName+"="))?.split("=")[1];
  if (!token || !env.SESSION_SECRET) return false;
  const [exp, sig] = token.split(".");
  if (!exp || Number(exp) < Date.now()) return false;
  return (await sign(exp, env.SESSION_SECRET)) === sig;
}
function sessionCookie(value, maxAge) {
  return `${cookieName}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}
async function api(req, env, url) {
  if (url.pathname === "/api/login" && req.method === "POST") {
    const body = await req.json().catch(()=>({}));
    if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) return json({error:"تنظیمات ورود مدیر کامل نیست."},500);
    if (body.username !== "admin" || body.password !== env.ADMIN_PASSWORD) return json({error:"نام کاربری یا رمز عبور نادرست است."},401);
    const exp = String(Date.now()+8*60*60*1000);
    const sig = await sign(exp, env.SESSION_SECRET);
    return json({ok:true},200,{ "set-cookie":sessionCookie(`${exp}.${sig}`,8*60*60) });
  }
  if (url.pathname === "/api/logout" && req.method === "POST")
    return json({ok:true},200,{"set-cookie":sessionCookie("",0)});
  if (!await validSession(req, env)) return json({error:"ابتدا وارد پنل شوید."},401);
  if (url.pathname === "/api/products" && req.method === "GET") {
    const {results=[]} = await env.DB.prepare("SELECT * FROM products ORDER BY id DESC").all();
    return json(results);
  }
  if (url.pathname === "/api/products" && req.method === "POST") {
    const p = await req.json();
    if (!p.name?.trim()) return json({error:"نام محصول الزامی است."},400);
    const result = await env.DB.prepare("INSERT INTO products (name,description,price,image_url,stock,is_active) VALUES (?,?,?,?,?,?)")
      .bind(p.name.trim(),p.description||"",Number(p.price)||0,p.image_url||"",Math.max(0,Number(p.stock)||0),p.is_active===false?0:1).run();
    return json({ok:true,id:result.meta.last_row_id});
  }
  const productMatch = url.pathname.match(/^\/api\/products\/(\d+)$/);
  if (productMatch && req.method === "PUT") {
    const p = await req.json();
    await env.DB.prepare("UPDATE products SET name=?,description=?,price=?,image_url=?,stock=?,is_active=? WHERE id=?")
      .bind(p.name,p.description||"",Number(p.price)||0,p.image_url||"",Math.max(0,Number(p.stock)||0),p.is_active===false?0:1,Number(productMatch[1])).run();
    return json({ok:true});
  }
  if (productMatch && req.method === "DELETE") {
    await env.DB.prepare("DELETE FROM products WHERE id=?").bind(Number(productMatch[1])).run();
    return json({ok:true});
  }
  if (url.pathname === "/api/orders" && req.method === "GET") {
    const {results=[]} = await env.DB.prepare("SELECT * FROM orders ORDER BY id DESC LIMIT 300").all();
    return json(results);
  }
  const orderMatch = url.pathname.match(/^\/api\/orders\/(\d+)$/);
  if (orderMatch && req.method === "PATCH") {
    const b=await req.json();
    await env.DB.prepare("UPDATE orders SET status=? WHERE id=?").bind(String(b.status||"new"),Number(orderMatch[1])).run();
    return json({ok:true});
  }
  return json({error:"مسیر پیدا نشد."},404);
}
