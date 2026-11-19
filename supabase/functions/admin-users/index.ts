// Edge Function: admin-users
// Lets an approved admin create / update / delete accounts from inside the app.
// The service-role key stays on the server (it is injected automatically by Supabase).
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const EMAIL_DOMAIN = "litemini.app";
const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

const PHONE_RE = /^[0-9+]{6,20}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ROLES = ["user", "rep"]; // admins are only created manually from the dashboard

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return json({ error: "method not allowed" }, 405);

  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!, {
    auth: { persistSession: false },
  });

  // 1) who is calling?
  const token = (req.headers.get("Authorization") ?? "").replace(/^Bearer\s+/i, "");
  if (!token) return json({ error: "غير مصرح" }, 401);
  const { data: caller, error: callerErr } = await admin.auth.getUser(token);
  if (callerErr || !caller?.user) return json({ error: "غير مصرح" }, 401);

  // 2) must be an approved admin
  const { data: me } = await admin.from("profiles").select("role, approved").eq("id", caller.user.id).maybeSingle();
  if (!me || me.role !== "admin" || !me.approved) return json({ error: "هذه العملية للمدير فقط" }, 403);

  let body: Record<string, unknown>;
  try { body = await req.json(); } catch { return json({ error: "طلب غير صالح" }, 400); }

  const action = String(body.action ?? "");
  const username = String(body.username ?? "").trim();
  const phone = String(body.phone ?? "").trim().replace(/\s+/g, "");
  const password = body.password ? String(body.password) : "";
  const role = String(body.role ?? "user");
  const approved = body.approved === true;
  const id = body.id ? String(body.id) : "";

  if (action === "create") {
    if (!username) return json({ error: "الرجاء إدخال اسم المستخدم" }, 400);
    if (!PHONE_RE.test(phone)) return json({ error: "رقم الموبايل غير صالح" }, 400);
    if (password.length < 8) return json({ error: "كلمة المرور يجب ألا تقل عن 8 أحرف" }, 400);
    if (!ROLES.includes(role)) return json({ error: "نوع الحساب غير صالح" }, 400);

    const { data: created, error } = await admin.auth.admin.createUser({
      email: `${phone}@${EMAIL_DOMAIN}`,
      password,
      email_confirm: true,
      user_metadata: { username, phone },
    });
    if (error || !created?.user) {
      const dup = /already|registered|exists/i.test(error?.message ?? "");
      return json({ error: dup ? "رقم الموبايل مسجل بالفعل" : "فشل إضافة الحساب" }, dup ? 409 : 400);
    }
    // the DB trigger created the profile row; now set role / approval
    const { error: upErr } = await admin.from("profiles")
      .update({ username, phone, role, approved }).eq("id", created.user.id);
    if (upErr) {
      await admin.auth.admin.deleteUser(created.user.id);
      return json({ error: "فشل حفظ بيانات الحساب" }, 500);
    }
    return json({ ok: true, id: created.user.id });
  }

  if (action === "update") {
    if (!UUID_RE.test(id)) return json({ error: "معرّف غير صالح" }, 400);
    const { data: target } = await admin.from("profiles").select("role").eq("id", id).maybeSingle();
    if (!target) return json({ error: "الحساب غير موجود" }, 404);
    if (target.role === "admin") return json({ error: "لا يمكن تعديل حساب المدير من هنا" }, 403);
    if (!username) return json({ error: "الرجاء إدخال اسم المستخدم" }, 400);
    if (!PHONE_RE.test(phone)) return json({ error: "رقم الموبايل غير صالح" }, 400);
    if (!ROLES.includes(role)) return json({ error: "نوع الحساب غير صالح" }, 400);
    if (password && password.length < 8) return json({ error: "كلمة المرور يجب ألا تقل عن 8 أحرف" }, 400);

    const patch: Record<string, unknown> = {
      email: `${phone}@${EMAIL_DOMAIN}`,
      email_confirm: true,
      user_metadata: { username, phone },
    };
    if (password) patch.password = password;
    const { error } = await admin.auth.admin.updateUserById(id, patch);
    if (error) {
      const dup = /already|registered|exists/i.test(error.message);
      return json({ error: dup ? "رقم الموبايل مسجل بالفعل" : "فشل تحديث الحساب" }, dup ? 409 : 400);
    }
    const { error: upErr } = await admin.from("profiles").update({ username, phone, role, approved }).eq("id", id);
    if (upErr) return json({ error: "فشل حفظ بيانات الحساب" }, 500);
    return json({ ok: true });
  }

  if (action === "delete") {
    if (!UUID_RE.test(id)) return json({ error: "معرّف غير صالح" }, 400);
    if (id === caller.user.id) return json({ error: "لا يمكنك حذف حسابك" }, 403);
    const { data: target } = await admin.from("profiles").select("role").eq("id", id).maybeSingle();
    if (target?.role === "admin") return json({ error: "لا يمكن حذف حساب مدير من هنا" }, 403);
    const { error } = await admin.auth.admin.deleteUser(id);
    if (error) return json({ error: "فشل حذف الحساب" }, 400);
    return json({ ok: true });
  }

  return json({ error: "إجراء غير معروف" }, 400);
});
