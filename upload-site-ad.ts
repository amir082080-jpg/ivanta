import { createClient } from "npm:@supabase/supabase-js@2";
import { createRemoteJWKSet, jwtVerify } from "npm:jose@5";

const FIREBASE_PROJECT_ID = "i-vanta-cloud";
const ADMIN_UID = "MAtDMHxLQea68hL9KTrKTYFr0K73";
const BUCKET = "site-ads";
const MAX_FILE_SIZE = 5 * 1024 * 1024;
const JWKS = createRemoteJWKSet(new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"));
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
function respond(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...corsHeaders, "Content-Type": "application/json" } });
}
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return respond({ error: "Method not allowed" }, 405);
  try {
    const auth = req.headers.get("Authorization") || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
    if (!token) return respond({ error: "ورود تأیید نشد" }, 401);
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`,
      audience: FIREBASE_PROJECT_ID,
      algorithms: ["RS256"],
    });
    if (payload.sub !== ADMIN_UID) return respond({ error: "فقط مدیر اجازه آپلود تبلیغ دارد" }, 403);

    const form = await req.formData();
    const file = form.get("file");
    if (!(file instanceof File)) return respond({ error: "فایل تصویر ارسال نشده است" }, 400);
    const types: Record<string, string> = { "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp" };
    const ext = types[file.type];
    if (!ext) return respond({ error: "فرمت تصویر مجاز نیست" }, 400);
    if (file.size <= 0 || file.size > MAX_FILE_SIZE) return respond({ error: "حجم تصویر باید حداکثر ۵ مگابایت باشد" }, 400);

    const url = Deno.env.get("SUPABASE_URL");
    const key = Deno.env.get("SERVICE_ROLE_KEY");
    if (!url || !key) return respond({ error: "تنظیمات سرور کامل نیست" }, 500);
    const supabase = createClient(url, key);
    const path = `${crypto.randomUUID()}.${ext}`;
    const { error } = await supabase.storage.from(BUCKET).upload(path, file, { contentType: file.type, upsert: false });
    if (error) {
      console.error("Ad image upload error:", error.message);
      return respond({ error: "ذخیره تصویر تبلیغ انجام نشد؛ باکت site-ads را بررسی کن" }, 500);
    }
    const { data } = supabase.storage.from(BUCKET).getPublicUrl(path);
    return respond({ success: true, path, publicUrl: data.publicUrl });
  } catch (error) {
    console.error("Ad upload function error:", error);
    return respond({ error: "درخواست معتبر نیست یا ورود تأیید نشد" }, 401);
  }
});
