import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { corsJsonHeaders, json } from "../_shared/security.ts";

// The one-time platform bootstrap has already been completed. Keeping an
// unauthenticated creation path would let an attacker become platform operator
// if all profiles were ever removed, so POST is permanently fail-closed.
Deno.serve((req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsJsonHeaders });
  if (req.method === "GET") {
    return json(200, { initialized: true, bootstrapDisabled: true });
  }
  if (req.method === "POST") {
    return json(410, {
      error: "İlk kurulum uç noktası kalıcı olarak kapatıldı",
      code: "BOOTSTRAP_DISABLED",
    });
  }
  return json(405, { error: "Yalnızca GET ve POST desteklenir" });
});
