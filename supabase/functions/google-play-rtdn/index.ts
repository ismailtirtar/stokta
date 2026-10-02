import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import { GooglePlayError } from "../_shared/google_play.ts";
import {
  GooglePushAuthUnavailable,
  verifyGooglePlayPush,
} from "../_shared/google_play_push_auth.ts";
import {
  GooglePlayPushMalformed,
  readGooglePlayPushEvent,
} from "../_shared/google_play_rtdn_payload.ts";
import { processGooglePlayToken } from "../_shared/google_play_sync.ts";
import { json, sha256 } from "../_shared/security.ts";

// The Supabase JWT gateway must be disabled for this function. Google Pub/Sub
// supplies its own signed OIDC bearer token, checked before any body is read.
Deno.serve(async (request: Request) => {
  if (request.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });

  const audience = Deno.env.get("GOOGLE_PLAY_RTDN_AUDIENCE") ?? "";
  const serviceAccount = Deno.env.get("GOOGLE_PLAY_RTDN_SERVICE_ACCOUNT") ?? "";
  const subscription = Deno.env.get("GOOGLE_PLAY_RTDN_SUBSCRIPTION") ?? "";
  if (!audience || !serviceAccount
    || !/^projects\/[A-Za-z0-9._~+%-]{3,255}\/subscriptions\/[A-Za-z0-9._~+%-]{3,255}$/.test(
      subscription,
    )) return json(503, { error: "Google Play bildirim yapılandırması eksik" });

  try {
    if (!await verifyGooglePlayPush(request, audience, serviceAccount)) {
      return json(401, { error: "Pub/Sub kimliği doğrulanamadı" });
    }
  } catch (error) {
    if (error instanceof GooglePushAuthUnavailable) {
      return json(503, { error: "Pub/Sub kimliği şu anda doğrulanamıyor" });
    }
    console.error("Google Play push authentication failed", {
      name: error instanceof Error ? error.name : "unknown",
    });
    return json(503, { error: "Pub/Sub kimliği şu anda doğrulanamıyor" });
  }

  let event: Awaited<ReturnType<typeof readGooglePlayPushEvent>>;
  try {
    event = await readGooglePlayPushEvent(request, subscription);
  } catch (error) {
    if (error instanceof GooglePlayPushMalformed) {
      console.warn("Google Play push notification discarded", { reason: error.message });
      return new Response(null, { status: 204 });
    }
    console.error("Google Play push body unavailable", {
      name: error instanceof Error ? error.name : "unknown",
    });
    return json(503, { error: "Bildirim okunamadı" });
  }
  if (event.kind === "ignore") return new Response(null, { status: 204 });

  const supabaseUrl = Deno.env.get("SUPABASE_URL");
  const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!supabaseUrl || !serviceRoleKey) {
    return json(503, { error: "Abonelik sunucu yapılandırması eksik" });
  }
  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { autoRefreshToken: false, persistSession: false },
  });

  try {
    if (event.kind === "void") {
      // Persist the order-specific refund fence before any fresh Publisher GET
      // could accidentally grant access for that same order.
      const { error } = await admin.rpc("service_record_google_play_void", {
        p_token_hash: await sha256(event.purchaseToken),
        p_order_hash: await sha256(event.orderId),
        p_event_time: event.eventTime,
      });
      if (error) {
        console.error("Google Play void fence failed", { code: error.code ?? "unknown" });
        return json(503, { error: "İade bildirimi kaydedilemedi" });
      }
    }
    // Notifications are hints. The common sync path validates the latest
    // subscriptionsv2 resource and known ownership before changing access.
    // An unknown token is safely ignored by that path; Pub/Sub can acknowledge it.
    await processGooglePlayToken(admin, event.purchaseToken, "rtdn");
    return new Response(null, { status: 204 });
  } catch (error) {
    if (error instanceof GooglePlayError
      && ["INVALID_REQUEST", "INVALID_PURCHASE", "IDENTITY_MISMATCH"].includes(error.code)) {
      console.warn("Google Play notification cannot be applied", { code: error.code });
      return new Response(null, { status: 204 });
    }
    console.error("Google Play notification processing failed", {
      name: error instanceof Error ? error.name : "unknown",
      code: error instanceof GooglePlayError ? error.code : "unknown",
    });
    // Pub/Sub will retry transient Publisher/API/database failures.
    return json(503, { error: "Abonelik bildirimi işlenemedi" });
  }
});
