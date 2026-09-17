import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "npm:@supabase/supabase-js@2.112.3";
import {
  authorizeGooglePlayPush,
  GOOGLE_PLAY_PACKAGE_NAME,
  GooglePlayError,
  validateGooglePlayPurchaseToken,
} from "../_shared/google_play.ts";
import { encryptPurchaseToken } from "../_shared/google_play_subscription_sync.ts";
import { HttpInputError, isRecord, json, readBoundedJson, sha256 } from "../_shared/security.ts";

function decodeData(value: unknown) {
  if (typeof value !== "string" || value.length < 4 || value.length > 64_000
    || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) throw new HttpInputError(400, "Geçersiz Pub/Sub verisi");
  try {
    const bytes = Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
    if (bytes.byteLength > 32_768) throw new Error("large");
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!isRecord(parsed)) throw new Error("shape");
    return parsed;
  } catch {
    throw new HttpInputError(400, "Geçersiz Pub/Sub verisi");
  }
}

function eventTime(notification: Record<string, unknown>) {
  if (typeof notification.eventTimeMillis !== "string"
    || !/^\d{10,16}$/.test(notification.eventTimeMillis)) return null;
  const milliseconds = Number(notification.eventTimeMillis);
  return Number.isSafeInteger(milliseconds) && milliseconds >= 0 && milliseconds <= 8_640_000_000_000_000
    ? new Date(milliseconds).toISOString()
    : null;
}

const notificationKeys = [
  "subscriptionNotification",
  "oneTimeProductNotification",
  "voidedPurchaseNotification",
  "testNotification",
] as const;

function exactNotificationKind(
  notification: Record<string, unknown>,
): typeof notificationKeys[number] | null {
  const present = notificationKeys.filter((key) => notification[key] !== undefined);
  const key = present[0];
  return present.length === 1 && key !== undefined && isRecord(notification[key]) ? key : null;
}

Deno.serve(async (req: Request) => {
  if (req.method !== "POST") return json(405, { error: "Yalnızca POST desteklenir" });
  try {
    if (!await authorizeGooglePlayPush(req)) return json(401, { error: "Geçersiz Pub/Sub kimliği" });
    const supabaseUrl = Deno.env.get("SUPABASE_URL");
    const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
    const expectedSubscription = Deno.env.get("GOOGLE_PLAY_RTDN_SUBSCRIPTION") ?? "";
    if (!supabaseUrl || !serviceRoleKey
      || !/^projects\/[a-z0-9][a-z0-9-]{4,61}[a-z0-9]\/subscriptions\/[A-Za-z0-9._~+%-]{3,255}$/.test(
        expectedSubscription,
      )) return json(500, { error: "Sunucu yapılandırması eksik" });
    const admin = createClient(supabaseUrl, serviceRoleKey, {
      auth: { autoRefreshToken: false, persistSession: false },
    });

    const envelope = await readBoundedJson(req, 96_000);
    if (!isRecord(envelope) || !isRecord(envelope.message)
      || envelope.subscription !== expectedSubscription) {
      console.error("Malformed Google Play Pub/Sub envelope");
      return new Response(null, { status: 204 });
    }
    const messageId = typeof envelope.message.messageId === "string"
      ? envelope.message.messageId
      : envelope.message.message_id;
    if (typeof messageId !== "string" || messageId.length < 1 || messageId.length > 240) {
      console.error("Google Play Pub/Sub message id is invalid");
      return new Response(null, { status: 204 });
    }
    const notification = decodeData(envelope.message.data);
    const observedAt = eventTime(notification);
    const kind = exactNotificationKind(notification);
    if (notification.version !== "1.0" || notification.packageName !== GOOGLE_PLAY_PACKAGE_NAME
      || !observedAt || kind === null) {
      console.error("Google Play Pub/Sub package/time is invalid", { messageId });
      return new Response(null, { status: 204 });
    }

    const subscription = notification.subscriptionNotification;
    if (kind === "subscriptionNotification" && isRecord(subscription)) {
      // SubscriptionNotification intentionally has no product id. Product and
      // base-plan validation happens against subscriptionsv2.get in the worker.
      if (subscription.version !== "1.0"
        || typeof subscription.notificationType !== "number"
        || !Number.isInteger(subscription.notificationType)
        || subscription.notificationType < 1 || subscription.notificationType > 22) {
        console.error("Unsupported subscription RTDN type", { messageId });
        return new Response(null, { status: 204 });
      }
      const token = validateGooglePlayPurchaseToken(subscription.purchaseToken);
      const tokenHash = await sha256(token);
      const secret = await encryptPurchaseToken(token);
      const { error } = await admin.rpc("service_enqueue_google_play_rtdn", {
        p_message_id: messageId,
        p_purchase_token_hash: tokenHash,
        p_notification_type: subscription.notificationType,
        p_event_time: observedAt,
        p_token_ciphertext: secret.ciphertext,
        p_token_nonce: secret.nonce,
        p_token_key_version: secret.keyVersion,
      });
      if (error) {
        console.error("RTDN durable enqueue failed", { code: error.code ?? "unknown" });
        return json(503, { error: "Bildirim kuyruğa alınamadı" });
      }
      // Processing is deliberately decoupled from the Pub/Sub request. A
      // scheduled worker owns retries, fairness and poison-message handling.
      return new Response(null, { status: 204 });
    }

    const voided = notification.voidedPurchaseNotification;
    if (kind === "voidedPurchaseNotification" && isRecord(voided)) {
      const token = validateGooglePlayPurchaseToken(voided.purchaseToken);
      if (voided.productType !== 1
        || typeof voided.refundType !== "number"
        || !Number.isInteger(voided.refundType)
        || ![1, 2].includes(voided.refundType)
        || typeof voided.orderId !== "string" || voided.orderId.length < 1 || voided.orderId.length > 256) {
        console.error("Voided purchase order id is invalid", { messageId });
        return new Response(null, { status: 204 });
      }
      const tokenHash = await sha256(token);
      const orderHash = await sha256(voided.orderId);
      const secret = await encryptPurchaseToken(token);
      // The refund/void fence is committed before any future Publisher GET can
      // grant or acknowledge this exact order.
      const { data, error } = await admin.rpc("service_record_google_play_voided_notification", {
        p_message_id: messageId,
        p_purchase_token_hash: tokenHash,
        p_order_id_hash: orderHash,
        p_event_time: observedAt,
        p_token_ciphertext: secret.ciphertext,
        p_token_nonce: secret.nonce,
        p_token_key_version: secret.keyVersion,
      });
      if (error || !isRecord(data)) {
        console.error("Voided purchase fence failed", { code: error?.code ?? "unknown" });
        return json(503, { error: "İade bildirimi kaydedilemedi" });
      }
      if (data.deletedOwner === true) {
        const { error: enqueueError } = await admin.rpc("service_enqueue_google_play_rtdn", {
          p_message_id: `${messageId}:stop`,
          p_purchase_token_hash: tokenHash,
          p_notification_type: 22,
          p_event_time: observedAt,
          p_token_ciphertext: secret.ciphertext,
          p_token_nonce: secret.nonce,
          p_token_key_version: secret.keyVersion,
        });
        if (enqueueError) return json(503, { error: "Silinmiş hesap bildirimi kuyruğa alınamadı" });
      }
      return new Response(null, { status: 204 });
    }

    // Strictly-shaped test and unrelated one-time-product notifications are
    // intentionally acknowledged; they never reach the subscription ledger.
    const ignored = notification[kind];
    if (!isRecord(ignored) || ignored.version !== "1.0") {
      console.error("Unsupported Google Play notification version", { messageId, kind });
    }
    return new Response(null, { status: 204 });
  } catch (error) {
    if (error instanceof HttpInputError) {
      console.error("Malformed Google Play Pub/Sub body", { status: error.status });
      return new Response(null, { status: 204 });
    }
    if (error instanceof GooglePlayError
      && ["INVALID_REQUEST", "INVALID_PURCHASE", "INVALID_RESPONSE"].includes(error.code)) {
      console.error("Malformed Google Play notification", { code: error.code });
      return new Response(null, { status: 204 });
    }
    console.error("Google Play RTDN failed", { name: error instanceof Error ? error.name : "unknown" });
    return json(503, { error: "Bildirim işlenemedi" });
  }
});
