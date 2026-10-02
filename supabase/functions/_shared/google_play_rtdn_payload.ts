import { GOOGLE_PLAY_PACKAGE_NAME, validateGooglePlayPurchaseToken } from "./google_play.ts";

const MAX_BODY_BYTES = 96_000;
const MAX_DATA_BYTES = 32_768;
const MAX_EVENT_AGE_MS = 120 * 24 * 60 * 60 * 1_000;

type ObjectValue = Record<string, unknown>;

export type GooglePlayPushEvent =
  | { kind: "subscription"; messageId: string; purchaseToken: string; eventTime: string }
  | { kind: "void"; messageId: string; purchaseToken: string; orderId: string; eventTime: string }
  | { kind: "ignore"; reason: string };

export class GooglePlayPushMalformed extends Error {
  constructor(reason: string) {
    super(reason);
    this.name = "GooglePlayPushMalformed";
  }
}

function object(value: unknown): value is ObjectValue {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function readBoundedBody(request: Request): Promise<ObjectValue> {
  if (!request.body) throw new GooglePlayPushMalformed("empty_body");
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) throw new GooglePlayPushMalformed("large_body");
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof GooglePlayPushMalformed) throw error;
    throw new GooglePlayPushMalformed("unreadable_body");
  } finally {
    if (total > MAX_BODY_BYTES) await reader.cancel().catch(() => undefined);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    const result: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (object(result)) return result;
  } catch { /* handled below */ }
  throw new GooglePlayPushMalformed("invalid_json");
}

function decodeNotification(data: unknown): ObjectValue {
  if (typeof data !== "string" || data.length < 4 || data.length > 64_000
    || !/^[A-Za-z0-9+/]+={0,2}$/.test(data)) {
    throw new GooglePlayPushMalformed("invalid_data");
  }
  try {
    const binary = atob(data);
    if (binary.length > MAX_DATA_BYTES) throw new Error("large_data");
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    const result: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (object(result)) return result;
  } catch { /* handled below */ }
  throw new GooglePlayPushMalformed("invalid_data");
}

function eventTime(value: unknown, now: number): string {
  if (typeof value !== "string" || !/^\d{10,16}$/.test(value)) {
    throw new GooglePlayPushMalformed("invalid_event_time");
  }
  const milliseconds = Number(value);
  if (!Number.isSafeInteger(milliseconds)
    || milliseconds < now - MAX_EVENT_AGE_MS
    || milliseconds > now + 10 * 60_000) {
    throw new GooglePlayPushMalformed("invalid_event_time");
  }
  return new Date(milliseconds).toISOString();
}

function purchaseToken(value: unknown): string {
  try {
    return validateGooglePlayPurchaseToken(value);
  } catch {
    throw new GooglePlayPushMalformed("invalid_purchase_token");
  }
}

/** Only signed Pub/Sub requests should reach this parser. Malformed messages are poison, not retries. */
export async function readGooglePlayPushEvent(
  request: Request,
  expectedSubscription: string,
  now = Date.now(),
): Promise<GooglePlayPushEvent> {
  const envelope = await readBoundedBody(request);
  if (envelope.subscription !== expectedSubscription || !object(envelope.message)) {
    throw new GooglePlayPushMalformed("invalid_envelope");
  }
  const messageId = envelope.message.messageId ?? envelope.message.message_id;
  if (typeof messageId !== "string" || messageId.length < 1 || messageId.length > 256
    || /[\u0000-\u001f\u007f]/.test(messageId)) {
    throw new GooglePlayPushMalformed("invalid_message_id");
  }
  const notification = decodeNotification(envelope.message.data);
  if (notification.packageName !== GOOGLE_PLAY_PACKAGE_NAME
    || notification.version !== "1.0") {
    throw new GooglePlayPushMalformed("invalid_package_or_version");
  }
  const occurredAt = eventTime(notification.eventTimeMillis, now);
  const kinds = [
    "subscriptionNotification", "voidedPurchaseNotification", "oneTimeProductNotification",
    "testNotification", "pendingRefundReviewNotification",
  ];
  const present = kinds.filter((key) => notification[key] !== undefined);
  if (present.length !== 1 || !object(notification[present[0]!])) {
    throw new GooglePlayPushMalformed("invalid_notification_kind");
  }
  const kind = present[0];
  const detail = notification[kind!] as ObjectValue;
  if (kind === "subscriptionNotification") {
    if (detail.version !== "1.0" || typeof detail.notificationType !== "number"
      || !Number.isInteger(detail.notificationType)
      || detail.notificationType < 1 || detail.notificationType > 1_000) {
      throw new GooglePlayPushMalformed("invalid_subscription_notification");
    }
    return { kind: "subscription", messageId, purchaseToken: purchaseToken(detail.purchaseToken), eventTime: occurredAt };
  }
  if (kind === "voidedPurchaseNotification") {
    if (detail.productType === 2) return { kind: "ignore", reason: "one_time_void" };
    if (detail.productType !== 1 || ![1, 2].includes(detail.refundType as number)
      || typeof detail.orderId !== "string" || detail.orderId.length < 1
      || detail.orderId.length > 256 || /[\u0000-\u001f\u007f]/.test(detail.orderId)) {
      throw new GooglePlayPushMalformed("invalid_void_notification");
    }
    return {
      kind: "void", messageId, purchaseToken: purchaseToken(detail.purchaseToken),
      orderId: detail.orderId, eventTime: occurredAt,
    };
  }
  return { kind: "ignore", reason: kind ?? "unrelated" };
}
