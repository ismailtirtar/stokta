import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  ActivityIndicator,
  Linking,
  Modal,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { requireOptionalNativeModule } from "expo-modules-core";
import { useIAP } from "expo-iap";
import type { ProductSubscription, Purchase } from "expo-iap";
import {
  billingOpaqueId,
  ANDROID_PACKAGE_NAME,
  PLAY_SUBSCRIPTION_BASE_PLAN_ID,
  PLAY_SUBSCRIPTION_PRODUCT_ID,
} from "../lib/billing";
import { supabase } from "../lib/supabase";

type Props = {
  visible: boolean;
  userId: string;
  organizationId: string;
  subscriptionLabel: string;
  trialEndsAt: string | null;
  currentPeriodEnd: string | null;
  onClose: () => void;
  onSubscriptionUpdated: () => Promise<void> | void;
};

type VerificationResponse = {
  store?: string;
  entitled?: boolean;
  acknowledged?: boolean;
  subscriptionStatus?: string;
  currentPeriodEnd?: string | null;
};

type ScreenState = "idle" | "launching" | "verifying" | "restoring" | "pending" | "success";

const PURCHASE_REVERIFY_TTL_MS = 30_000;

export default function SubscriptionModal({
  visible,
  onClose,
  ...nativeProps
}: Props) {
  const hasNativeGoogleBilling = Platform.OS === "android" && Boolean(requireOptionalNativeModule("ExpoIap"));
  if (!hasNativeGoogleBilling) {
    return (
      <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
        <View style={styles.backdrop}>
          <View style={styles.unavailableSheet}>
            <View style={styles.handle} />
            <Text style={styles.title}>Google Play ödemeleri</Text>
            <Text style={styles.unavailableText}>Bu özellik Expo Go'da veya Play Store dışındaki kurulumlarda kullanılamaz. Google Play'den yüklenen güncel Stokdaş sürümünü kullanın.</Text>
            <Pressable style={styles.restoreButton} onPress={onClose} accessibilityRole="button" accessibilityLabel="Abonelik ekranını kapat">
              <Text style={styles.restoreButtonText}>Kapat</Text>
            </Pressable>
          </View>
        </View>
      </Modal>
    );
  }
  return <NativeSubscriptionModal visible={visible} onClose={onClose} {...nativeProps} />;
}

function NativeSubscriptionModal({
  visible,
  userId,
  organizationId,
  subscriptionLabel,
  trialEndsAt,
  currentPeriodEnd,
  onClose,
  onSubscriptionUpdated,
}: Props) {
  const [screenState, setScreenState] = useState<ScreenState>("idle");
  const [error, setError] = useState("");
  const [storeMessage, setStoreMessage] = useState("");
  const [nativeUnavailable, setNativeUnavailable] = useState(Platform.OS !== "android");
  const [productLoading, setProductLoading] = useState(false);
  const purchaseHandlerRef = useRef<((purchase: Purchase) => Promise<void>) | null>(null);
  const recentlyProcessedPurchaseHashesRef = useRef(new Map<string, number>());
  const processingPurchaseHashesRef = useRef(new Set<string>());
  const reconciledForVisibleSessionRef = useRef(false);
  const onSubscriptionUpdatedRef = useRef(onSubscriptionUpdated);
  onSubscriptionUpdatedRef.current = onSubscriptionUpdated;

  const handleIapError = useCallback((iapError: { code?: string; message?: string }) => {
    setScreenState("idle");
    setError("");
    if (iapError.code === "user-cancelled" || /user.*cancel|cancelled by user/i.test(iapError.message ?? "")) {
      setStoreMessage("Satın alma işlemi iptal edildi.");
      return;
    }

    const message = iapError.message ?? "Google Play ile bağlantı kurulamadı.";
    if (/native module|iap.*unavailable|billing.*unavailable|unsupported platform/i.test(message)) {
      setNativeUnavailable(true);
      setError("Google Play ödemeleri bu uygulama kurulumunda kullanılamıyor. Play Store'dan yüklenen güncel Stokdaş sürümünü kullanın.");
      return;
    }
    setError(friendlyBillingError(message));
  }, []);

  const {
    connected,
    subscriptions,
    availablePurchases,
    fetchProducts,
    requestPurchase,
    finishTransaction,
    getAvailablePurchases,
    restorePurchases,
    reconnect,
  } = useIAP({
    onPurchaseSuccess: (purchase) => { void purchaseHandlerRef.current?.(purchase); },
    onPurchaseError: handleIapError,
    onError: handleIapError,
    onSubscriptionBillingIssue: () => {
      setStoreMessage("Google Play ödeme yönteminizin güncellenmesi gerekiyor.");
    },
  });

  const fetchSubscriptionProducts = useCallback(async () => {
    if (Platform.OS !== "android") return;
    setProductLoading(true);
    setError("");
    try {
      await fetchProducts({ skus: [PLAY_SUBSCRIPTION_PRODUCT_ID], type: "subs" });
    } catch (fetchError) {
      setError(friendlyBillingError(errorMessage(fetchError)));
    } finally {
      setProductLoading(false);
    }
  }, [fetchProducts]);

  const playSubscription = useMemo(
    () => subscriptions.find((item) => item.id === PLAY_SUBSCRIPTION_PRODUCT_ID),
    [subscriptions],
  );
  const basePlanOffer = useMemo(() => findMonthlyBasePlan(playSubscription), [playSubscription]);
  const localizedPrice = useMemo(() => {
    const phases = basePlanOffer?.pricingPhases.pricingPhaseList ?? [];
    return phases.at(-1)?.formattedPrice ?? playSubscription?.displayPrice ?? "";
  }, [basePlanOffer, playSubscription]);

  const processPurchase = useCallback(async (purchase: Purchase) => {
    if (purchase.productId !== PLAY_SUBSCRIPTION_PRODUCT_ID || purchase.store !== "google") return;
    const googlePurchase = purchase as Purchase & {
      isAcknowledgedAndroid?: boolean | null;
      isSuspendedAndroid?: boolean | null;
    };

    if (purchase.purchaseState !== "purchased" && !googlePurchase.isSuspendedAndroid) {
      if (purchase.purchaseState === "pending") {
        setScreenState("pending");
        setError("");
        setStoreMessage("Ödeme Google Play'de bekliyor. Onaylanana kadar abonelik etkinleştirilmez.");
      }
      return;
    }

    const purchaseToken = purchase.purchaseToken;
    if (!purchaseToken) {
      setError("Google Play satın alma kaydı alınamadı. Lütfen satın alımları geri yükleyin.");
      setScreenState("idle");
      return;
    }

    const purchaseHash = await billingOpaqueId(purchaseToken);
    const lastProcessedAt = recentlyProcessedPurchaseHashesRef.current.get(purchaseHash);
    if (processingPurchaseHashesRef.current.has(purchaseHash)
      || (lastProcessedAt !== undefined && Date.now() - lastProcessedAt < PURCHASE_REVERIFY_TTL_MS)) return;

    if (lastProcessedAt !== undefined) recentlyProcessedPurchaseHashesRef.current.delete(purchaseHash);

    processingPurchaseHashesRef.current.add(purchaseHash);
    setScreenState("verifying");
    setError("");
    setStoreMessage("Satın alma Google Play ile doğrulanıyor…");

    try {
      const { data, error: verificationError } = await supabase.functions.invoke<VerificationResponse>(
        "verify-play-subscription",
        { body: { purchaseToken, productId: PLAY_SUBSCRIPTION_PRODUCT_ID } },
      );
      if (verificationError) throw new Error(await edgeFunctionMessage(verificationError));

      const processedAt = Date.now();
      recentlyProcessedPurchaseHashesRef.current.set(purchaseHash, processedAt);
      setTimeout(() => {
        if (recentlyProcessedPurchaseHashesRef.current.get(purchaseHash) === processedAt) {
          recentlyProcessedPurchaseHashesRef.current.delete(purchaseHash);
        }
      }, PURCHASE_REVERIFY_TTL_MS);

      if (data?.store === "google" && data.subscriptionStatus === "suspended") {
        setScreenState("pending");
        setError("");
        setStoreMessage("İşletme erişimi platform güvenlik kararıyla askıya alınmış. Google Play aboneliğini doğrulamak veya geri yüklemek bu kısıtlamayı kaldırmaz; destek için Stokdaş ile iletişime geçin.");
        await onSubscriptionUpdatedRef.current();
        return;
      }

      if (!data?.entitled || data.store !== "google") {
        setScreenState("pending");
        setStoreMessage(googlePurchase.isSuspendedAndroid
          ? "Google Play aboneliği ödeme sorunu nedeniyle askıda. Ödeme yönteminizi Google Play'de güncelleyin; ardından satın alımları geri yükleyin."
          : "Ödeme henüz tamamlanmadı. Abonelik yalnızca Google Play onayından sonra açılır.");
        return;
      }

      if (!data.acknowledged && !googlePurchase.isAcknowledgedAndroid) {
        await finishTransaction({ purchase, isConsumable: false });
      }
      setScreenState("success");
      setStoreMessage("Abonelik doğrulandı ve işletme erişimi güncellendi.");
      await onSubscriptionUpdatedRef.current();
    } catch (verificationFailure) {
      setScreenState("idle");
      setError(friendlyBillingError(errorMessage(verificationFailure)));
      setStoreMessage("");
    } finally {
      processingPurchaseHashesRef.current.delete(purchaseHash);
    }
  }, [finishTransaction]);
  purchaseHandlerRef.current = processPurchase;

  useEffect(() => {
    if (!visible) {
      reconciledForVisibleSessionRef.current = false;
      return;
    }
    if (!connected || Platform.OS !== "android") return;
    setNativeUnavailable(false);
    setError("");
    void fetchSubscriptionProducts();

    if (!reconciledForVisibleSessionRef.current) {
      reconciledForVisibleSessionRef.current = true;
      void getAvailablePurchases({ includeSuspendedAndroid: true })
        .catch((restoreError: unknown) => handleIapError({ message: errorMessage(restoreError) }));
    }
  }, [connected, fetchSubscriptionProducts, getAvailablePurchases, handleIapError, visible]);

  useEffect(() => {
    for (const purchase of availablePurchases) {
      if (purchase.productId === PLAY_SUBSCRIPTION_PRODUCT_ID && purchase.store === "google") void processPurchase(purchase);
    }
  }, [availablePurchases, processPurchase]);

  async function startPurchase() {
    if (Platform.OS !== "android" || nativeUnavailable) return;
    if (!connected) {
      setError("");
      const reconnected = await reconnect();
      if (!reconnected) {
        setError("Google Play'e bağlanılamadı. İnternet bağlantınızı ve Play Store oturumunuzu kontrol edin.");
        return;
      }
    }
    if (!basePlanOffer?.offerToken) {
      setError("Aylık abonelik şu anda Google Play'de kullanılamıyor. Lütfen biraz sonra yeniden deneyin.");
      return;
    }

    setScreenState("launching");
    setError("");
    setStoreMessage("Google Play ödeme ekranı açılıyor…");
    try {
      const [obfuscatedAccountId, obfuscatedProfileId] = await Promise.all([
        billingOpaqueId(userId),
        billingOpaqueId(organizationId),
      ]);
      await requestPurchase({
        type: "subs",
        request: {
          google: {
            skus: [PLAY_SUBSCRIPTION_PRODUCT_ID],
            subscriptionOffers: [{
              sku: PLAY_SUBSCRIPTION_PRODUCT_ID,
              offerToken: basePlanOffer.offerToken,
            }],
            obfuscatedAccountId,
            obfuscatedProfileId,
            isOfferPersonalized: false,
          },
        },
      });
    } catch (purchaseError) {
      handleIapError(iapErrorShape(purchaseError));
    }
  }

  async function restore() {
    if (nativeUnavailable || Platform.OS !== "android") return;
    recentlyProcessedPurchaseHashesRef.current.clear();
    setScreenState("restoring");
    setError("");
    setStoreMessage("Google Play satın alımları kontrol ediliyor…");
    try {
      await restorePurchases({ includeSuspendedAndroid: true });
      setScreenState("idle");
      setStoreMessage("Satın alma kayıtları kontrol edildi.");
    } catch (restoreError) {
      setScreenState("idle");
      setError(friendlyBillingError(errorMessage(restoreError)));
      setStoreMessage("");
    }
  }

  async function retrySubscriptionProducts() {
    if (nativeUnavailable || Platform.OS !== "android") return;
    if (connected) {
      await fetchSubscriptionProducts();
      return;
    }

    setProductLoading(true);
    setError("");
    try {
      const reconnected = await reconnect();
      if (!reconnected) {
        setError("Google Play'e bağlanılamadı. İnternet bağlantınızı ve Play Store oturumunuzu kontrol edip yeniden deneyin.");
        return;
      }
      await fetchSubscriptionProducts();
    } catch (connectionError) {
      setError(friendlyBillingError(errorMessage(connectionError)));
    } finally {
      setProductLoading(false);
    }
  }

  async function openPlaySubscriptionManagement() {
    const url = `https://play.google.com/store/account/subscriptions?sku=${encodeURIComponent(PLAY_SUBSCRIPTION_PRODUCT_ID)}&package=${encodeURIComponent(ANDROID_PACKAGE_NAME)}`;
    try {
      await Linking.openURL(url);
    } catch {
      setError("Google Play abonelik yönetimi açılamadı. Play Store'da Ödemeler ve abonelikler bölümünü açın.");
    }
  }

  const busy = screenState === "launching" || screenState === "verifying" || screenState === "restoring";
  const statusDetail = subscriptionStatusDetail(subscriptionLabel, trialEndsAt, currentPeriodEnd);
  const currentPeriodExpired = Boolean(currentPeriodEnd) && new Date(currentPeriodEnd ?? 0).getTime() <= Date.now();
  const canStartNewPurchase = subscriptionLabel === "Deneme"
    || subscriptionLabel === "İptal edildi"
    || (subscriptionLabel === "Aktif" && (!currentPeriodEnd || currentPeriodExpired));

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={busy ? () => undefined : onClose}>
      <View style={styles.backdrop}>
        <View style={styles.sheet}>
          <View style={styles.handle} />
          <View style={styles.header}>
            <View style={styles.headerText}>
              <Text style={styles.eyebrow}>GOOGLE PLAY ABONELİĞİ</Text>
              <Text style={styles.title}>Stokdaş Pro</Text>
            </View>
            <Pressable
              style={[styles.closeButton, busy && styles.disabled]}
              onPress={onClose}
              disabled={busy}
              accessibilityRole="button"
              accessibilityLabel="Abonelik ekranını kapat"
            >
              <Text style={styles.closeText}>×</Text>
            </Pressable>
          </View>

          <ScrollView showsVerticalScrollIndicator={false} contentContainerStyle={styles.content}>
            <View style={styles.statusCard}>
              <Text style={styles.statusLabel}>MEVCUT DURUM</Text>
              <Text style={styles.statusValue}>{subscriptionLabel}</Text>
              <Text style={styles.statusDetail}>{statusDetail}</Text>
            </View>

            <View style={styles.planCard}>
              <View style={styles.planTop}>
                <View style={styles.planNameBox}>
                  <Text style={styles.planName}>Aylık abonelik</Text>
                  <Text style={styles.planCaption}>İşletme çalışma alanı için</Text>
                </View>
                {localizedPrice ? (
                  <View style={styles.priceBox}>
                    <Text style={styles.price}>{localizedPrice}</Text>
                    <Text style={styles.pricePeriod}>/ ay</Text>
                  </View>
                ) : productLoading ? <ActivityIndicator color="#1f7353" /> : <Text style={styles.priceUnavailable}>Fiyat alınamadı</Text>}
              </View>
              <PlanFeature>Stok ve ekip değişikliklerine kesintisiz erişim</PlanFeature>
              <PlanFeature>Bulut senkronizasyonu ve işlem geçmişi</PlanFeature>
              <PlanFeature>Google Play üzerinden güvenli ödeme ve iptal</PlanFeature>
            </View>

            <View style={styles.notice}>
              <Text style={styles.noticeTitle}>Yenileme bilgisi</Text>
              <Text style={styles.noticeText}>
                Abonelik her ay otomatik yenilenir ve ücret Google Play hesabınızdan alınır. Dilediğiniz zaman Google Play'deki Abonelikler bölümünden iptal edebilirsiniz. Stokdaş yeni işletmelere 14 günlük uygulama içi deneme sunar; Google Play'de ayrıca ücretsiz deneme yoktur. Deneme sürerken abone olursanız ücret hemen alınır ve uygulama içi deneme ücretli aboneliğe dönüşür.
              </Text>
            </View>

            {storeMessage ? (
              <View
                style={[styles.messageBox, screenState === "success" ? styles.successBox : styles.infoBox]}
                accessibilityLiveRegion="polite"
              >
                <Text style={screenState === "success" ? styles.successText : styles.infoText}>{storeMessage}</Text>
              </View>
            ) : null}
            {error ? (
              <View style={styles.errorBox} accessibilityLiveRegion="assertive">
                <Text style={styles.errorText}>{error}</Text>
              </View>
            ) : null}

            {canStartNewPurchase ? <Pressable
              style={[styles.primaryButton, (busy || nativeUnavailable || productLoading || !basePlanOffer?.offerToken) && styles.disabled]}
              onPress={() => void startPurchase()}
              disabled={busy || nativeUnavailable || productLoading || !basePlanOffer?.offerToken}
              accessibilityRole="button"
              accessibilityLabel={localizedPrice ? `${localizedPrice} aylık Stokdaş Pro aboneliğini Google Play'den başlat` : "Stokdaş Pro aboneliğini Google Play'den başlat"}
            >
              {screenState === "launching" || screenState === "verifying"
                ? <ActivityIndicator color="#172820" />
                : <Text style={styles.primaryButtonText}>{localizedPrice ? `${localizedPrice} / ay ile abone ol` : "Google Play fiyatı yükleniyor"}</Text>}
            </Pressable> : null}
            {!basePlanOffer?.offerToken && !nativeUnavailable ? <Pressable
              style={[styles.retryProductsButton, (busy || productLoading) && styles.disabled]}
              onPress={() => void retrySubscriptionProducts()}
              disabled={busy || productLoading}
              accessibilityRole="button"
              accessibilityLabel="Google Play abonelik fiyatını yeniden yükle"
            >
              {productLoading
                ? <ActivityIndicator color="#356b54" />
                : <Text style={styles.retryProductsButtonText}>Google Play fiyatını yeniden dene</Text>}
            </Pressable> : null}
            <Pressable
              style={[styles.restoreButton, (busy || nativeUnavailable) && styles.disabled]}
              onPress={() => void restore()}
              disabled={busy || nativeUnavailable}
              accessibilityRole="button"
              accessibilityLabel="Google Play satın alımlarını geri yükle"
            >
              {screenState === "restoring"
                ? <ActivityIndicator color="#356b54" />
                : <Text style={styles.restoreButtonText}>Satın alımları geri yükle</Text>}
            </Pressable>
            {["Aktif", "Ödeme bekliyor", "Askıda"].includes(subscriptionLabel) ? <Pressable
              style={styles.manageButton}
              onPress={() => void openPlaySubscriptionManagement()}
              accessibilityRole="link"
              accessibilityLabel="Google Play'de aboneliği yönet"
            >
              <Text style={styles.manageButtonText}>Google Play'de aboneliği yönet</Text>
            </Pressable> : null}
            <Text style={styles.footerText}>Kart ve ödeme yöntemi ayrıntıları Stokdaş tarafından görülmez veya saklanmaz; ödeme Google Play tarafından yürütülür.</Text>
          </ScrollView>
        </View>
      </View>
    </Modal>
  );
}

function findMonthlyBasePlan(product: ProductSubscription | undefined) {
  if (!product || product.platform !== "android") return null;
  return product.subscriptionOfferDetailsAndroid.find((offer) => (
    offer.basePlanId === PLAY_SUBSCRIPTION_BASE_PLAN_ID && !offer.offerId && Boolean(offer.offerToken)
  )) ?? null;
}

function PlanFeature({ children }: { children: string }) {
  return <View style={styles.featureRow}><Text style={styles.featureIcon}>✓</Text><Text style={styles.featureText}>{children}</Text></View>;
}

function subscriptionStatusDetail(label: string, trialEndsAt: string | null, currentPeriodEnd: string | null) {
  if (label === "Deneme" && trialEndsAt) return `Uygulama içi deneme ${formatDate(trialEndsAt)} tarihinde sona erer.`;
  if (label === "Aktif" && currentPeriodEnd) return `Mevcut dönem ${formatDate(currentPeriodEnd)} tarihine kadar geçerli.`;
  if (label === "Aktif") return "İşletme erişimi etkin.";
  return "Abonelik yenilendiğinde yazma işlemleri yeniden açılır.";
}

function formatDate(value: string) {
  return new Date(value).toLocaleDateString("tr-TR", { day: "numeric", month: "long", year: "numeric" });
}

function errorMessage(value: unknown) {
  return value instanceof Error ? value.message : "Google Play işlemi tamamlanamadı.";
}

function iapErrorShape(value: unknown) {
  const candidate = value as { code?: unknown; message?: unknown };
  return {
    code: typeof candidate?.code === "string" ? candidate.code : undefined,
    message: typeof candidate?.message === "string" ? candidate.message : errorMessage(value),
  };
}

async function edgeFunctionMessage(error: unknown) {
  const candidate = error as { context?: Response; message?: string };
  try {
    const body = await candidate.context?.json() as { error?: string } | undefined;
    if (body?.error) return body.error;
  } catch { /* Güvenli istemci mesajına dönülür. */ }
  return candidate.message ?? "Satın alma sunucuda doğrulanamadı.";
}

function friendlyBillingError(message: string) {
  if (/network|internet|timeout|timed out/i.test(message)) return "Bağlantı kurulamadı. İnternet bağlantınızı kontrol edip yeniden deneyin.";
  if (/already.*owned|zaten.*sahip/i.test(message)) return "Bu abonelik Google Play hesabınızda zaten var. Satın alımları geri yükleyin.";
  if (/not found|unavailable|bulunamadı|kullanılamıyor/i.test(message)) return "Aylık abonelik şu anda Google Play'de kullanılamıyor.";
  return message || "Google Play işlemi tamamlanamadı.";
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, justifyContent: "flex-end", backgroundColor: "#0c1813a8" },
  sheet: { maxHeight: "94%", minHeight: 520, padding: 20, paddingTop: 10, borderTopLeftRadius: 24, borderTopRightRadius: 24, backgroundColor: "#f8f8f5" },
  unavailableSheet: { padding: 20, paddingTop: 12, paddingBottom: 28, borderTopLeftRadius: 24, borderTopRightRadius: 24, backgroundColor: "#f8f8f5" },
  unavailableText: { marginTop: 12, color: "#66716b", fontSize: 11, lineHeight: 18 },
  handle: { width: 40, height: 4, alignSelf: "center", marginBottom: 15, borderRadius: 2, backgroundColor: "#cbd0cc" },
  header: { marginBottom: 17, flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  headerText: { flex: 1 },
  eyebrow: { color: "#718078", fontSize: 8, fontWeight: "900", letterSpacing: 1.1 },
  title: { marginTop: 3, color: "#1b2721", fontSize: 22, fontWeight: "900" },
  closeButton: { width: 36, height: 36, alignItems: "center", justifyContent: "center", borderRadius: 10, backgroundColor: "#e9ece8" },
  closeText: { color: "#5c6861", fontSize: 22 },
  content: { paddingBottom: 20 },
  statusCard: { padding: 14, borderWidth: 1, borderColor: "#dce6df", borderRadius: 13, backgroundColor: "#edf5f0" },
  statusLabel: { color: "#5b7568", fontSize: 8, fontWeight: "900", letterSpacing: .8 },
  statusValue: { marginTop: 5, color: "#236647", fontSize: 17, fontWeight: "900" },
  statusDetail: { marginTop: 4, color: "#617269", fontSize: 9, lineHeight: 14 },
  planCard: { marginTop: 12, padding: 16, borderWidth: 1, borderColor: "#e0e4df", borderRadius: 15, backgroundColor: "#fff" },
  planTop: { minHeight: 50, marginBottom: 13, flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  planNameBox: { flex: 1, paddingRight: 8 },
  planName: { color: "#1e2a24", fontSize: 16, fontWeight: "900" },
  planCaption: { marginTop: 3, color: "#88918c", fontSize: 9 },
  priceBox: { alignItems: "flex-end" },
  price: { color: "#1f7353", fontSize: 19, fontWeight: "900" },
  pricePeriod: { marginTop: 1, color: "#7e8983", fontSize: 9, fontWeight: "700" },
  priceUnavailable: { color: "#8d6653", fontSize: 9, fontWeight: "800" },
  featureRow: { minHeight: 31, flexDirection: "row", alignItems: "center" },
  featureIcon: { width: 22, color: "#2d7b59", fontSize: 13, fontWeight: "900" },
  featureText: { flex: 1, color: "#59655f", fontSize: 10, lineHeight: 15 },
  notice: { marginTop: 12, padding: 13, borderWidth: 1, borderColor: "#f0d8b4", borderRadius: 12, backgroundColor: "#fff5e5" },
  noticeTitle: { color: "#8b5b1c", fontSize: 10, fontWeight: "900" },
  noticeText: { marginTop: 5, color: "#8b6b40", fontSize: 9, lineHeight: 15 },
  messageBox: { marginTop: 12, padding: 12, borderRadius: 11 },
  infoBox: { backgroundColor: "#eaf0f5" },
  successBox: { backgroundColor: "#e3f2e9" },
  infoText: { color: "#4f687b", fontSize: 10, lineHeight: 15 },
  successText: { color: "#276b4c", fontSize: 10, fontWeight: "800", lineHeight: 15 },
  errorBox: { marginTop: 12, padding: 12, borderRadius: 11, backgroundColor: "#fae9e5" },
  errorText: { color: "#92483f", fontSize: 10, lineHeight: 15 },
  primaryButton: { minHeight: 50, marginTop: 15, paddingHorizontal: 14, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#f3a952" },
  primaryButtonText: { color: "#172820", fontSize: 12, fontWeight: "900" },
  retryProductsButton: { minHeight: 42, marginTop: 8, alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "#cbd9d1", borderRadius: 11, backgroundColor: "#f4f8f5" },
  retryProductsButtonText: { color: "#356b54", fontSize: 9, fontWeight: "900" },
  restoreButton: { minHeight: 46, marginTop: 9, alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "#cbd9d1", borderRadius: 11, backgroundColor: "#f4f8f5" },
  restoreButtonText: { color: "#356b54", fontSize: 10, fontWeight: "900" },
  manageButton: { minHeight: 40, marginTop: 6, alignItems: "center", justifyContent: "center" },
  manageButtonText: { color: "#356b54", fontSize: 9, fontWeight: "800", textDecorationLine: "underline" },
  footerText: { marginTop: 12, paddingHorizontal: 5, color: "#929a95", textAlign: "center", fontSize: 8, lineHeight: 13 },
  disabled: { opacity: .45 },
});
