import { useEffect, useRef, useState } from "react";
import { randomUUID } from "expo-crypto";
import {
  ActivityIndicator, Alert, KeyboardAvoidingView, Modal, Platform, Pressable,
  ScrollView, StyleSheet, Text, TextInput, View,
} from "react-native";
import { supabase } from "../lib/supabase";
import { isTransientSupabaseError, retryTransientSupabaseOperation } from "../lib/auth-retry";

type Business = {
  id: string;
  name: string;
  slug: string;
  subscription_status: "trial" | "active" | "past_due" | "suspended" | "canceled";
  trial_ends_at: string | null;
  current_period_end: string | null;
  max_members: number;
  max_products: number;
  member_count: number;
  product_count: number;
  platform_entitlement_until: string | null;
  platform_entitlement_reason: string | null;
  subscription_revision: number;
};

type BusinessCursor = { beforeCreatedAt: string; beforeId: string };
type PendingSubscriptionChange = { business: Business; status: "active" | "suspended" };

type Props = { visible: boolean; onClose: () => void };

export default function PlatformModal({ visible, onClose }: Props) {
  const [businesses, setBusinesses] = useState<Business[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);
  const [savingCommand, setSavingCommand] = useState(false);
  const [nextCursor, setNextCursor] = useState<BusinessCursor | null>(null);
  const [pendingChange, setPendingChange] = useState<PendingSubscriptionChange | null>(null);
  const [reason, setReason] = useState("");
  const listRequestSequence = useRef(0);
  const commandRequestSequence = useRef(0);
  const commandInFlightRef = useRef(false);
  const unresolvedCommandKeyRef = useRef<string | null>(null);
  const mountedRef = useRef(true);
  const pendingCommandIds = useRef(new Map<string, string>());

  useEffect(() => {
    if (!visible) {
      listRequestSequence.current += 1;
      commandRequestSequence.current += 1;
      commandInFlightRef.current = false;
      unresolvedCommandKeyRef.current = null;
      setLoading(false);
      setLoadingMore(false);
      setSavingCommand(false);
      setPendingChange(null);
      setReason("");
      return;
    }
    void loadBusinesses(false);
  }, [visible]);

  useEffect(() => () => {
    mountedRef.current = false;
    listRequestSequence.current += 1;
    commandRequestSequence.current += 1;
    commandInFlightRef.current = false;
  }, []);

  async function loadBusinesses(append: boolean) {
    if (append && !nextCursor) return;
    const requestSequence = ++listRequestSequence.current;
    if (append) setLoadingMore(true);
    else {
      setLoading(true);
      setLoadingMore(false);
      setNextCursor(null);
    }
    const cursor = append ? nextCursor : null;
    const { data, error } = await retryTransientSupabaseOperation(() =>
      supabase.functions.invoke("manage-businesses", {
        body: {
          action: "list",
          limit: 100,
          beforeCreatedAt: cursor?.beforeCreatedAt,
          beforeId: cursor?.beforeId,
        },
      })
    );
    if (!mountedRef.current || requestSequence !== listRequestSequence.current) return;
    if (error) {
      const message = await edgeFunctionError(error);
      if (!mountedRef.current || requestSequence !== listRequestSequence.current) return;
      if (append) setLoadingMore(false);
      else setLoading(false);
      Alert.alert("İşletmeler alınamadı", message);
      return;
    }
    if (append) setLoadingMore(false);
    else setLoading(false);
    const incoming = (data?.organizations ?? []) as Business[];
    setBusinesses((current) => append
      ? [...new Map([...current, ...incoming].map((item) => [item.id, item])).values()]
      : incoming);
    setNextCursor((data?.nextCursor ?? null) as BusinessCursor | null);
  }

  function updateSubscription(business: Business, status: "active" | "suspended") {
    setReason("");
    setPendingChange({ business, status });
  }

  async function saveSubscription(business: Business, status: "active" | "suspended", rawReason: string) {
    if (commandInFlightRef.current) return;
    const normalizedReason = rawReason.trim();
    if (!normalizedReason || normalizedReason.length > 500) {
      Alert.alert("Gerekçe gerekli", "İşlem gerekçesi 1-500 karakter arasında olmalıdır.");
      return;
    }
    const commandKey = JSON.stringify({
      organizationId: business.id,
      expectedRevision: business.subscription_revision,
      status,
      periodDays: 30,
      maxMembers: business.max_members,
      maxProducts: business.max_products,
      reason: normalizedReason,
    });
    const requestId = pendingCommandIds.current.get(commandKey) ?? randomUUID();
    if (unresolvedCommandKeyRef.current && unresolvedCommandKeyRef.current !== commandKey) {
      Alert.alert(
        "Önceki işlem bekliyor",
        "Önceki abonelik kararının sonucu doğrulanmadı. Çifte işlem oluşmaması için aynı işletme, durum ve gerekçeyle tekrar deneyin.",
      );
      return;
    }
    pendingCommandIds.current.set(commandKey, requestId);
    const requestSequence = ++commandRequestSequence.current;
    commandInFlightRef.current = true;
    setSavingCommand(true);

    const { data, error } = await retryTransientSupabaseOperation(() =>
      supabase.functions.invoke("manage-businesses", {
        body: {
          action: "update_subscription",
          requestId,
          expectedRevision: business.subscription_revision,
          organizationId: business.id,
          status,
          periodDays: 30,
          maxMembers: business.max_members,
          maxProducts: business.max_products,
          reason: normalizedReason,
        },
      })
    );
    if (!mountedRef.current || requestSequence !== commandRequestSequence.current) return;
    if (error) {
      const message = await edgeFunctionError(error);
      if (!mountedRef.current || requestSequence !== commandRequestSequence.current) return;
      commandInFlightRef.current = false;
      setSavingCommand(false);
      if (isAmbiguousCommandError(error)) unresolvedCommandKeyRef.current = commandKey;
      else {
        unresolvedCommandKeyRef.current = null;
        pendingCommandIds.current.delete(commandKey);
      }
      Alert.alert("Durum güncellenemedi", message);
      await loadBusinesses(false);
      return;
    }
    commandInFlightRef.current = false;
    setSavingCommand(false);
    const response = data && typeof data === "object"
      ? data as Record<string, unknown>
      : null;
    const updatedBusiness = response?.organization && typeof response.organization === "object"
      ? response.organization as Partial<Business>
      : null;
    if (!response || response.request_id !== requestId
      || updatedBusiness?.id !== business.id
      || updatedBusiness.subscription_status !== status
      || updatedBusiness.subscription_revision !== business.subscription_revision + 1) {
      Alert.alert(
        "Durum doğrulanamadı",
        "Sunucu işlem kimliğini doğrulamadı. Güncel işletme durumu yeniden yüklenecek.",
      );
      unresolvedCommandKeyRef.current = commandKey;
      await loadBusinesses(false);
      return;
    }
    unresolvedCommandKeyRef.current = null;
    pendingCommandIds.current.delete(commandKey);
    setPendingChange(null);
    setReason("");
    await loadBusinesses(false);
  }

  function closePlatformModal() {
    if (savingCommand || unresolvedCommandKeyRef.current) {
      Alert.alert(
        "İşlem sonucu bekleniyor",
        "Abonelik kararı doğrulanana kadar aynı bilgilerle yeniden deneyin.",
      );
      return;
    }
    onClose();
  }

  function cancelReasonModal() {
    if (savingCommand || unresolvedCommandKeyRef.current) {
      Alert.alert(
        "İşlem sonucu bekleniyor",
        "Önceki kararın sonucu doğrulanana kadar aynı gerekçeyle yeniden deneyin.",
      );
      return;
    }
    setPendingChange(null);
  }

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={closePlatformModal}>
      <KeyboardAvoidingView style={styles.backdrop} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <View style={styles.sheet}>
          <View style={styles.handle} />
          <View style={styles.header}>
            <View style={styles.headerButtonPlaceholder} />
            <Text style={styles.title}>Kiralık işletmeler</Text>
            <Pressable style={styles.headerButton} onPress={closePlatformModal} disabled={loading || savingCommand}><Text style={styles.closeText}>×</Text></Pressable>
          </View>

          <ScrollView showsVerticalScrollIndicator={false}>
            <View style={styles.summaryRow}>
              <View><Text style={styles.summaryLabel}>YÜKLENEN İŞLETME</Text><Text style={styles.summaryValue}>{businesses.length}</Text></View>
              <View style={styles.selfServiceNote}><Text style={styles.selfServiceText}>Yeni işletmeler kayıt ekranından açılır</Text></View>
            </View>
            {loading && !businesses.length ? <ActivityIndicator style={styles.loader} color="#1f7353" /> : null}
            {businesses.map((business) => (
              <View style={styles.businessCard} key={business.id}>
                <View style={styles.businessTop}>
                  <View style={styles.businessText}><Text style={styles.businessName}>{business.name}</Text><Text style={styles.businessSlug}>{business.slug}</Text></View>
                  <View style={[styles.statusBadge, statusTone(business.subscription_status)]}><Text style={styles.statusText}>{statusLabel(business.subscription_status)}</Text></View>
                </View>
                <Text style={styles.usage}>{business.member_count}/{business.max_members} kullanıcı · {business.product_count}/{business.max_products} ürün</Text>
                <Text style={styles.period}>{periodLabel(business)}</Text>
                <View style={styles.actions}>
                  <Pressable style={styles.activateButton} onPress={() => updateSubscription(business, "active")} disabled={loading || savingCommand}><Text style={styles.activateText}>30 gün etkinleştir</Text></Pressable>
                  <Pressable style={styles.suspendButton} onPress={() => updateSubscription(business, "suspended")} disabled={loading || savingCommand}><Text style={styles.suspendText}>Askıya al</Text></Pressable>
                </View>
              </View>
            ))}
            {nextCursor ? (
              <Pressable
                style={styles.loadMoreButton}
                onPress={() => void loadBusinesses(true)}
                disabled={loading || loadingMore || savingCommand}
              >
                {loadingMore
                  ? <ActivityIndicator color="#2d7053" />
                  : <Text style={styles.loadMoreText}>Daha fazla işletme yükle</Text>}
              </Pressable>
            ) : null}
            <View style={styles.bottomSpace} />
          </ScrollView>
          <Modal
            visible={Boolean(pendingChange)}
            transparent
            animationType="fade"
            onRequestClose={cancelReasonModal}
          >
            <KeyboardAvoidingView style={styles.reasonBackdrop} behavior={Platform.OS === "ios" ? "padding" : undefined}>
              <View style={styles.reasonCard}>
                <Text style={styles.reasonTitle}>{pendingChange?.status === "active" ? "İşletmeyi 30 gün etkinleştir" : "İşletmeyi askıya al"}</Text>
                <Text style={styles.reasonBody}>
                  {pendingChange
                    ? `${pendingChange.business.name} için bu idari kararın açık gerekçesini yazın. Gerekçe güvenlik denetim kaydında tutulur.`
                    : ""}
                </Text>
                <Text style={styles.reasonLabel}>İşlem gerekçesi</Text>
                <TextInput
                  value={reason}
                  onChangeText={setReason}
                  style={styles.reasonInput}
                  placeholder={pendingChange?.status === "active" ? "Örn. Ödeme teyidi sonrası erişim uzatıldı" : "Örn. Doğrulanmış güvenlik ihlali nedeniyle askıya alındı"}
                  placeholderTextColor="#929994"
                  multiline
                  maxLength={500}
                  editable={!savingCommand}
                  autoFocus
                />
                <Text style={styles.reasonCount}>{reason.length}/500</Text>
                <View style={styles.reasonActions}>
                  <Pressable style={[styles.reasonCancel, (savingCommand || Boolean(unresolvedCommandKeyRef.current)) && styles.disabled]} onPress={cancelReasonModal} disabled={savingCommand || Boolean(unresolvedCommandKeyRef.current)} accessibilityRole="button">
                    <Text style={styles.reasonCancelText}>Vazgeç</Text>
                  </Pressable>
                  <Pressable
                    style={[pendingChange?.status === "suspended" ? styles.reasonSuspend : styles.reasonConfirm, (!reason.trim() || savingCommand) && styles.disabled]}
                    onPress={() => pendingChange && void saveSubscription(pendingChange.business, pendingChange.status, reason)}
                    disabled={!reason.trim() || savingCommand}
                    accessibilityRole="button"
                  >
                    {savingCommand
                      ? <ActivityIndicator color="#fff" />
                      : <Text style={styles.reasonConfirmText}>{pendingChange?.status === "active" ? "Etkinleştir" : "Askıya al"}</Text>}
                  </Pressable>
                </View>
              </View>
            </KeyboardAvoidingView>
          </Modal>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function statusLabel(status: Business["subscription_status"]) {
  return { trial: "DENEME", active: "AKTİF", past_due: "ÖDEME BEKLİYOR", suspended: "ASKIDA", canceled: "İPTAL" }[status];
}

function statusTone(status: Business["subscription_status"]) {
  return status === "active" ? styles.statusActive : status === "trial" ? styles.statusTrial : styles.statusBlocked;
}

function periodLabel(business: Business) {
  const value = business.subscription_status === "trial" ? business.trial_ends_at : business.current_period_end;
  if (!value) return "Bitiş tarihi tanımlı değil";
  return `${business.subscription_status === "trial" ? "Deneme" : "Dönem"} bitişi: ${new Date(value).toLocaleDateString("tr-TR")}`;
}

function isAmbiguousCommandError(error: unknown) {
  const status = (error as { context?: { status?: number }; status?: number })?.context?.status
    ?? (error as { status?: number })?.status;
  return isTransientSupabaseError(error, status);
}

async function edgeFunctionError(error: unknown) {
  const candidate = error as { context?: Response; message?: string };
  try {
    const body = await candidate.context?.json() as { error?: string } | undefined;
    if (body?.error) return body.error;
  } catch { /* İstemci mesajına dönülür. */ }
  return candidate.message ?? "İşlem tamamlanamadı.";
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, justifyContent: "flex-end", backgroundColor: "#0c1813a8" },
  sheet: { maxHeight: "94%", minHeight: "75%", padding: 20, paddingTop: 10, borderTopLeftRadius: 24, borderTopRightRadius: 24, backgroundColor: "#f8f8f5" },
  handle: { width: 40, height: 4, alignSelf: "center", marginBottom: 13, borderRadius: 2, backgroundColor: "#cbd0cc" },
  header: { height: 38, marginBottom: 16, flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  headerButton: { width: 36, height: 36, alignItems: "center", justifyContent: "center", borderRadius: 10, backgroundColor: "#e9ece8" },
  headerButtonPlaceholder: { width: 36, height: 36 }, closeText: { color: "#5c6861", fontSize: 22 },
  title: { color: "#1b2721", fontSize: 19, fontWeight: "800" },
  summaryRow: { marginBottom: 13, padding: 14, flexDirection: "row", alignItems: "center", justifyContent: "space-between", borderRadius: 14, backgroundColor: "#172820" },
  summaryLabel: { color: "#8ea499", fontSize: 8, fontWeight: "900", letterSpacing: .8 }, summaryValue: { marginTop: 4, color: "#fff", fontSize: 24, fontWeight: "900" },
  selfServiceNote: { maxWidth: 150, paddingHorizontal: 11, paddingVertical: 9, borderRadius: 10, backgroundColor: "#2b4438" }, selfServiceText: { color: "#cfddd6", textAlign: "center", fontSize: 8, lineHeight: 12, fontWeight: "800" },
  loader: { marginVertical: 30 },
  businessCard: { marginBottom: 11, padding: 14, borderWidth: 1, borderColor: "#e0e5e0", borderRadius: 14, backgroundColor: "#fff" },
  businessTop: { flexDirection: "row", alignItems: "flex-start" }, businessText: { flex: 1 }, businessName: { color: "#1b2721", fontSize: 13, fontWeight: "900" }, businessSlug: { marginTop: 3, color: "#929994", fontSize: 9 },
  statusBadge: { paddingHorizontal: 8, paddingVertical: 5, borderRadius: 20 }, statusActive: { backgroundColor: "#e4f2ea" }, statusTrial: { backgroundColor: "#fff0d8" }, statusBlocked: { backgroundColor: "#f7e4e0" }, statusText: { color: "#3e6453", fontSize: 7, fontWeight: "900" },
  usage: { marginTop: 12, color: "#59645e", fontSize: 10, fontWeight: "700" }, period: { marginTop: 4, color: "#8b938e", fontSize: 8 },
  actions: { marginTop: 12, flexDirection: "row", gap: 8 }, activateButton: { flex: 1, paddingVertical: 9, alignItems: "center", borderRadius: 9, backgroundColor: "#e3f1e9" }, activateText: { color: "#2d7053", fontSize: 9, fontWeight: "900" }, suspendButton: { flex: 1, paddingVertical: 9, alignItems: "center", borderRadius: 9, backgroundColor: "#f5e5e1" }, suspendText: { color: "#a64d43", fontSize: 9, fontWeight: "900" },
  loadMoreButton: { minHeight: 42, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#e3f1e9" },
  loadMoreText: { color: "#2d7053", fontSize: 10, fontWeight: "900" },
  reasonBackdrop: { flex: 1, justifyContent: "center", padding: 20, backgroundColor: "#0c1813b8" },
  reasonCard: { padding: 18, borderRadius: 17, backgroundColor: "#f8f8f5" },
  reasonTitle: { color: "#1d2a24", fontSize: 18, fontWeight: "900" },
  reasonBody: { marginTop: 7, color: "#69736d", fontSize: 10, lineHeight: 16 },
  reasonLabel: { marginTop: 16, marginBottom: 7, color: "#56635c", fontSize: 10, fontWeight: "900" },
  reasonInput: { minHeight: 104, padding: 12, borderWidth: 1, borderColor: "#d9dfda", borderRadius: 11, backgroundColor: "#fff", color: "#1d2a24", fontSize: 12, lineHeight: 18, textAlignVertical: "top" },
  reasonCount: { marginTop: 5, color: "#8b948f", textAlign: "right", fontSize: 8 },
  reasonActions: { marginTop: 13, flexDirection: "row", gap: 9 },
  reasonCancel: { flex: 1, minHeight: 45, alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "#d8ded9", borderRadius: 10, backgroundColor: "#fff" },
  reasonCancelText: { color: "#5e6a63", fontSize: 10, fontWeight: "900" },
  reasonConfirm: { flex: 1, minHeight: 45, alignItems: "center", justifyContent: "center", borderRadius: 10, backgroundColor: "#2d7053" },
  reasonSuspend: { flex: 1, minHeight: 45, alignItems: "center", justifyContent: "center", borderRadius: 10, backgroundColor: "#a64d43" },
  reasonConfirmText: { color: "#fff", fontSize: 10, fontWeight: "900" },
  disabled: { opacity: .5 },
  bottomSpace: { height: 22 },
});
