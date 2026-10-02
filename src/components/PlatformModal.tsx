import { useEffect, useState } from "react";
import {
  ActivityIndicator, Alert, KeyboardAvoidingView, Modal, Platform, Pressable,
  ScrollView, StyleSheet, Text, View,
} from "react-native";
import { supabase } from "../lib/supabase";

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
};

type Props = { visible: boolean; onClose: () => void };
type DeletionRequest = {
  id: string; status: "requested" | "under_review"; scope: "account" | "organization";
  requestedAt: string; paymentStatus: "pending" | "reviewed";
  username: string | null; organizationName: string | null;
};

export default function PlatformModal({ visible, onClose }: Props) {
  const [businesses, setBusinesses] = useState<Business[]>([]);
  const [loading, setLoading] = useState(false);
  const [deletionRequests, setDeletionRequests] = useState<DeletionRequest[]>([]);
  const [reviewingId, setReviewingId] = useState<string | null>(null);
  const [deletionQueueError, setDeletionQueueError] = useState(false);

  useEffect(() => {
    if (!visible) return;
    void loadBusinesses();
    void loadDeletionRequests();
  }, [visible]);

  async function loadDeletionRequests() {
    const { data, error } = await supabase.rpc("platform_list_account_deletion_requests");
    setDeletionQueueError(Boolean(error));
    setDeletionRequests(error ? [] : data as DeletionRequest[]);
  }

  async function reviewDeletionRequest(requestId: string) {
    setReviewingId(requestId);
    const { error } = await supabase.rpc("platform_review_account_deletion_request", { p_request_id: requestId });
    setReviewingId(null);
    if (error) {
      Alert.alert("Talep güncellenemedi", error.message);
      return;
    }
    await loadDeletionRequests();
  }

  async function loadBusinesses() {
    setLoading(true);
    const { data, error } = await supabase.functions.invoke("manage-businesses", { method: "GET" });
    setLoading(false);
    if (error) {
      Alert.alert("İşletmeler alınamadı", await edgeFunctionError(error));
      return;
    }
    setBusinesses((data?.organizations ?? []) as Business[]);
  }

  function updateSubscription(business: Business, status: "active" | "suspended") {
    const label = status === "active" ? "30 gün etkinleştir" : "askıya al";
    Alert.alert("Kiralama durumunu değiştir", `${business.name} işletmesini ${label}?`, [
      { text: "Vazgeç", style: "cancel" },
      { text: status === "active" ? "Etkinleştir" : "Askıya al", style: status === "active" ? "default" : "destructive", onPress: () => void saveSubscription(business, status) },
    ]);
  }

  async function saveSubscription(business: Business, status: "active" | "suspended") {
    setLoading(true);
    const { error } = await supabase.functions.invoke("manage-businesses", {
      body: {
        action: "update_subscription", organizationId: business.id, status,
        periodDays: 30, maxMembers: business.max_members, maxProducts: business.max_products,
      },
    });
    setLoading(false);
    if (error) {
      Alert.alert("Durum güncellenemedi", await edgeFunctionError(error));
      return;
    }
    await loadBusinesses();
  }

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <KeyboardAvoidingView style={styles.backdrop} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <View style={styles.sheet}>
          <View style={styles.handle} />
          <View style={styles.header}>
            <View style={styles.headerButtonPlaceholder} />
            <Text style={styles.title}>Kiralık işletmeler</Text>
            <Pressable style={styles.headerButton} onPress={onClose} disabled={loading}><Text style={styles.closeText}>×</Text></Pressable>
          </View>

          <ScrollView showsVerticalScrollIndicator={false}>
            <View style={styles.businessCard}>
              <Text style={styles.businessName}>Hesap silme talepleri</Text>
              <Text style={styles.period}>Ödeme kayıtları korunur. İncelemeye alma hesabı silmez. Nihai silme ve saklama kararı destek üzerinden ayrıca tamamlanmalıdır.</Text>
              {deletionQueueError ? <Text style={styles.usage}>Talep kuyruğu alınamadı. TOTP oturumunu doğrulayarak yeniden açın.</Text>
                : !deletionRequests.length ? <Text style={styles.usage}>Bekleyen talep yok.</Text> : null}
              {deletionRequests.map((request) => <View key={request.id} style={styles.businessCard}>
                <Text style={styles.businessName}>{request.organizationName ?? "İşletme"} · @{request.username ?? "kullanıcı"}</Text>
                <Text style={styles.usage}>{request.scope === "organization" ? "İşletme ve hesaplar" : "Çalışan hesabı"} · {request.status === "under_review" ? "İnceleniyor" : "Talep alındı"}</Text>
                <Text style={styles.period}>{new Date(request.requestedAt).toLocaleDateString("tr-TR")} · Ödeme kaydı: {request.paymentStatus === "pending" ? "Bekleyen" : "İncelenmiş"}</Text>
                <Text selectable style={styles.period}>Talep: {request.id}</Text>
                {request.status === "requested" ? <Pressable style={styles.activateButton}
                  disabled={Boolean(reviewingId)} onPress={() => void reviewDeletionRequest(request.id)}>
                  <Text style={styles.activateText}>{reviewingId === request.id ? "Güncelleniyor…" : "İncelemeye al"}</Text>
                </Pressable> : null}
              </View>)}
            </View>
            <View style={styles.summaryRow}>
              <View><Text style={styles.summaryLabel}>TOPLAM İŞLETME</Text><Text style={styles.summaryValue}>{businesses.length}</Text></View>
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
                  <Pressable style={styles.activateButton} onPress={() => updateSubscription(business, "active")} disabled={loading}><Text style={styles.activateText}>30 gün etkinleştir</Text></Pressable>
                  <Pressable style={styles.suspendButton} onPress={() => updateSubscription(business, "suspended")} disabled={loading}><Text style={styles.suspendText}>Askıya al</Text></Pressable>
                </View>
              </View>
            ))}
            <View style={styles.bottomSpace} />
          </ScrollView>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function statusLabel(status: Business["subscription_status"]) {
  return { trial: "DENEME", active: "AKTİF", past_due: "ERİŞİM KAPALI", suspended: "ASKIDA", canceled: "İPTAL" }[status];
}

function statusTone(status: Business["subscription_status"]) {
  return status === "active" ? styles.statusActive : status === "trial" ? styles.statusTrial : styles.statusBlocked;
}

function periodLabel(business: Business) {
  const value = business.subscription_status === "trial" ? business.trial_ends_at : business.current_period_end;
  if (!value) return "Bitiş tarihi tanımlı değil";
  return `${business.subscription_status === "trial" ? "Deneme" : "Dönem"} bitişi: ${new Date(value).toLocaleDateString("tr-TR")}`;
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
  bottomSpace: { height: 22 },
});
