import { useEffect, useState } from "react";
import {
  ActivityIndicator, Alert, KeyboardAvoidingView, Modal, Platform, Pressable,
  ScrollView, StyleSheet, Text, TextInput, View,
} from "react-native";
import { normalizeUsername, supabase } from "../lib/supabase";

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

export default function PlatformModal({ visible, onClose }: Props) {
  const [businesses, setBusinesses] = useState<Business[]>([]);
  const [page, setPage] = useState<"list" | "create">("list");
  const [loading, setLoading] = useState(false);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [adminName, setAdminName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [trialDays, setTrialDays] = useState("14");
  const [maxMembers, setMaxMembers] = useState("5");
  const [maxProducts, setMaxProducts] = useState("1000");

  useEffect(() => {
    if (!visible) return;
    setPage("list");
    void loadBusinesses();
  }, [visible]);

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

  function openCreate() {
    setName(""); setSlug(""); setAdminName(""); setUsername(""); setPassword("");
    setTrialDays("14"); setMaxMembers("5"); setMaxProducts("1000");
    setPage("create");
  }

  async function createBusiness() {
    const normalizedUsername = normalizeUsername(username);
    if (name.trim().length < 2 || !/^[a-z0-9][a-z0-9-]{2,47}$/.test(slug.trim().toLowerCase())) {
      Alert.alert("Eksik bilgi", "İşletme adı ve yalnızca küçük harf/rakam/tire içeren işletme kodunu kontrol edin.");
      return;
    }
    if (!adminName.trim() || normalizedUsername.length < 3 || !isStrongPassword(password)) {
      Alert.alert("Eksik yönetici bilgisi", "Yönetici adı, kullanıcı adı ve büyük/küçük harf, rakam, sembol içeren en az 8 karakterli şifre gereklidir.");
      return;
    }

    setLoading(true);
    const { error } = await supabase.functions.invoke("manage-businesses", {
      body: {
        action: "create",
        name: name.trim(), slug: slug.trim().toLowerCase(),
        displayName: adminName.trim(), username: normalizedUsername, password,
        trialDays: Number(trialDays), maxMembers: Number(maxMembers), maxProducts: Number(maxProducts),
      },
    });
    setLoading(false);
    if (error) {
      Alert.alert("İşletme oluşturulamadı", await edgeFunctionError(error));
      return;
    }

    Alert.alert("Kiralık işletme hazır", `${name.trim()} oluşturuldu.\n\nYönetici kullanıcı adı: ${normalizedUsername}\nŞifreyi işletme yöneticisine güvenli biçimde iletin.`);
    setPage("list");
    await loadBusinesses();
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
            {page === "create" ? <Pressable style={styles.headerButton} onPress={() => setPage("list")} disabled={loading}><Text style={styles.backText}>‹</Text></Pressable> : <View style={styles.headerButtonPlaceholder} />}
            <Text style={styles.title}>{page === "create" ? "Yeni işletme" : "Kiralık işletmeler"}</Text>
            <Pressable style={styles.headerButton} onPress={onClose} disabled={loading}><Text style={styles.closeText}>×</Text></Pressable>
          </View>

          {page === "list" ? (
            <ScrollView showsVerticalScrollIndicator={false}>
              <View style={styles.summaryRow}>
                <View><Text style={styles.summaryLabel}>TOPLAM İŞLETME</Text><Text style={styles.summaryValue}>{businesses.length}</Text></View>
                <Pressable style={styles.createButton} onPress={openCreate}><Text style={styles.createButtonText}>＋ İşletme ekle</Text></Pressable>
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
          ) : (
            <ScrollView keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}>
              <Field label="İşletme adı" value={name} onChangeText={setName} placeholder="Örn. Tırtar Market" />
              <Field label="İşletme kodu" value={slug} onChangeText={(value) => setSlug(value.toLowerCase().replace(/[^a-z0-9-]/g, ""))} placeholder="tirtar-market" autoCapitalize="none" />
              <Field label="Yönetici adı ve soyadı" value={adminName} onChangeText={setAdminName} placeholder="Ad Soyad" />
              <Field label="Yönetici kullanıcı adı" value={username} onChangeText={setUsername} placeholder="kullaniciadi" autoCapitalize="none" />
              <Field label="Geçici şifre" value={password} onChangeText={setPassword} placeholder="En az 8 karakter" secureTextEntry autoCapitalize="none" />
              <View style={styles.formRow}>
                <View style={styles.formThird}><Field label="Deneme günü" value={trialDays} onChangeText={setTrialDays} placeholder="14" keyboardType="number-pad" /></View>
                <View style={styles.formThird}><Field label="Kullanıcı limiti" value={maxMembers} onChangeText={setMaxMembers} placeholder="5" keyboardType="number-pad" /></View>
                <View style={styles.formThird}><Field label="Ürün limiti" value={maxProducts} onChangeText={setMaxProducts} placeholder="1000" keyboardType="number-pad" /></View>
              </View>
              <Pressable style={[styles.saveButton, loading && styles.disabled]} onPress={createBusiness} disabled={loading}>
                {loading ? <ActivityIndicator color="#172820" /> : <Text style={styles.saveButtonText}>İşletmeyi ve yöneticiyi oluştur</Text>}
              </Pressable>
              <Text style={styles.help}>İşletme, deneme süresi boyunca kendi stok ve çalışan verileriyle tamamen ayrı çalışır.</Text>
              <View style={styles.bottomSpace} />
            </ScrollView>
          )}
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function Field(props: React.ComponentProps<typeof TextInput> & { label: string }) {
  const { label, ...inputProps } = props;
  return <View style={styles.field}><Text style={styles.label}>{label}</Text><TextInput style={styles.input} placeholderTextColor="#98a09b" {...inputProps} /></View>;
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

function isStrongPassword(value: string) {
  return value.length >= 8 && value.length <= 72
    && /[a-z]/.test(value) && /[A-Z]/.test(value)
    && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value);
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
  headerButtonPlaceholder: { width: 36, height: 36 }, backText: { color: "#405048", fontSize: 30, lineHeight: 31 }, closeText: { color: "#5c6861", fontSize: 22 },
  title: { color: "#1b2721", fontSize: 19, fontWeight: "800" },
  summaryRow: { marginBottom: 13, padding: 14, flexDirection: "row", alignItems: "center", justifyContent: "space-between", borderRadius: 14, backgroundColor: "#172820" },
  summaryLabel: { color: "#8ea499", fontSize: 8, fontWeight: "900", letterSpacing: .8 }, summaryValue: { marginTop: 4, color: "#fff", fontSize: 24, fontWeight: "900" },
  createButton: { paddingHorizontal: 12, paddingVertical: 10, borderRadius: 10, backgroundColor: "#f3a952" }, createButtonText: { color: "#172820", fontSize: 10, fontWeight: "900" },
  loader: { marginVertical: 30 },
  businessCard: { marginBottom: 11, padding: 14, borderWidth: 1, borderColor: "#e0e5e0", borderRadius: 14, backgroundColor: "#fff" },
  businessTop: { flexDirection: "row", alignItems: "flex-start" }, businessText: { flex: 1 }, businessName: { color: "#1b2721", fontSize: 13, fontWeight: "900" }, businessSlug: { marginTop: 3, color: "#929994", fontSize: 9 },
  statusBadge: { paddingHorizontal: 8, paddingVertical: 5, borderRadius: 20 }, statusActive: { backgroundColor: "#e4f2ea" }, statusTrial: { backgroundColor: "#fff0d8" }, statusBlocked: { backgroundColor: "#f7e4e0" }, statusText: { color: "#3e6453", fontSize: 7, fontWeight: "900" },
  usage: { marginTop: 12, color: "#59645e", fontSize: 10, fontWeight: "700" }, period: { marginTop: 4, color: "#8b938e", fontSize: 8 },
  actions: { marginTop: 12, flexDirection: "row", gap: 8 }, activateButton: { flex: 1, paddingVertical: 9, alignItems: "center", borderRadius: 9, backgroundColor: "#e3f1e9" }, activateText: { color: "#2d7053", fontSize: 9, fontWeight: "900" }, suspendButton: { flex: 1, paddingVertical: 9, alignItems: "center", borderRadius: 9, backgroundColor: "#f5e5e1" }, suspendText: { color: "#a64d43", fontSize: 9, fontWeight: "900" },
  field: { marginBottom: 13 }, label: { marginBottom: 6, color: "#5e6863", fontSize: 10, fontWeight: "800" }, input: { height: 46, paddingHorizontal: 12, borderWidth: 1, borderColor: "#dde2dd", borderRadius: 10, backgroundColor: "#fff", color: "#17201d", fontSize: 12 },
  formRow: { flexDirection: "row", gap: 8 }, formThird: { flex: 1 },
  saveButton: { height: 50, marginTop: 5, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#f3a952" }, saveButtonText: { color: "#172820", fontSize: 11, fontWeight: "900" }, disabled: { opacity: .55 },
  help: { marginTop: 11, color: "#8b938e", textAlign: "center", fontSize: 9, lineHeight: 14 }, bottomSpace: { height: 22 },
});
