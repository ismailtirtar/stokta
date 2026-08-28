import { useEffect, useState } from "react";
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Modal,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import type { ProfileRole } from "../types";

type Props = {
  visible: boolean;
  displayName: string;
  username: string;
  role: ProfileRole | null;
  organizationName: string;
  subscriptionLabel: string;
  isPlatformOperator: boolean;
  saving: boolean;
  onClose: () => void;
  onSignOut: () => void;
  onDelete: (confirmation: string, currentPassword: string) => void;
};

export default function AccountModal({
  visible,
  displayName,
  username,
  role,
  organizationName,
  subscriptionLabel,
  isPlatformOperator,
  saving,
  onClose,
  onSignOut,
  onDelete,
}: Props) {
  const [page, setPage] = useState<"account" | "privacy" | "delete">("account");
  const [confirmation, setConfirmation] = useState("");
  const [currentPassword, setCurrentPassword] = useState("");

  useEffect(() => {
    if (visible) {
      setPage("account");
      setConfirmation("");
      setCurrentPassword("");
    }
  }, [visible]);

  const isAdmin = role === "admin";
  const expectedConfirmation = isAdmin ? "STOKDAŞ" : username;
  const canDelete = confirmation.trim() === expectedConfirmation
    && currentPassword.length > 0
    && currentPassword.length <= 72
    && !saving;

  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <KeyboardAvoidingView style={styles.backdrop} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <View style={styles.sheet}>
          <View style={styles.handle} />
          <View style={styles.header}>
            <Pressable
              style={[styles.headerButton, page === "account" && styles.headerButtonHidden]}
              onPress={() => { setPage("account"); setConfirmation(""); setCurrentPassword(""); }}
              disabled={page === "account" || saving}
            >
              <Text style={styles.headerButtonText}>‹</Text>
            </Pressable>
            <Text style={styles.title}>{page === "privacy" ? "Gizlilik politikası" : page === "delete" ? "Hesabı sil" : "Hesabım"}</Text>
            <Pressable style={styles.headerButton} onPress={onClose} disabled={saving}>
              <Text style={styles.closeText}>×</Text>
            </Pressable>
          </View>

          {page === "account" ? (
            <View>
              <View style={styles.profileCard}>
                <View style={styles.avatar}><Text style={styles.avatarText}>{initials(displayName)}</Text></View>
                <View style={styles.profileText}>
                  <Text style={styles.name}>{displayName}</Text>
                  <Text style={styles.username}>@{username || "kullanici"} · {isAdmin ? "Yönetici" : "Çalışan"}</Text>
                  <Text style={styles.organization}>{organizationName} · {subscriptionLabel}</Text>
                </View>
              </View>

              <Pressable style={styles.menuItem} onPress={() => setPage("privacy")}>
                <View><Text style={styles.menuTitle}>Gizlilik politikası</Text><Text style={styles.menuCaption}>Verilerin nasıl işlendiğini görüntüle</Text></View>
                <Text style={styles.chevron}>›</Text>
              </Pressable>
              <Pressable style={styles.menuItem} onPress={onSignOut}>
                <View><Text style={styles.menuTitle}>Çıkış yap</Text><Text style={styles.menuCaption}>Yalnızca bu cihazdaki oturumu kapat</Text></View>
                <Text style={styles.chevron}>›</Text>
              </Pressable>
              {!isPlatformOperator ? <Pressable style={[styles.menuItem, styles.dangerItem]} onPress={() => setPage("delete")}>
                <View><Text style={styles.dangerTitle}>{isAdmin ? "İşletmeyi ve hesapları sil" : "Hesabımı sil"}</Text><Text style={styles.dangerCaption}>Bu işlem geri alınamaz</Text></View>
                <Text style={styles.dangerChevron}>›</Text>
              </Pressable> : null}

              <Text style={styles.version}>Stokdaş · Sürüm 1.3.2</Text>
            </View>
          ) : null}

          {page === "privacy" ? <PrivacyPolicy /> : null}

          {page === "delete" ? (
            <ScrollView keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}>
              <View style={styles.warningBox}>
                <Text style={styles.warningTitle}>Kalıcı silme işlemi</Text>
                <Text style={styles.warningText}>
                  {isAdmin
                    ? "İşletme yöneticisi hesabı silindiğinde yalnızca bu işletmenin ürünleri, stok hareketleri ve çalışan hesapları kalıcı olarak silinir. Diğer işletmeler etkilenmez."
                    : "Adınız, kullanıcı adınız ve giriş hesabınız kalıcı olarak silinir. Ortak stok geçmişinin tutarlılığı için eski hareketleriniz yalnızca “Silinmiş kullanıcı” adıyla anonim olarak kalır."}
                </Text>
              </View>
              <Text style={styles.confirmLabel}>Devam etmek için aşağıya {expectedConfirmation} yazın</Text>
              <TextInput
                style={styles.confirmInput}
                value={confirmation}
                onChangeText={setConfirmation}
                placeholder={expectedConfirmation}
                placeholderTextColor="#9ca39f"
                autoCapitalize={isAdmin ? "characters" : "none"}
                autoCorrect={false}
                editable={!saving}
              />
              <Text style={styles.confirmLabel}>Mevcut şifreniz</Text>
              <TextInput
                style={styles.confirmInput}
                value={currentPassword}
                onChangeText={setCurrentPassword}
                placeholder="Mevcut şifrenizi girin"
                placeholderTextColor="#9ca39f"
                autoCapitalize="none"
                autoCorrect={false}
                secureTextEntry
                textContentType="password"
                editable={!saving}
              />
              <Pressable style={[styles.deleteButton, !canDelete && styles.disabled]} onPress={() => onDelete(confirmation.trim(), currentPassword)} disabled={!canDelete}>
                {saving ? <ActivityIndicator color="#fff" /> : <Text style={styles.deleteButtonText}>{isAdmin ? "Her şeyi kalıcı olarak sil" : "Hesabımı kalıcı olarak sil"}</Text>}
              </Pressable>
            </ScrollView>
          ) : null}
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function PrivacyPolicy() {
  return (
    <ScrollView style={styles.policy} showsVerticalScrollIndicator={false}>
      <Text style={styles.policyDate}>Yürürlük tarihi: 25 Ağustos 2026</Text>
      <PolicySection title="Veri sorumlusu">Stokdaş uygulaması İsmail Tırtar tarafından işletilir. Hizmet, kiracı işletmelerin stok ve kullanıcı verilerini birbirinden ayrılmış çalışma alanlarında yönetmesini sağlar.</PolicySection>
      <PolicySection title="İşlenen veriler">İşletme adı; kullanıcı adı, ad ve soyad, hesap rolü, oturum bilgileri; ürünler, stok miktarları, işlem notları ve işlemi yapan kullanıcı kaydı işlenir. Kayıt kötüye kullanımını sınırlandırmak için ağ adresinin geri döndürülemeyen özeti kısa süreyle tutulur. Şifreler Supabase Auth tarafından güvenli biçimde yönetilir ve uygulama tarafından düz metin olarak saklanmaz.</PolicySection>
      <PolicySection title="Amaç ve paylaşım">Veriler yalnızca kimlik doğrulama, işletme hesabı açma, ortak stok takibi, kiralama yönetimi, yetkilendirme, güvenlik ve işlem geçmişi amaçlarıyla kullanılır. Reklam veya kullanıcı takibi yapılmaz. Altyapı sağlayıcısı olarak Supabase kullanılır; veriler Frankfurt bölgesindeki sunucularda tutulur.</PolicySection>
      <PolicySection title="Saklama ve silme">Veriler hesap veya işletme çalışma alanı silinene kadar saklanır. Çalışan hesabı silindiğinde profil bilgileri kaldırılır ve eski hareketler anonimleştirilir. İşletme yöneticisi silme işlemini başlattığında yalnızca kendi işletmesinin verileri ve hesapları kalıcı olarak kaldırılır.</PolicySection>
      <PolicySection title="Güvenlik">Aktarım sırasında HTTPS kullanılır. Her kayıt işletme kimliğiyle ayrılır; veritabanında satır düzeyi güvenlik ve rol tabanlı yetkilendirme uygulanır. Bir işletme diğer işletmenin ürün, hareket veya kullanıcı verilerini okuyamaz. Hizmet rolü anahtarı mobil uygulamaya eklenmez.</PolicySection>
      <PolicySection title="Haklarınız">Hesabınızı bu ekrandaki “Hesabımı sil” seçeneğiyle silebilirsiniz. İşletme yöneticisi yalnızca kendi işletmesinin çalışma alanını kaldırabilir. Platform yöneticisi hesabı güvenlik nedeniyle uygulama içinden silinemez. Gizlilik ve veri talepleri için tirtarismail@gmail.com adresine ulaşabilirsiniz.</PolicySection>
      <View style={styles.policyBottom} />
    </ScrollView>
  );
}

function PolicySection({ title, children }: { title: string; children: string }) {
  return <View style={styles.policySection}><Text style={styles.policyTitle}>{title}</Text><Text style={styles.policyText}>{children}</Text></View>;
}

function initials(value: string) {
  return value.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]?.toLocaleUpperCase("tr-TR")).join("") || "?";
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, justifyContent: "flex-end", backgroundColor: "#0c1813a8" },
  sheet: { maxHeight: "92%", minHeight: 410, padding: 20, paddingTop: 10, borderTopLeftRadius: 24, borderTopRightRadius: 24, backgroundColor: "#f8f8f5" },
  handle: { width: 40, height: 4, alignSelf: "center", marginBottom: 13, borderRadius: 2, backgroundColor: "#cbd0cc" },
  header: { height: 38, marginBottom: 16, flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  headerButton: { width: 36, height: 36, alignItems: "center", justifyContent: "center", borderRadius: 10, backgroundColor: "#e9ece8" },
  headerButtonHidden: { opacity: 0 },
  headerButtonText: { color: "#405048", fontSize: 30, lineHeight: 31 },
  closeText: { color: "#5c6861", fontSize: 22 },
  title: { color: "#1b2721", fontSize: 19, fontWeight: "800" },
  profileCard: { padding: 16, flexDirection: "row", alignItems: "center", borderWidth: 1, borderColor: "#e2e6e1", borderRadius: 14, backgroundColor: "#fff" },
  avatar: { width: 48, height: 48, alignItems: "center", justifyContent: "center", borderRadius: 15, backgroundColor: "#f3a952" },
  avatarText: { color: "#172820", fontSize: 14, fontWeight: "900" },
  profileText: { flex: 1, marginLeft: 12 },
  name: { color: "#1b2721", fontSize: 14, fontWeight: "800" },
  username: { marginTop: 4, color: "#858d88", fontSize: 10 },
  organization: { marginTop: 4, color: "#5e786b", fontSize: 9, fontWeight: "700" },
  menuItem: { minHeight: 64, paddingHorizontal: 4, flexDirection: "row", alignItems: "center", justifyContent: "space-between", borderBottomWidth: 1, borderBottomColor: "#e6e9e5" },
  menuTitle: { color: "#26322c", fontSize: 12, fontWeight: "800" },
  menuCaption: { marginTop: 4, color: "#8a918d", fontSize: 9 },
  chevron: { color: "#89938e", fontSize: 23 },
  dangerItem: { marginTop: 8, borderBottomWidth: 0 },
  dangerTitle: { color: "#a84d43", fontSize: 12, fontWeight: "800" },
  dangerCaption: { marginTop: 4, color: "#b57870", fontSize: 9 },
  dangerChevron: { color: "#b96055", fontSize: 23 },
  version: { marginTop: 24, color: "#9aa19d", textAlign: "center", fontSize: 9 },
  warningBox: { padding: 15, borderWidth: 1, borderColor: "#efd2cc", borderRadius: 13, backgroundColor: "#fae9e5" },
  warningTitle: { color: "#943f36", fontSize: 13, fontWeight: "900" },
  warningText: { marginTop: 7, color: "#8f5149", fontSize: 10, lineHeight: 16 },
  confirmLabel: { marginTop: 18, marginBottom: 7, color: "#59645e", fontSize: 10, fontWeight: "800" },
  confirmInput: { height: 48, paddingHorizontal: 13, borderWidth: 1, borderColor: "#d8ddd8", borderRadius: 11, backgroundColor: "#fff", color: "#17201d", fontSize: 13 },
  deleteButton: { height: 50, marginTop: 14, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#ad4f44" },
  deleteButtonText: { color: "#fff", fontSize: 12, fontWeight: "900" },
  disabled: { opacity: .45 },
  policy: { marginHorizontal: -3 },
  policyDate: { marginBottom: 14, color: "#8c948f", fontSize: 9 },
  policySection: { marginBottom: 17 },
  policyTitle: { marginBottom: 5, color: "#26322c", fontSize: 12, fontWeight: "900" },
  policyText: { color: "#66716b", fontSize: 10, lineHeight: 17 },
  policyBottom: { height: 18 },
});
