import {
  ActivityIndicator,
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { CURRENT_UGC_TERMS_VERSION } from "../lib/ugc";

type Props = {
  visible: boolean;
  mandatory: boolean;
  accepted: boolean;
  reviewOnly?: boolean;
  checking?: boolean;
  saving?: boolean;
  error?: string;
  onAccept: () => void;
  onClose: () => void;
  onDecline?: () => void;
  onRetry?: () => void;
};

export default function TermsModal({
  visible,
  mandatory,
  accepted,
  reviewOnly = false,
  checking = false,
  saving = false,
  error = "",
  onAccept,
  onClose,
  onDecline,
  onRetry,
}: Props) {
  const canAccept = !checking && !saving && !accepted && !error;

  return (
    <Modal
      visible={visible}
      animationType="fade"
      presentationStyle="fullScreen"
      statusBarTranslucent={false}
      onRequestClose={mandatory ? () => undefined : onClose}
    >
      <SafeAreaView style={styles.safe} edges={["top", "bottom"]}>
        <View style={styles.header}>
          <View style={styles.brandMark}><Text style={styles.brandMarkText}>S</Text></View>
          <View style={styles.headerText}>
            <Text style={styles.eyebrow}>STOKDAŞ GÜVENLİ KULLANIM</Text>
            <Text style={styles.title}>Kullanım koşulları</Text>
          </View>
          {!mandatory ? (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Kullanım koşullarını kapat"
              hitSlop={8}
              style={styles.closeButton}
              onPress={onClose}
            >
              <Text style={styles.closeText}>×</Text>
            </Pressable>
          ) : null}
        </View>

        <ScrollView
          style={styles.scroll}
          contentContainerStyle={styles.content}
          showsVerticalScrollIndicator={false}
        >
          <View style={styles.versionBox}>
            <Text style={styles.versionTitle}>Koşul sürümü: {CURRENT_UGC_TERMS_VERSION}</Text>
            <Text style={styles.versionText}>
              {mandatory
                ? "Stok alanını kullanmadan önce bu koşulları okuyup açıkça kabul etmeniz gerekir."
                : "Bu koşulları Hesabım ekranından istediğiniz zaman yeniden inceleyebilirsiniz."}
            </Text>
          </View>

          <TermsSection title="1. Kapsam">
            Stokdaş, aynı işletmedeki doğrulanmış kullanıcıların ürün adı, ürün kodu, kategori, birim ve stok hareketi notu gibi içerikleri ortak çalışma alanında paylaşmasını sağlar. Bu içerikler yalnızca bağlı işletmenin yetkili kullanıcılarına gösterilir.
          </TermsSection>
          <TermsSection title="2. Yasak içerikler">
            Yasa dışı; cinsel veya çocukların istismarıyla ilişkili; şiddeti teşvik eden; tehdit, nefret, ayrımcılık, taciz ya da zorbalık içeren içerikler yasaktır. Başkasının kişisel verisini veya mahremiyetini ihlal eden, fikrî mülkiyet hakkını çiğneyen, dolandırıcılık ya da kimliğe bürünme amacı taşıyan, yanıltıcı, spam, izinsiz reklam, zararlı bağlantı veya kötü amaçlı yazılım niteliğindeki içerikler de yüklenemez.
          </TermsSection>
          <TermsSection title="3. Yasak davranışlar">
            Diğer kullanıcıları taciz etmek, stok kayıtlarını zarar verme amacıyla değiştirmek, yetkisiz hesaba veya işletme verisine erişmeye çalışmak, güvenlik önlemlerini aşmak, hesabı başkasına kullandırmak ve bildirim sistemini kötü niyetle kullanmak yasaktır. Her kullanıcı kendi hesabıyla yapılan işlemlerden sorumludur.
          </TermsSection>
          <TermsSection title="4. Bildirim ve moderasyon">
            Uygulamadaki “Bildir” seçenekleriyle ürünleri, stok hareketlerini ve hareketi yapan kullanıcıyı yetkili inceleme kuyruğuna bildirebilirsiniz. Bildirim; hedef kaydı, bildirim nedenini, isteğe bağlı açıklamayı, bildiren hesabı ve işlem zamanını içerir. Çalışan hesabıyla ilişkili içerikler işletme yöneticisinin inceleme kuyruğuna gider; yönetici ürünü kaldırabilir, hareket notunu gizleyebilir, bildirilen çalışan hesabını devre dışı bırakabilir veya bildirimi işlem gerektirmediği gerekçesiyle kapatabilir. İşletme yöneticisi ya da platform yöneticisi hesabıyla ilişkili içerikler, çıkar çatışmasını önlemek için yalnız yetkili Stokdaş platform inceleme kuyruğuna yönlendirilir. Platform incelemesi ürünü kaldırabilir, hareket notunu gizleyebilir, ilgili işletmeyi idari olarak askıya alabilir veya bildirimi işlem gerektirmediği gerekçesiyle kapatabilir.
          </TermsSection>
          <TermsSection title="5. Yaptırımlar">
            Yasak içeriğin kaldırılması, görünürlüğünün sınırlandırılması, hesap veya işletme erişiminin askıya alınması ya da sona erdirilmesi mümkündür. Ciddi veya tekrarlanan ihlaller platform güvenliği kapsamında ayrıca incelenebilir ve hukuken gerekli hâllerde yetkili mercilerle iş birliği yapılabilir. Kötü niyetli ve tekrarlanan asılsız bildirimler de hesap kısıtlamasına yol açabilir.
          </TermsSection>
          <TermsSection title="6. Koşulların güncellenmesi">
            Güvenlik, mevzuat veya hizmet değişiklikleri nedeniyle koşullar güncellenebilir. Yeni bir sürüm yayımlandığında stok alanını kullanmaya devam etmeden önce yeniden kabulünüz istenir. Gizlilik ve veri işleme ayrıntıları Hesabım bölümündeki Gizlilik Politikası’nda açıklanır.
          </TermsSection>

          <Text style={styles.contact}>İletişim: tirtarismail@gmail.com</Text>
        </ScrollView>

        <View style={styles.footer}>
          {error ? (
            <View accessibilityRole="alert" style={styles.errorBox}>
              <Text style={styles.errorText}>{error}</Text>
              {onRetry ? (
                <Pressable accessibilityRole="button" onPress={onRetry} style={styles.retryButton}>
                  <Text style={styles.retryText}>Tekrar dene</Text>
                </Pressable>
              ) : null}
            </View>
          ) : null}
          {reviewOnly ? (
            <Pressable accessibilityRole="button" style={styles.doneButton} onPress={onClose}>
              <Text style={styles.doneButtonText}>Kapat</Text>
            </Pressable>
          ) : checking ? (
            <View style={styles.checkingBox}>
              <ActivityIndicator color="#f3a952" />
              <Text style={styles.checkingText}>Hesap koşulları denetleniyor…</Text>
            </View>
          ) : accepted ? (
            <View style={styles.acceptedBox}>
              <Text style={styles.acceptedText}>✓ Güncel koşulları kabul ettiniz.</Text>
            </View>
          ) : (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Kullanım koşullarını kabul et"
              accessibilityHint="Koşulların güncel sürümünü hesabınız için kabul eder"
              accessibilityState={{ disabled: !canAccept, busy: saving }}
              style={[styles.acceptButton, !canAccept && styles.disabled]}
              onPress={onAccept}
              disabled={!canAccept}
            >
              {saving ? <ActivityIndicator color="#172820" /> : <Text style={styles.acceptButtonText}>Okudum ve kabul ediyorum</Text>}
            </Pressable>
          )}
          {!reviewOnly && !mandatory && accepted ? (
            <Pressable accessibilityRole="button" style={styles.doneButton} onPress={onClose}>
              <Text style={styles.doneButtonText}>Kapat</Text>
            </Pressable>
          ) : null}
          {mandatory && onDecline ? (
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Koşulları kabul etmeden çıkış yap"
              style={[styles.declineButton, saving && styles.disabled]}
              onPress={onDecline}
              disabled={saving}
            >
              <Text style={styles.declineButtonText}>Kabul etmeden çıkış yap</Text>
            </Pressable>
          ) : null}
        </View>
      </SafeAreaView>
    </Modal>
  );
}

function TermsSection({ title, children }: { title: string; children: string }) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      <Text style={styles.sectionText}>{children}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#f4f5f1" },
  header: { minHeight: 82, paddingHorizontal: 18, paddingVertical: 14, flexDirection: "row", alignItems: "center", backgroundColor: "#172820" },
  brandMark: { width: 44, height: 44, alignItems: "center", justifyContent: "center", borderRadius: 13, borderBottomLeftRadius: 4, backgroundColor: "#f3a952" },
  brandMarkText: { color: "#172820", fontSize: 23, fontWeight: "900" },
  headerText: { flex: 1, marginLeft: 12 },
  eyebrow: { color: "#91a69c", fontSize: 8, fontWeight: "900", letterSpacing: 1.1 },
  title: { marginTop: 4, color: "#fff", fontSize: 22, fontWeight: "800" },
  closeButton: { width: 38, height: 38, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#284237" },
  closeText: { color: "#dce7e1", fontSize: 24 },
  scroll: { flex: 1 },
  content: { padding: 18, paddingBottom: 28 },
  versionBox: { marginBottom: 18, padding: 14, borderWidth: 1, borderColor: "#efd4ae", borderRadius: 13, backgroundColor: "#fff4df" },
  versionTitle: { color: "#82551b", fontSize: 11, fontWeight: "900" },
  versionText: { marginTop: 5, color: "#936f40", fontSize: 10, lineHeight: 16 },
  section: { marginBottom: 18 },
  sectionTitle: { marginBottom: 6, color: "#1d2b24", fontSize: 13, fontWeight: "900" },
  sectionText: { color: "#5d6962", fontSize: 11, lineHeight: 18 },
  contact: { color: "#4f6f5f", fontSize: 10, fontWeight: "700" },
  footer: { padding: 14, paddingTop: 10, borderTopWidth: 1, borderTopColor: "#dfe3de", backgroundColor: "#fff" },
  errorBox: { marginBottom: 9, padding: 10, flexDirection: "row", alignItems: "center", borderRadius: 10, backgroundColor: "#fae8e4" },
  errorText: { flex: 1, color: "#92483f", fontSize: 10, lineHeight: 15 },
  retryButton: { paddingHorizontal: 10, paddingVertical: 7 },
  retryText: { color: "#813e36", fontSize: 10, fontWeight: "900" },
  checkingBox: { minHeight: 50, flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 10, borderRadius: 12, backgroundColor: "#172820" },
  checkingText: { color: "#d8e4de", fontSize: 11, fontWeight: "700" },
  acceptedBox: { minHeight: 48, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#e4f2ea" },
  acceptedText: { color: "#2f7455", fontSize: 11, fontWeight: "900" },
  acceptButton: { minHeight: 51, alignItems: "center", justifyContent: "center", borderRadius: 12, backgroundColor: "#f3a952" },
  acceptButtonText: { color: "#172820", fontSize: 12, fontWeight: "900" },
  doneButton: { minHeight: 44, marginTop: 8, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#172820" },
  doneButtonText: { color: "#fff", fontSize: 11, fontWeight: "900" },
  declineButton: { minHeight: 42, marginTop: 8, alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "#d9ded9", borderRadius: 11, backgroundColor: "#fff" },
  declineButtonText: { color: "#5e6b64", fontSize: 10, fontWeight: "800" },
  disabled: { opacity: .5 },
});
