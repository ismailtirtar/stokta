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
import type { ContentReportReason, ContentReportTarget } from "../types";

const reasons: { value: ContentReportReason; label: string }[] = [
  { value: "offensive", label: "Uygunsuz veya saldırgan içerik" },
  { value: "harassment", label: "Taciz veya zorbalık" },
  { value: "fraud", label: "Dolandırıcılık veya yanıltma" },
  { value: "privacy", label: "Gizlilik ihlali" },
  { value: "spam", label: "Spam veya izinsiz reklam" },
  { value: "other", label: "Diğer" },
];

type Props = {
  target: ContentReportTarget | null;
  saving: boolean;
  error?: string;
  onClose: () => void;
  onSubmit: (reason: ContentReportReason, details: string) => void;
};

export default function ContentReportModal({ target, saving, error = "", onClose, onSubmit }: Props) {
  const [reason, setReason] = useState<ContentReportReason | null>(null);
  const [details, setDetails] = useState("");

  useEffect(() => {
    if (target) {
      setReason(null);
      setDetails("");
    }
  }, [target]);

  return (
    <Modal visible={Boolean(target)} transparent animationType="slide" onRequestClose={saving ? () => undefined : onClose}>
      <KeyboardAvoidingView style={styles.backdrop} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <View style={styles.sheet}>
          <View style={styles.handle} />
          <View style={styles.header}>
            <View style={styles.headerText}>
              <Text style={styles.eyebrow}>GÜVENLİK BİLDİRİMİ</Text>
              <Text style={styles.title}>{targetTypeLabel(target?.type)} bildir</Text>
              <Text style={styles.target} numberOfLines={2}>{target?.label}</Text>
            </View>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Bildirim ekranını kapat"
              style={styles.closeButton}
              onPress={onClose}
              disabled={saving}
            >
              <Text style={styles.closeText}>×</Text>
            </Pressable>
          </View>

          <ScrollView keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}>
            <Text style={styles.label}>Bildirim nedeni</Text>
            <View style={styles.reasons}>
              {reasons.map((item) => (
                <Pressable
                  key={item.value}
                  accessibilityRole="radio"
                  accessibilityState={{ selected: reason === item.value, disabled: saving }}
                  style={[styles.reasonButton, reason === item.value && styles.reasonButtonActive]}
                  onPress={() => setReason(item.value)}
                  disabled={saving}
                >
                  <View style={[styles.radio, reason === item.value && styles.radioActive]}>{reason === item.value ? <View style={styles.radioDot} /> : null}</View>
                  <Text style={[styles.reasonText, reason === item.value && styles.reasonTextActive]}>{item.label}</Text>
                </Pressable>
              ))}
            </View>

            <Text style={styles.label}>Açıklama (isteğe bağlı)</Text>
            <TextInput
              accessibilityLabel="Bildirim açıklaması"
              style={styles.detailsInput}
              value={details}
              onChangeText={setDetails}
              placeholder="Neyi uygunsuz bulduğunuzu kişisel veya hassas bilgi eklemeden açıklayın."
              placeholderTextColor="#959d98"
              multiline
              maxLength={1000}
              textAlignVertical="top"
              editable={!saving}
            />
            <Text style={styles.counter}>{details.length}/1000</Text>

            {error ? <Text accessibilityRole="alert" style={styles.errorText}>{error}</Text> : null}
            <Text style={styles.notice}>Bildirim, hedefin rolüne göre yetkili inceleme kuyruğuna iletilir. Kötü niyetli veya tekrarlanan asılsız bildirimler kullanım koşullarını ihlal eder.</Text>

            <Pressable
              accessibilityRole="button"
              accessibilityLabel="Güvenlik bildirimini gönder"
              accessibilityState={{ disabled: !reason || saving, busy: saving }}
              style={[styles.submitButton, (!reason || saving) && styles.disabled]}
              onPress={() => reason && onSubmit(reason, details.trim())}
              disabled={!reason || saving}
            >
              {saving ? <ActivityIndicator color="#172820" /> : <Text style={styles.submitText}>Bildirimi gönder</Text>}
            </Pressable>
          </ScrollView>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function targetTypeLabel(type?: ContentReportTarget["type"]) {
  return type === "product" ? "Ürünü" : type === "movement" ? "Hareket içeriğini" : "Kullanıcıyı";
}

const styles = StyleSheet.create({
  backdrop: { flex: 1, justifyContent: "flex-end", backgroundColor: "#0c1813b5" },
  sheet: { maxHeight: "94%", padding: 20, paddingTop: 10, borderTopLeftRadius: 24, borderTopRightRadius: 24, backgroundColor: "#f8f8f5" },
  handle: { width: 40, height: 4, alignSelf: "center", marginBottom: 15, borderRadius: 2, backgroundColor: "#cbd0cc" },
  header: { marginBottom: 18, flexDirection: "row", alignItems: "flex-start", justifyContent: "space-between" },
  headerText: { flex: 1, paddingRight: 12 },
  eyebrow: { color: "#858e89", fontSize: 8, fontWeight: "900", letterSpacing: 1.1 },
  title: { marginTop: 4, color: "#1b2721", fontSize: 21, fontWeight: "800" },
  target: { marginTop: 5, color: "#657069", fontSize: 10, lineHeight: 15 },
  closeButton: { width: 36, height: 36, alignItems: "center", justifyContent: "center", borderRadius: 10, backgroundColor: "#e8ebe7" },
  closeText: { color: "#5c6861", fontSize: 23 },
  label: { marginBottom: 7, color: "#59645e", fontSize: 10, fontWeight: "900" },
  reasons: { marginBottom: 17, gap: 7 },
  reasonButton: { minHeight: 43, paddingHorizontal: 12, flexDirection: "row", alignItems: "center", borderWidth: 1, borderColor: "#dde2dd", borderRadius: 10, backgroundColor: "#fff" },
  reasonButtonActive: { borderColor: "#69a187", backgroundColor: "#edf6f1" },
  radio: { width: 18, height: 18, marginRight: 9, alignItems: "center", justifyContent: "center", borderWidth: 1.5, borderColor: "#a6aea9", borderRadius: 9 },
  radioActive: { borderColor: "#34795a" },
  radioDot: { width: 9, height: 9, borderRadius: 5, backgroundColor: "#34795a" },
  reasonText: { flex: 1, color: "#66716b", fontSize: 10, fontWeight: "700" },
  reasonTextActive: { color: "#2c6e52" },
  detailsInput: { minHeight: 94, padding: 12, borderWidth: 1, borderColor: "#dce1dc", borderRadius: 11, backgroundColor: "#fff", color: "#17201d", fontSize: 11, lineHeight: 17 },
  counter: { marginTop: 4, color: "#999f9b", textAlign: "right", fontSize: 8 },
  errorText: { marginTop: 10, padding: 10, color: "#92483f", fontSize: 10, borderRadius: 9, backgroundColor: "#fae8e4" },
  notice: { marginTop: 11, color: "#7a837e", fontSize: 9, lineHeight: 14 },
  submitButton: { minHeight: 50, marginTop: 15, marginBottom: 8, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#f3a952" },
  submitText: { color: "#172820", fontSize: 12, fontWeight: "900" },
  disabled: { opacity: .5 },
});
