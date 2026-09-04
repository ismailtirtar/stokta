import { useState } from "react";
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { supabase } from "../lib/supabase";

export default function ForcedPasswordChange() {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPasswordAgain, setNewPasswordAgain] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function changePassword() {
    if (!currentPassword) {
      setError("Geçici şifrenizi girin.");
      return;
    }
    if (!isStrongPassword(newPassword)) {
      setError("Yeni şifre 8–72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli.");
      return;
    }
    if (currentPassword === newPassword) {
      setError("Yeni şifre geçici şifreden farklı olmalı.");
      return;
    }
    if (newPassword !== newPasswordAgain) {
      setError("Yeni şifreler eşleşmiyor.");
      return;
    }

    setLoading(true);
    setError("");
    const { error: changeError } = await supabase.functions.invoke("account-security", {
      body: { action: "change-password", currentPassword, newPassword },
    });
    setLoading(false);
    if (changeError) {
      setError(await edgeFunctionError(changeError));
      return;
    }
    await supabase.auth.signOut({ scope: "local" });
  }

  return (
    <SafeAreaView style={styles.safe} edges={["top", "bottom"]}>
      <KeyboardAvoidingView style={styles.flex} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled">
          <View style={styles.brand}><View style={styles.logo}><Text style={styles.logoText}>S</Text></View><Text style={styles.brandName}>Stokdaş</Text></View>
          <Text style={styles.kicker}>HESAP GÜVENLİĞİ</Text>
          <Text style={styles.title}>Yeni şifre belirleyin</Text>
          <Text style={styles.subtitle}>Yöneticinizin verdiği geçici şifreyi kişisel ve güçlü bir şifreyle değiştirmeniz gerekiyor.</Text>
          <View style={styles.card}>
            <PasswordField label="Geçici şifre" value={currentPassword} onChangeText={setCurrentPassword} textContentType="password" autoFocus />
            <PasswordField label="Yeni şifre" value={newPassword} onChangeText={setNewPassword} textContentType="newPassword" />
            <PasswordField label="Yeni şifre tekrarı" value={newPasswordAgain} onChangeText={setNewPasswordAgain} textContentType="newPassword" onSubmitEditing={changePassword} />
            {error ? <Text style={styles.error}>{error}</Text> : null}
            <Pressable style={[styles.button, loading && styles.disabled]} onPress={() => void changePassword()} disabled={loading}>
              {loading ? <ActivityIndicator color="#172820" /> : <Text style={styles.buttonText}>Şifreyi değiştir</Text>}
            </Pressable>
            <Text style={styles.help}>Değişiklikten sonra bu cihazdaki oturum kapanır; yeni şifrenizle tekrar giriş yaparsınız.</Text>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

function PasswordField(props: React.ComponentProps<typeof TextInput> & { label: string }) {
  const { label, ...inputProps } = props;
  return <View style={styles.field}><Text style={styles.label}>{label}</Text><TextInput style={styles.input} placeholder="••••••••" placeholderTextColor="#98a09b" secureTextEntry autoCapitalize="none" autoCorrect={false} {...inputProps} /></View>;
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
  } catch {
    // Yanıt gövdesi yoksa istemci mesajına dönülür.
  }
  return candidate.message ?? "Şifre değiştirilemedi.";
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#172820" },
  flex: { flex: 1 },
  content: { flexGrow: 1, justifyContent: "center", paddingHorizontal: 22, paddingVertical: 28 },
  brand: { flexDirection: "row", alignItems: "center", gap: 10 },
  logo: { width: 40, height: 40, borderRadius: 12, borderBottomLeftRadius: 4, alignItems: "center", justifyContent: "center", backgroundColor: "#f3a952" },
  logoText: { color: "#172820", fontSize: 21, fontWeight: "900" },
  brandName: { color: "#fff", fontSize: 21, fontWeight: "800" },
  kicker: { marginTop: 30, color: "#f3b765", fontSize: 10, fontWeight: "800", letterSpacing: 1.5 },
  title: { marginTop: 9, color: "#fff", fontSize: 28, fontWeight: "800" },
  subtitle: { marginTop: 9, marginBottom: 18, color: "#9fb0a7", fontSize: 13, lineHeight: 20 },
  card: { padding: 20, borderRadius: 18, backgroundColor: "#f7f7f3" },
  field: { marginBottom: 14 },
  label: { marginBottom: 7, color: "#5e6863", fontSize: 11, fontWeight: "700" },
  input: { height: 48, paddingHorizontal: 13, borderWidth: 1, borderColor: "#dde2dd", borderRadius: 11, backgroundColor: "#fff", color: "#17201d", fontSize: 14 },
  error: { color: "#b54e43", fontSize: 11, lineHeight: 16 },
  button: { height: 49, alignItems: "center", justifyContent: "center", marginTop: 10, borderRadius: 11, backgroundColor: "#f3a952" },
  buttonText: { color: "#172820", fontSize: 14, fontWeight: "900" },
  disabled: { opacity: 0.55 },
  help: { marginTop: 13, color: "#7d8882", textAlign: "center", fontSize: 10, lineHeight: 15 },
});
