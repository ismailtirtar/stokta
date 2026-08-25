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
import { normalizeUsername, supabase, usernameToInternalEmail } from "../lib/supabase";

type Mode = "signIn" | "register";

export default function LoginScreen() {
  const [mode, setMode] = useState<Mode>("signIn");
  const [organizationName, setOrganizationName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordAgain, setPasswordAgain] = useState("");
  const [secure, setSecure] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const isRegister = mode === "register";

  function switchMode(nextMode: Mode) {
    setMode(nextMode);
    setError("");
    setPasswordAgain("");
  }

  async function signIn() {
    const email = usernameToInternalEmail(username);
    if (!email || password.length < 8) {
      setError("Kullanıcı adı ve en az 8 karakterli şifre girin.");
      return;
    }

    setLoading(true);
    setError("");
    const { error: authError } = await supabase.auth.signInWithPassword({ email, password });
    if (authError) {
      setError(authError.message.includes("Invalid login") ? "Kullanıcı adı veya şifre hatalı." : authError.message);
    }
    setLoading(false);
  }

  async function registerBusiness() {
    const normalizedUsername = normalizeUsername(username);
    if (organizationName.trim().length < 2) {
      setError("İşletme adı en az 2 karakter olmalı.");
      return;
    }
    if (displayName.trim().length < 1) {
      setError("Ad ve soyad girin.");
      return;
    }
    if (normalizedUsername.length < 3) {
      setError("Kullanıcı adı en az 3 karakter olmalı.");
      return;
    }
    if (!isStrongPassword(password)) {
      setError("Şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli.");
      return;
    }
    if (password !== passwordAgain) {
      setError("Şifreler eşleşmiyor.");
      return;
    }

    setLoading(true);
    setError("");
    const { error: registrationError } = await supabase.functions.invoke("register-business", {
      body: {
        organizationName: organizationName.trim(),
        displayName: displayName.trim(),
        username: normalizedUsername,
        password,
      },
    });
    if (registrationError) {
      setError(await edgeFunctionError(registrationError));
      setLoading(false);
      return;
    }

    const { error: authError } = await supabase.auth.signInWithPassword({
      email: usernameToInternalEmail(normalizedUsername),
      password,
    });
    if (authError) {
      setMode("signIn");
      setError("İşletme hesabınız oluşturuldu. Kullanıcı adınız ve şifrenizle giriş yapın.");
    }
    setLoading(false);
  }

  return (
    <SafeAreaView style={styles.safe} edges={["top", "bottom"]}>
      <KeyboardAvoidingView style={styles.container} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <ScrollView
          contentContainerStyle={styles.content}
          keyboardShouldPersistTaps="handled"
          showsVerticalScrollIndicator={false}
        >
          <View style={styles.brand}>
            <View style={styles.logo}><Text style={styles.logoText}>S</Text></View>
            <Text style={styles.brandName}>Stokta</Text>
          </View>
          <View style={styles.heading}>
            <Text style={styles.kicker}>{isRegister ? "YENİ İŞLETME" : "BULUT STOK TAKİBİ"}</Text>
            <Text style={styles.title}>{isRegister ? "İşletmeni Stokta'ya taşı." : "Ekibinle aynı stokta buluş."}</Text>
            <Text style={styles.subtitle}>
              {isRegister
                ? "İşletme hesabını oluştur, ürünlerini ekle ve çalışma arkadaşlarınla ortak kullanmaya başla."
                : "Ürün giriş ve çıkışları, kritik stoklar ve tüm ekip hareketleri tek yerde."}
            </Text>
          </View>
          <View style={styles.card}>
            <View style={styles.modeRow}>
              <Pressable
                style={[styles.modeButton, !isRegister && styles.modeButtonActive]}
                onPress={() => switchMode("signIn")}
                disabled={loading}
              >
                <Text style={[styles.modeText, !isRegister && styles.modeTextActive]}>Giriş yap</Text>
              </Pressable>
              <Pressable
                style={[styles.modeButton, isRegister && styles.modeButtonActive]}
                onPress={() => switchMode("register")}
                disabled={loading}
              >
                <Text style={[styles.modeText, isRegister && styles.modeTextActive]}>Yeni işletme</Text>
              </Pressable>
            </View>

            {isRegister ? (
              <>
                <Text style={styles.label}>İşletme adı</Text>
                <TextInput
                  style={styles.input}
                  value={organizationName}
                  onChangeText={setOrganizationName}
                  placeholder="Örn. Tırtar Market"
                  placeholderTextColor="#98a09b"
                  autoCapitalize="words"
                  returnKeyType="next"
                />
                <Text style={styles.label}>Ad ve soyad</Text>
                <TextInput
                  style={styles.input}
                  value={displayName}
                  onChangeText={setDisplayName}
                  placeholder="Örn. İsmail Tırtar"
                  placeholderTextColor="#98a09b"
                  autoCapitalize="words"
                  textContentType="name"
                  returnKeyType="next"
                />
              </>
            ) : null}

            <Text style={styles.label}>Kullanıcı adı</Text>
            <TextInput
              style={styles.input}
              value={username}
              onChangeText={setUsername}
              placeholder="örn. ismail"
              placeholderTextColor="#98a09b"
              autoCapitalize="none"
              autoCorrect={false}
              textContentType="username"
              returnKeyType="next"
            />
            <Text style={styles.label}>Şifre</Text>
            <View style={styles.passwordRow}>
              <TextInput
                style={styles.passwordInput}
                value={password}
                onChangeText={setPassword}
                placeholder="En az 8 karakter"
                placeholderTextColor="#98a09b"
                secureTextEntry={secure}
                textContentType={isRegister ? "newPassword" : "password"}
                onSubmitEditing={isRegister ? undefined : signIn}
                returnKeyType={isRegister ? "next" : "done"}
              />
              <Pressable onPress={() => setSecure((value) => !value)} hitSlop={10}>
                <Text style={styles.show}>{secure ? "Göster" : "Gizle"}</Text>
              </Pressable>
            </View>
            {isRegister ? (
              <>
                <Text style={[styles.label, styles.confirmLabel]}>Şifre tekrar</Text>
                <TextInput
                  style={styles.input}
                  value={passwordAgain}
                  onChangeText={setPasswordAgain}
                  placeholder="Şifreyi yeniden gir"
                  placeholderTextColor="#98a09b"
                  secureTextEntry={secure}
                  textContentType="newPassword"
                  onSubmitEditing={registerBusiness}
                  returnKeyType="done"
                />
              </>
            ) : null}

            {error ? <Text style={styles.error}>{error}</Text> : null}
            <Pressable
              style={({ pressed }) => [styles.button, pressed && styles.buttonPressed, loading && styles.buttonDisabled]}
              onPress={isRegister ? registerBusiness : signIn}
              disabled={loading}
            >
              {loading
                ? <ActivityIndicator color="#172820" />
                : <Text style={styles.buttonText}>{isRegister ? "İşletme hesabını oluştur" : "Giriş yap"}</Text>}
            </Pressable>
            <Text style={styles.help}>
              {isRegister
                ? "14 günlük deneme başlar. İlk hesabınız işletme yöneticisi olur."
                : "Çalışan hesabınızı işletme yöneticiniz oluşturur."}
            </Text>
          </View>
          <Text style={styles.cloud}>● Frankfurt sunucusuna bağlı</Text>
        </ScrollView>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

async function edgeFunctionError(error: unknown) {
  const candidate = error as { context?: Response; message?: string };
  try {
    const body = await candidate.context?.json() as { error?: string } | undefined;
    if (body?.error) return body.error;
  } catch {
    // Yanıt gövdesi yoksa istemci mesajına dönülür.
  }
  return candidate.message ?? "İşlem tamamlanamadı.";
}

function isStrongPassword(value: string) {
  return value.length >= 8 && value.length <= 72
    && /[a-z]/.test(value) && /[A-Z]/.test(value)
    && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value);
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#172820" },
  container: { flex: 1 },
  content: { flexGrow: 1, justifyContent: "center", paddingHorizontal: 22, paddingVertical: 20 },
  brand: { flexDirection: "row", alignItems: "center", gap: 10 },
  logo: { width: 40, height: 40, borderRadius: 12, borderBottomLeftRadius: 4, alignItems: "center", justifyContent: "center", backgroundColor: "#f3a952" },
  logoText: { color: "#172820", fontSize: 21, fontWeight: "900" },
  brandName: { color: "#fff", fontSize: 21, fontWeight: "800" },
  heading: { marginTop: 24, marginBottom: 18 },
  kicker: { color: "#f3b765", fontSize: 10, fontWeight: "800", letterSpacing: 1.5 },
  title: { marginTop: 9, maxWidth: 340, color: "#fff", fontSize: 28, lineHeight: 34, fontWeight: "800" },
  subtitle: { marginTop: 9, color: "#9fb0a7", fontSize: 13, lineHeight: 20 },
  card: { padding: 20, borderRadius: 18, backgroundColor: "#f7f7f3" },
  modeRow: { height: 42, marginBottom: 18, flexDirection: "row", padding: 3, borderRadius: 11, backgroundColor: "#e8ebe7" },
  modeButton: { flex: 1, alignItems: "center", justifyContent: "center", borderRadius: 9 },
  modeButtonActive: { backgroundColor: "#fff" },
  modeText: { color: "#7a847e", fontSize: 11, fontWeight: "800" },
  modeTextActive: { color: "#1d2a24" },
  label: { marginBottom: 7, color: "#5e6863", fontSize: 11, fontWeight: "700" },
  confirmLabel: { marginTop: 12 },
  input: { height: 48, marginBottom: 13, paddingHorizontal: 13, borderWidth: 1, borderColor: "#dde2dd", borderRadius: 11, backgroundColor: "#fff", color: "#17201d", fontSize: 14 },
  passwordRow: { height: 48, flexDirection: "row", alignItems: "center", marginBottom: 4, paddingHorizontal: 13, borderWidth: 1, borderColor: "#dde2dd", borderRadius: 11, backgroundColor: "#fff" },
  passwordInput: { flex: 1, color: "#17201d", fontSize: 14 },
  show: { color: "#287153", fontSize: 11, fontWeight: "800" },
  error: { marginTop: 10, color: "#b54e43", fontSize: 11, lineHeight: 16 },
  button: { height: 49, alignItems: "center", justifyContent: "center", marginTop: 17, borderRadius: 11, backgroundColor: "#f3a952" },
  buttonPressed: { opacity: 0.88 },
  buttonDisabled: { opacity: 0.6 },
  buttonText: { color: "#172820", fontSize: 14, fontWeight: "900" },
  help: { marginTop: 13, color: "#8a918d", textAlign: "center", fontSize: 10, lineHeight: 15 },
  cloud: { marginTop: 18, color: "#7fa993", textAlign: "center", fontSize: 10, fontWeight: "700" },
});
