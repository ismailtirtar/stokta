import { useEffect, useState } from "react";
import {
  ActivityIndicator,
  Linking,
  Pressable,
  SafeAreaView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { supabase } from "../lib/supabase";

type Props = {
  visible: boolean;
  onVerified: () => void;
  onSignOut: () => void;
};

type Mode = "loading" | "setup" | "enroll" | "challenge";

export default function PlatformMfaGate({ visible, onVerified, onSignOut }: Props) {
  const [mode, setMode] = useState<Mode>("loading");
  const [factorId, setFactorId] = useState("");
  const [secret, setSecret] = useState("");
  const [uri, setUri] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!visible) return;
    let active = true;
    setMode("loading");
    setFactorId("");
    setSecret("");
    setUri("");
    setCode("");
    setError("");

    void (async () => {
      const assurance = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
      if (!active) return;
      if (assurance.error) {
        setError("İki adımlı doğrulama durumu alınamadı. Bağlantınızı kontrol edip yeniden deneyin.");
        setMode("setup");
        return;
      }
      const factors = await supabase.auth.mfa.listFactors();
      if (!active) return;
      if (factors.error) {
        setError("Doğrulayıcı bilgileri alınamadı. Lütfen yeniden deneyin.");
        setMode("setup");
        return;
      }
      const verifiedTotp = factors.data.totp[0];
      if (verifiedTotp) {
        setFactorId(verifiedTotp.id);
        const hasTotpMethod = assurance.data.currentAuthenticationMethods.some((entry) => {
          const method = typeof entry === "string" ? entry : entry.method;
          return method === "totp" || method === "mfa/totp";
        });
        if (
          assurance.data.currentLevel === "aal2"
          && assurance.data.nextLevel === "aal2"
          && hasTotpMethod
        ) {
          onVerified();
        } else {
          setMode("challenge");
        }
      } else {
        setMode("setup");
      }
    })();

    return () => { active = false; };
  }, [onVerified, visible]);

  if (!visible) return null;

  async function beginEnrollment() {
    setBusy(true);
    setError("");
    try {
      const factors = await supabase.auth.mfa.listFactors();
      if (factors.error) throw factors.error;
      const verifiedTotp = factors.data.totp[0];
      if (verifiedTotp) {
        setFactorId(verifiedTotp.id);
        setMode("challenge");
        return;
      }
      const staleTotpFactors = factors.data.all.filter((factor) =>
        factor.factor_type === "totp" && factor.status === "unverified"
      );
      for (const factor of staleTotpFactors) {
        const removal = await supabase.auth.mfa.unenroll({ factorId: factor.id });
        if (removal.error) throw removal.error;
      }

      const enrollment = await supabase.auth.mfa.enroll({
        factorType: "totp",
        friendlyName: "Stokdaş Platform",
      });
      if (enrollment.error) throw enrollment.error;
      setFactorId(enrollment.data.id);
      setSecret(enrollment.data.totp.secret);
      setUri(enrollment.data.totp.uri);
      setMode("enroll");
    } catch (caught) {
      setError(mfaError(caught, "Kurulum başlatılamadı. Lütfen yeniden deneyin."));
    } finally {
      setBusy(false);
    }
  }

  async function verifyCode() {
    const normalizedCode = code.replace(/\D/g, "");
    if (!factorId || normalizedCode.length !== 6) {
      setError("Doğrulayıcı uygulamanızdaki 6 haneli kodu girin.");
      return;
    }

    setBusy(true);
    setError("");
    try {
      const challenge = await supabase.auth.mfa.challenge({ factorId });
      if (challenge.error) throw challenge.error;
      const verification = await supabase.auth.mfa.verify({
        factorId,
        challengeId: challenge.data.id,
        code: normalizedCode,
      });
      if (verification.error) throw verification.error;

      const assurance = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
      const hasTotpMethod = !assurance.error
        && assurance.data.currentAuthenticationMethods.some((entry) => {
          const method = typeof entry === "string" ? entry : entry.method;
          return method === "totp" || method === "mfa/totp";
        });
      if (
        assurance.error
        || assurance.data.currentLevel !== "aal2"
        || assurance.data.nextLevel !== "aal2"
        || !hasTotpMethod
      ) {
        throw new Error("AAL2_SESSION_REQUIRED");
      }
      setFactorId("");
      setSecret("");
      setUri("");
      setCode("");
      onVerified();
    } catch (caught) {
      setCode("");
      setError(mfaError(caught, "Kod doğrulanamadı. Yeni kodu kontrol edip yeniden deneyin."));
    } finally {
      setBusy(false);
    }
  }

  async function openAuthenticator() {
    if (!uri) return;
    try {
      await Linking.openURL(uri);
    } catch {
      setError("Doğrulayıcı uygulama açılamadı. Aşağıdaki kurulum anahtarını elle girin.");
    }
  }

  return (
    <SafeAreaView style={styles.safe}>
      <View style={styles.card}>
        <View style={styles.badge}><Text style={styles.badgeText}>PLATFORM GÜVENLİĞİ</Text></View>
        <Text style={styles.title}>İki adımlı doğrulama gerekli</Text>
        <Text style={styles.body}>
          Platform yönetimi yalnızca şifreniz ve doğrulayıcı uygulamanızla doğrulanmış AAL2 oturumunda açılır.
        </Text>

        {mode === "loading" ? (
          <View style={styles.loading}>
            <ActivityIndicator color="#f3a952" />
            <Text style={styles.loadingText}>Güvenli oturum kontrol ediliyor…</Text>
          </View>
        ) : null}

        {mode === "setup" ? (
          <View>
            <Text style={styles.stepTitle}>Doğrulayıcıyı kurun</Text>
            <Text style={styles.stepText}>Google Authenticator, Microsoft Authenticator veya uyumlu bir TOTP uygulaması kullanabilirsiniz.</Text>
            <Pressable style={[styles.primaryButton, busy && styles.disabled]} onPress={() => void beginEnrollment()} disabled={busy}>
              {busy ? <ActivityIndicator color="#172820" /> : <Text style={styles.primaryText}>Kurulumu başlat</Text>}
            </Pressable>
          </View>
        ) : null}

        {mode === "enroll" ? (
          <View>
            <Text style={styles.stepTitle}>Kurulum anahtarını ekleyin</Text>
            <Text style={styles.stepText}>Uygulamayı açın veya anahtarı yeni bir TOTP hesabına elle girin.</Text>
            <Pressable style={styles.secondaryButton} onPress={() => void openAuthenticator()} disabled={busy}>
              <Text style={styles.secondaryText}>Doğrulayıcı uygulamada aç</Text>
            </Pressable>
            <View style={styles.secretBox}>
              <Text style={styles.secretLabel}>KURULUM ANAHTARI</Text>
              <Text style={styles.secret} selectable>{secret}</Text>
            </View>
            <Text style={styles.recoveryText}>
              Supabase bu sürümde kurtarma kodu üretmez. Bu anahtarı ana telefonunuzdan ayrı, güvenli bir parola yöneticisinde saklayın.
            </Text>
            <CodeInput code={code} setCode={setCode} busy={busy} />
            <VerifyButton busy={busy} onPress={verifyCode} />
          </View>
        ) : null}

        {mode === "challenge" ? (
          <View>
            <Text style={styles.stepTitle}>Oturumu doğrulayın</Text>
            <Text style={styles.stepText}>Doğrulayıcı uygulamanızdaki güncel 6 haneli kodu girin.</Text>
            <CodeInput code={code} setCode={setCode} busy={busy} />
            <VerifyButton busy={busy} onPress={verifyCode} />
          </View>
        ) : null}

        {error ? <Text accessibilityRole="alert" style={styles.error}>{error}</Text> : null}
        {mode !== "loading" ? (
          <Pressable style={styles.signOutButton} onPress={onSignOut} disabled={busy}>
            <Text style={styles.signOutText}>Çıkış yap</Text>
          </Pressable>
        ) : null}
      </View>
    </SafeAreaView>
  );
}

function CodeInput({ code, setCode, busy }: { code: string; setCode: (value: string) => void; busy: boolean }) {
  return (
    <TextInput
      style={styles.input}
      value={code}
      onChangeText={(value) => setCode(value.replace(/\D/g, "").slice(0, 6))}
      placeholder="000000"
      placeholderTextColor="#80938a"
      keyboardType="number-pad"
      textContentType="oneTimeCode"
      autoComplete="one-time-code"
      maxLength={6}
      editable={!busy}
      accessibilityLabel="Doğrulayıcı uygulama kodu"
    />
  );
}

function VerifyButton({ busy, onPress }: { busy: boolean; onPress: () => Promise<void> }) {
  return (
    <Pressable style={[styles.primaryButton, busy && styles.disabled]} onPress={() => void onPress()} disabled={busy}>
      {busy ? <ActivityIndicator color="#172820" /> : <Text style={styles.primaryText}>Doğrula ve devam et</Text>}
    </Pressable>
  );
}

function mfaError(error: unknown, fallback: string) {
  const message = error instanceof Error ? error.message : "";
  if (/invalid.*code|challenge|factor/i.test(message)) return "Kod doğrulanamadı. Doğrulayıcıdaki güncel kodu girin.";
  if (/aal2_session_required/i.test(message)) return "Oturum AAL2 düzeyine yükseltilemedi. Yeniden giriş yapıp tekrar deneyin.";
  return fallback;
}

const styles = StyleSheet.create({
  safe: { ...StyleSheet.absoluteFillObject, zIndex: 1000, alignItems: "center", justifyContent: "center", padding: 22, backgroundColor: "#172820" },
  card: { width: "100%", maxWidth: 520, padding: 22, borderRadius: 22, backgroundColor: "#f8f8f5" },
  badge: { alignSelf: "flex-start", paddingHorizontal: 9, paddingVertical: 6, borderRadius: 20, backgroundColor: "#e8eef8" },
  badgeText: { color: "#46658e", fontSize: 8, fontWeight: "900", letterSpacing: .8 },
  title: { marginTop: 17, color: "#1b2721", fontSize: 24, fontWeight: "900" },
  body: { marginTop: 9, color: "#617068", fontSize: 12, lineHeight: 19 },
  loading: { minHeight: 150, alignItems: "center", justifyContent: "center" },
  loadingText: { marginTop: 11, color: "#748078", fontSize: 10 },
  stepTitle: { marginTop: 22, color: "#25342d", fontSize: 14, fontWeight: "900" },
  stepText: { marginTop: 7, color: "#707b75", fontSize: 10, lineHeight: 16 },
  primaryButton: { minHeight: 50, marginTop: 16, alignItems: "center", justifyContent: "center", borderRadius: 12, backgroundColor: "#f3a952" },
  primaryText: { color: "#172820", fontSize: 11, fontWeight: "900" },
  secondaryButton: { minHeight: 44, marginTop: 13, alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "#cfd8d2", borderRadius: 11, backgroundColor: "#fff" },
  secondaryText: { color: "#2d6d52", fontSize: 10, fontWeight: "900" },
  secretBox: { marginTop: 12, padding: 13, borderRadius: 11, backgroundColor: "#eaf0ec" },
  secretLabel: { color: "#668074", fontSize: 8, fontWeight: "900", letterSpacing: .7 },
  secret: { marginTop: 7, color: "#172820", fontFamily: "monospace", fontSize: 13, lineHeight: 19 },
  recoveryText: { marginTop: 10, color: "#8c632c", fontSize: 9, lineHeight: 15 },
  input: { height: 54, marginTop: 14, paddingHorizontal: 16, borderWidth: 1, borderColor: "#ccd5cf", borderRadius: 12, backgroundColor: "#fff", color: "#172820", textAlign: "center", fontSize: 23, fontWeight: "800", letterSpacing: 7 },
  error: { marginTop: 13, padding: 11, borderRadius: 10, backgroundColor: "#fae8e4", color: "#93483f", fontSize: 10, lineHeight: 16 },
  signOutButton: { minHeight: 42, marginTop: 9, alignItems: "center", justifyContent: "center" },
  signOutText: { color: "#69766f", fontSize: 10, fontWeight: "800" },
  disabled: { opacity: .55 },
});
