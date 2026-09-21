import { useRef, useState } from "react";
import type { ComponentProps } from "react";
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Linking,
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { normalizeLoginIdentifier, normalizeUsername, supabase } from "../lib/supabase";
import { retryTransientSupabaseOperation } from "../lib/auth-retry";
import { CURRENT_UGC_TERMS_VERSION } from "../lib/ugc";
import TermsModal from "../components/TermsModal";

type Mode = "signIn" | "register";
type RecoveryStage = "request" | "verify" | "complete";

const privacyUrl = "https://stokdas.tirtarhan.chatgpt.site/gizlilik";

export default function LoginScreen() {
  const [mode, setMode] = useState<Mode>("signIn");
  const [organizationName, setOrganizationName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [recoveryEmail, setRecoveryEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passwordAgain, setPasswordAgain] = useState("");
  const [verificationUsername, setVerificationUsername] = useState("");
  const [verificationPassword, setVerificationPassword] = useState("");
  const [maskedEmail, setMaskedEmail] = useState<string | null>(null);
  const [verificationCode, setVerificationCode] = useState("");
  const [recoveryStage, setRecoveryStage] = useState<RecoveryStage | null>(null);
  const [recoveryIdentifier, setRecoveryIdentifier] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [resetTicket, setResetTicket] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPasswordAgain, setNewPasswordAgain] = useState("");
  const [secure, setSecure] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [registrationTermsAccepted, setRegistrationTermsAccepted] = useState(false);
  const [termsModal, setTermsModal] = useState(false);
  const signInInFlight = useRef(false);

  const isRegister = mode === "register";
  const isVerification = Boolean(verificationUsername);

  function switchMode(nextMode: Mode) {
    setMode(nextMode);
    setError("");
    setNotice("");
    setPassword("");
    setPasswordAgain("");
    setVerificationUsername("");
    setVerificationPassword("");
    setVerificationCode("");
    setMaskedEmail(null);
    setRecoveryStage(null);
    setRecoveryCode("");
    setResetTicket("");
    setNewPassword("");
    setNewPasswordAgain("");
    setRegistrationTermsAccepted(false);
  }

  async function useSession(data: unknown) {
    const session = (data as {
      session?: { access_token?: string; refresh_token?: string };
    } | null)?.session;
    if (!session?.access_token || !session.refresh_token) {
      setError("Giriş oturumu alınamadı. Lütfen tekrar deneyin.");
      return false;
    }

    const { data: sessionData, error: sessionError } = await retryTransientSupabaseOperation(
      () => supabase.auth.setSession({
        access_token: session.access_token as string,
        refresh_token: session.refresh_token as string,
      }),
    );
    if (sessionError) {
      setError(friendlyError(sessionError.message));
      return false;
    }
    if (!sessionData.session) {
      setError("Giriş oturumu alınamadı. Lütfen tekrar deneyin.");
      return false;
    }
    return true;
  }

  async function signIn() {
    if (signInInFlight.current) return;

    const normalizedIdentifier = normalizeLoginIdentifier(username);
    if (!normalizedIdentifier || !password) {
      setError("Geçerli kullanıcı adı veya e-posta ile şifrenizi girin.");
      return;
    }

    signInInFlight.current = true;
    setLoading(true);
    setError("");
    setNotice("");

    try {
      const { data, error: authError } = await supabase.functions.invoke("username-login", {
        body: { username: normalizedIdentifier, password },
      });
      if (authError) {
        const details = await edgeFunctionErrorDetails(authError);
        if (details.code === "EMAIL_VERIFICATION_REQUIRED") {
          const pendingUsername = details.username
            ?? (normalizedIdentifier.includes("@") ? "" : normalizeUsername(normalizedIdentifier));
          if (!pendingUsername) {
            setError("E-posta doğrulaması için kullanıcı adı alınamadı. Lütfen tekrar deneyin.");
            return;
          }
          setVerificationUsername(pendingUsername);
          setVerificationPassword(password);
          setMaskedEmail(details.maskedEmail ?? null);
          setVerificationCode("");
          setError("");
          return;
        }
        setError(friendlyError(details.message));
        return;
      }
      await useSession(data);
    } catch {
      setError("Giriş tamamlanamadı. Lütfen tekrar deneyin.");
    } finally {
      signInInFlight.current = false;
      setLoading(false);
    }
  }

  async function registerBusiness() {
    const normalizedUsername = normalizeUsername(username);
    const normalizedEmail = recoveryEmail.trim().toLowerCase();
    if (organizationName.trim().length < 2) {
      setError("İşletme adı en az 2 karakter olmalı.");
      return;
    }
    if (!displayName.trim()) {
      setError("Adınızı ve soyadınızı girin.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      setError("Geçerli bir e-posta adresi girin.");
      return;
    }
    if (normalizedUsername.length < 3) {
      setError("Kullanıcı adı en az 3 karakter olmalı.");
      return;
    }
    if (!isStrongPassword(password)) {
      setError("Şifre 8–72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli.");
      return;
    }
    if (password !== passwordAgain) {
      setError("Şifreler eşleşmiyor.");
      return;
    }
    if (!registrationTermsAccepted) {
      setError("İşletme hesabı oluşturmak için Kullanım Koşulları ve Topluluk Kuralları’nı kabul edin.");
      return;
    }

    setLoading(true);
    setError("");
    setNotice("");
    const { error: registrationError } = await supabase.functions.invoke("register-business", {
      body: {
        organizationName: organizationName.trim(),
        displayName: displayName.trim(),
        username: normalizedUsername,
        recoveryEmail: normalizedEmail,
        password,
        ugcTermsAccepted: true,
        ugcTermsVersion: CURRENT_UGC_TERMS_VERSION,
      },
    });
    setLoading(false);
    if (registrationError) {
      setError(await edgeFunctionError(registrationError));
      return;
    }

    setVerificationUsername(normalizedUsername);
    setVerificationPassword(password);
    setMaskedEmail(null);
    setVerificationCode("");
  }

  async function verifyEmail() {
    const code = verificationCode.replace(/\s/g, "");
    if (!/^[0-9]{6,10}$/.test(code)) {
      setError("E-postanıza gelen doğrulama kodunu eksiksiz girin.");
      return;
    }
    setLoading(true);
    setError("");
    const { data, error: verificationError } = await supabase.functions.invoke("verify-email-code", {
      body: { username: verificationUsername, code },
    });
    setLoading(false);
    if (verificationError) {
      setError(await edgeFunctionError(verificationError));
      return;
    }
    await useSession(data);
  }

  async function resendVerification() {
    if (!verificationUsername || !verificationPassword) return;
    setLoading(true);
    setError("");
    setNotice("");
    const { data, error: resendError } = await supabase.functions.invoke("resend-email-code", {
      body: { username: verificationUsername, password: verificationPassword },
    });
    setLoading(false);
    if (resendError) {
      setError(await edgeFunctionError(resendError));
      return;
    }
    setMaskedEmail(data?.maskedEmail ?? maskedEmail);
    setNotice(data?.message ?? "Yeni kod e-posta adresinize gönderildi.");
  }

  async function requestPasswordReset() {
    if (!recoveryIdentifier.trim()) {
      setError("Kullanıcı adınızı veya e-posta adresinizi girin.");
      return;
    }
    setLoading(true);
    setError("");
    setNotice("");
    const { error: requestError } = await supabase.functions.invoke("request-password-reset", {
      body: { identifier: recoveryIdentifier.trim() },
    });
    setLoading(false);
    if (requestError) {
      setError(await edgeFunctionError(requestError));
      return;
    }
    setRecoveryStage("verify");
  }

  async function verifyPasswordReset() {
    const code = recoveryCode.replace(/\s/g, "");
    if (!/^[0-9]{6,10}$/.test(code)) {
      setError("E-postanıza gelen kodu eksiksiz girin.");
      return;
    }
    setLoading(true);
    setError("");
    const { data, error: verificationError } = await supabase.functions.invoke("verify-password-reset-code", {
      body: { identifier: recoveryIdentifier.trim(), code },
    });
    setLoading(false);
    if (verificationError) {
      setError(await edgeFunctionError(verificationError));
      return;
    }
    if (!data?.resetTicket) {
      setError("Şifre yenileme bileti alınamadı. Yeni bir kod isteyin.");
      return;
    }
    setResetTicket(data.resetTicket);
    setRecoveryStage("complete");
  }

  async function completePasswordReset() {
    if (!isStrongPassword(newPassword)) {
      setError("Şifre 8–72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli.");
      return;
    }
    if (newPassword !== newPasswordAgain) {
      setError("Şifreler eşleşmiyor.");
      return;
    }
    setLoading(true);
    setError("");
    const { data, error: completionError } = await supabase.functions.invoke("complete-password-reset", {
      body: { resetTicket, newPassword },
    });
    setLoading(false);
    if (completionError) {
      setError(await edgeFunctionError(completionError));
      return;
    }
    if (
      !data?.updated || data.reauthenticationRequired !== true
      || typeof data.username !== "string" || !data.username
    ) {
      setError("Şifre yenilendi ancak giriş bilgisi alınamadı. Destek ile iletişime geçin.");
      return;
    }
    setRecoveryStage(null);
    setRecoveryCode("");
    setResetTicket("");
    setNewPassword("");
    setNewPasswordAgain("");
    setMode("signIn");
    setUsername(data.username);
    setPassword("");
    setNotice(data.accountLocksCleared === false
      ? `Şifreniz yenilendi. Kullanıcı adınız ${data.username}. Hesaba özel güvenlik kilidi en geç 15 dakika içinde kalkınca giriş yapın.`
      : `Şifreniz yenilendi. Kullanıcı adınız ${data.username}; yeni şifrenizle giriş yapmayı deneyin.`);
  }

  const kicker = isVerification ? "E-POSTA DOĞRULAMASI"
    : recoveryStage ? "ŞİFRE KURTARMA"
    : isRegister ? "YENİ İŞLETME" : "BULUT STOK TAKİBİ";
  const title = isVerification ? "Doğrulama kodunu gir."
    : recoveryStage === "request" ? "Hesabını bul."
    : recoveryStage === "verify" ? "Kurtarma kodunu gir."
    : recoveryStage === "complete" ? "Yeni şifreni belirle."
    : isRegister ? "İşletmeni Stokdaş'a taşı." : "Ekibinle aynı stokta buluş.";
  const subtitle = isVerification
    ? `${maskedEmail ? `${maskedEmail} adresine` : "E-posta adresinize"} gönderilen kodla hesabınızı etkinleştirin.`
    : recoveryStage === "request" ? "Kullanıcı adınızı veya doğrulanmış e-posta adresinizi girin."
    : recoveryStage === "verify" ? "Doğrulanmış e-posta adresinize gönderilen kodu girin."
    : recoveryStage === "complete" ? "Yeni şifreniz diğer açık oturumları güvenli biçimde kapatacak."
    : isRegister ? "İşletme hesabını oluştur, e-postanı doğrula ve ekibinle ortak kullanmaya başla."
    : "Ürün giriş ve çıkışları, kritik stoklar ve tüm ekip hareketleri tek yerde.";

  return (
    <SafeAreaView style={styles.safe} edges={["top", "bottom"]}>
      <KeyboardAvoidingView style={styles.container} behavior={Platform.OS === "ios" ? "padding" : undefined}>
        <ScrollView contentContainerStyle={styles.content} keyboardShouldPersistTaps="handled" showsVerticalScrollIndicator={false}>
          <View style={styles.brand}>
            <View style={styles.logo}><Text style={styles.logoText}>S</Text></View>
            <Text style={styles.brandName}>Stokdaş</Text>
          </View>
          <View style={styles.heading}>
            <Text style={styles.kicker}>{kicker}</Text>
            <Text style={styles.title}>{title}</Text>
            <Text style={styles.subtitle}>{subtitle}</Text>
          </View>
          <View style={styles.card}>
            {isVerification ? (
              <>
                <Field label="Doğrulama kodu" value={verificationCode} onChangeText={(value) => setVerificationCode(value.replace(/\D/g, ""))} placeholder="000000" keyboardType="number-pad" textContentType="oneTimeCode" maxLength={10} autoFocus />
                <Message error={error} notice={notice} />
                <PrimaryButton label="Hesabı doğrula ve devam et" loading={loading} onPress={verifyEmail} />
                <View style={styles.secondaryRow}>
                  <SecondaryButton label="Kodu yeniden gönder" disabled={loading} onPress={resendVerification} />
                  <SecondaryButton label="Girişe dön" disabled={loading} onPress={() => switchMode("signIn")} />
                </View>
              </>
            ) : recoveryStage ? (
              <>
                {recoveryStage === "request" ? <Field label="Kullanıcı adı veya e-posta" value={recoveryIdentifier} onChangeText={setRecoveryIdentifier} placeholder="kullaniciadi veya ornek@email.com" autoCapitalize="none" autoCorrect={false} textContentType="username" autoFocus /> : null}
                {recoveryStage === "verify" ? <Field label="Kurtarma kodu" value={recoveryCode} onChangeText={(value) => setRecoveryCode(value.replace(/\D/g, ""))} placeholder="000000" keyboardType="number-pad" textContentType="oneTimeCode" maxLength={10} autoFocus /> : null}
                {recoveryStage === "complete" ? <>
                  <Field label="Yeni şifre" value={newPassword} onChangeText={setNewPassword} placeholder="Güçlü şifre" secureTextEntry textContentType="newPassword" autoFocus />
                  <Field label="Yeni şifre tekrarı" value={newPasswordAgain} onChangeText={setNewPasswordAgain} placeholder="Tekrar gir" secureTextEntry textContentType="newPassword" />
                </> : null}
                <Message error={error} notice={notice} />
                <PrimaryButton label={recoveryStage === "request" ? "Kurtarma kodu gönder" : recoveryStage === "verify" ? "Kodu doğrula" : "Şifreyi yenile"} loading={loading} onPress={recoveryStage === "request" ? requestPasswordReset : recoveryStage === "verify" ? verifyPasswordReset : completePasswordReset} />
                <SecondaryButton label="Girişe dön" disabled={loading} onPress={() => switchMode("signIn")} full />
              </>
            ) : (
              <>
                <View style={styles.modeRow}>
                  <Pressable style={[styles.modeButton, !isRegister && styles.modeButtonActive]} onPress={() => switchMode("signIn")} disabled={loading}>
                    <Text style={[styles.modeText, !isRegister && styles.modeTextActive]}>Giriş yap</Text>
                  </Pressable>
                  <Pressable style={[styles.modeButton, isRegister && styles.modeButtonActive]} onPress={() => switchMode("register")} disabled={loading}>
                    <Text style={[styles.modeText, isRegister && styles.modeTextActive]}>Yeni işletme</Text>
                  </Pressable>
                </View>

                {isRegister ? <>
                  <Field label="İşletme adı" value={organizationName} onChangeText={setOrganizationName} placeholder="İşletme adını girin" autoCapitalize="words" />
                  <Field label="Ad ve soyad" value={displayName} onChangeText={setDisplayName} placeholder="Örn. İsmail Tırtar" autoCapitalize="words" textContentType="name" />
                  <Field label="E-posta" value={recoveryEmail} onChangeText={setRecoveryEmail} placeholder="ornek@email.com" autoCapitalize="none" autoCorrect={false} keyboardType="email-address" textContentType="emailAddress" />
                </> : null}

                <Field
                  label={isRegister ? "Kullanıcı adı" : "Kullanıcı adı veya e-posta"}
                  value={username}
                  onChangeText={setUsername}
                  placeholder={isRegister ? "örn. ismail" : "kullaniciadi veya ornek@email.com"}
                  autoCapitalize="none"
                  autoCorrect={false}
                  textContentType="username"
                />
                <Text style={styles.label}>Şifre</Text>
                <View style={styles.passwordRow}>
                  <TextInput style={styles.passwordInput} value={password} onChangeText={setPassword} placeholder="En az 8 karakter" placeholderTextColor="#98a09b" secureTextEntry={secure} textContentType={isRegister ? "newPassword" : "password"} onSubmitEditing={isRegister ? undefined : signIn} returnKeyType={isRegister ? "next" : "done"} />
                  <Pressable onPress={() => setSecure((value) => !value)} hitSlop={10}><Text style={styles.show}>{secure ? "Göster" : "Gizle"}</Text></Pressable>
                </View>
                {isRegister ? <Field label="Şifre tekrar" value={passwordAgain} onChangeText={setPasswordAgain} placeholder="Şifreyi yeniden gir" secureTextEntry={secure} textContentType="newPassword" onSubmitEditing={registerBusiness} returnKeyType="done" /> : null}

                {isRegister ? (
                  <View style={styles.termsConsentBox}>
                    <Pressable
                      accessibilityRole="checkbox"
                      accessibilityState={{ checked: registrationTermsAccepted, disabled: loading }}
                      accessibilityLabel="Kullanım Koşulları ve Topluluk Kurallarını kabul ediyorum"
                      style={styles.termsConsentRow}
                      onPress={() => setRegistrationTermsAccepted((value) => !value)}
                      disabled={loading}
                    >
                      <View style={[styles.checkbox, registrationTermsAccepted && styles.checkboxChecked]}>{registrationTermsAccepted ? <Text style={styles.checkmark}>✓</Text> : null}</View>
                      <Text style={styles.termsConsentText}>Kullanım Koşulları ve Topluluk Kuralları’nı okudum, kabul ediyorum.</Text>
                    </Pressable>
                    <Pressable accessibilityRole="button" style={styles.termsLinkButton} onPress={() => setTermsModal(true)}>
                      <Text style={styles.termsLinkText}>Koşulları aç ve incele</Text>
                    </Pressable>
                  </View>
                ) : null}

                <Message error={error} notice={notice} />
                <PrimaryButton label={isRegister ? "İşletme hesabını oluştur" : "Giriş yap"} loading={loading} disabled={isRegister && !registrationTermsAccepted} onPress={isRegister ? registerBusiness : signIn} />
                {!isRegister ? <Pressable style={styles.linkButton} onPress={() => { setRecoveryIdentifier(username); setRecoveryStage("request"); setError(""); setNotice(""); }}><Text style={styles.linkText}>Şifremi unuttum</Text></Pressable> : null}
                {isRegister ? <Text style={styles.help}>Hesabınız etkinleştirildikten sonra güncel koşul kabulü güvenli biçimde hesabınıza kaydedilir.</Text> : <Text style={styles.help}>Çalışan hesabınızı işletme yöneticiniz oluşturur.</Text>}
                <View style={styles.policyLinks}>
                  <Pressable accessibilityRole="link" style={styles.privacyButton} onPress={() => setTermsModal(true)}><Text style={styles.privacyText}>Kullanım koşulları</Text></Pressable>
                  <Pressable accessibilityRole="link" style={styles.privacyButton} onPress={() => void Linking.openURL(privacyUrl)}><Text style={styles.privacyText}>Gizlilik politikası</Text></Pressable>
                </View>
              </>
            )}
          </View>
          <Text style={styles.cloud}>● Frankfurt sunucusuna bağlı</Text>
        </ScrollView>
      </KeyboardAvoidingView>
      <TermsModal
        visible={termsModal}
        mandatory={false}
        accepted={false}
        reviewOnly
        onAccept={() => undefined}
        onClose={() => setTermsModal(false)}
      />
    </SafeAreaView>
  );
}

function Field(props: ComponentProps<typeof TextInput> & { label: string }) {
  const { label, ...inputProps } = props;
  return <View style={styles.field}><Text style={styles.label}>{label}</Text><TextInput style={styles.input} placeholderTextColor="#98a09b" {...inputProps} /></View>;
}

function Message({ error, notice }: { error: string; notice: string }) {
  return <>{error ? <Text style={styles.error}>{error}</Text> : null}{notice ? <Text style={styles.notice}>{notice}</Text> : null}</>;
}

function PrimaryButton({ label, loading, disabled = false, onPress }: { label: string; loading: boolean; disabled?: boolean; onPress: () => void | Promise<void> }) {
  const unavailable = loading || disabled;
  return <Pressable accessibilityRole="button" accessibilityState={{ disabled: unavailable, busy: loading }} style={({ pressed }) => [styles.button, pressed && styles.buttonPressed, unavailable && styles.buttonDisabled]} onPress={() => void onPress()} disabled={unavailable}>{loading ? <ActivityIndicator color="#172820" /> : <Text style={styles.buttonText}>{label}</Text>}</Pressable>;
}

function SecondaryButton({ label, disabled, onPress, full = false }: { label: string; disabled: boolean; onPress: () => void | Promise<void>; full?: boolean }) {
  return <Pressable style={[styles.secondaryButton, full && styles.secondaryFull, disabled && styles.buttonDisabled]} onPress={() => void onPress()} disabled={disabled}><Text style={styles.secondaryText}>{label}</Text></Pressable>;
}

type EdgeFunctionErrorDetails = { message: string; code?: string; username?: string; maskedEmail?: string | null };

async function edgeFunctionErrorDetails(error: unknown): Promise<EdgeFunctionErrorDetails> {
  const candidate = error as { context?: Response; message?: string };
  try {
    const body = await candidate.context?.json() as { error?: string; code?: string; errorCode?: string; username?: string; maskedEmail?: string | null } | undefined;
    if (body?.error) return { message: body.error, code: body.errorCode ?? body.code, username: body.username, maskedEmail: body.maskedEmail };
  } catch {
    // Yanıt gövdesi yoksa istemci mesajına dönülür.
  }
  return { message: candidate.message ?? "İşlem tamamlanamadı." };
}

async function edgeFunctionError(error: unknown) {
  return (await edgeFunctionErrorDetails(error)).message;
}

function friendlyError(message: string) {
  if (message.includes("Invalid login credentials")) return "Kullanıcı adı veya şifre hatalı.";
  if (message.includes("JWT") || message.includes("session")) return "Oturum süresi doldu. Lütfen yeniden giriş yapın.";
  return message;
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
  field: { marginBottom: 13 },
  label: { marginBottom: 7, color: "#5e6863", fontSize: 11, fontWeight: "700" },
  input: { height: 48, paddingHorizontal: 13, borderWidth: 1, borderColor: "#dde2dd", borderRadius: 11, backgroundColor: "#fff", color: "#17201d", fontSize: 14 },
  passwordRow: { height: 48, flexDirection: "row", alignItems: "center", marginBottom: 13, paddingHorizontal: 13, borderWidth: 1, borderColor: "#dde2dd", borderRadius: 11, backgroundColor: "#fff" },
  passwordInput: { flex: 1, color: "#17201d", fontSize: 14 },
  show: { color: "#287153", fontSize: 11, fontWeight: "800" },
  error: { marginTop: 2, color: "#b54e43", fontSize: 11, lineHeight: 16 },
  notice: { marginTop: 7, color: "#287153", fontSize: 11, lineHeight: 16 },
  button: { height: 49, alignItems: "center", justifyContent: "center", marginTop: 17, borderRadius: 11, backgroundColor: "#f3a952" },
  buttonPressed: { opacity: 0.88 },
  buttonDisabled: { opacity: 0.55 },
  buttonText: { color: "#172820", fontSize: 14, fontWeight: "900" },
  secondaryRow: { marginTop: 10, flexDirection: "row", gap: 9 },
  secondaryButton: { flex: 1, minHeight: 42, alignItems: "center", justifyContent: "center", paddingHorizontal: 8, borderWidth: 1, borderColor: "#d8ded8", borderRadius: 10, backgroundColor: "#fff" },
  secondaryFull: { flex: 0, marginTop: 10 },
  secondaryText: { color: "#426252", textAlign: "center", fontSize: 10, fontWeight: "800" },
  linkButton: { alignItems: "center", paddingTop: 14 },
  linkText: { color: "#287153", fontSize: 11, fontWeight: "800" },
  help: { marginTop: 13, color: "#8a918d", textAlign: "center", fontSize: 10, lineHeight: 15 },
  termsConsentBox: { marginTop: 3, padding: 11, borderWidth: 1, borderColor: "#dce2dc", borderRadius: 11, backgroundColor: "#fff" },
  termsConsentRow: { flexDirection: "row", alignItems: "flex-start" },
  checkbox: { width: 20, height: 20, marginRight: 9, alignItems: "center", justifyContent: "center", borderWidth: 1.5, borderColor: "#9ba59f", borderRadius: 6, backgroundColor: "#fff" },
  checkboxChecked: { borderColor: "#2e7657", backgroundColor: "#2e7657" },
  checkmark: { color: "#fff", fontSize: 13, fontWeight: "900" },
  termsConsentText: { flex: 1, color: "#5f6b64", fontSize: 10, lineHeight: 15 },
  termsLinkButton: { alignSelf: "flex-start", marginTop: 8, marginLeft: 29, paddingVertical: 2 },
  termsLinkText: { color: "#287153", fontSize: 10, fontWeight: "900", textDecorationLine: "underline" },
  policyLinks: { flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 18 },
  privacyButton: { alignItems: "center", paddingTop: 8 },
  privacyText: { color: "#3f6f5a", fontSize: 10, fontWeight: "800", textDecorationLine: "underline" },
  cloud: { marginTop: 18, color: "#7fa993", textAlign: "center", fontSize: 10, fontWeight: "700" },
});
