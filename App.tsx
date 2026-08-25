import { useEffect, useState } from "react";
import { ActivityIndicator, AppState, StyleSheet, Text, View } from "react-native";
import { SafeAreaProvider } from "react-native-safe-area-context";
import { StatusBar } from "expo-status-bar";
import type { Session } from "@supabase/supabase-js";
import { isCloudConfigured, supabase } from "./src/lib/supabase";
import LoginScreen from "./src/screens/LoginScreen";
import InventoryScreen from "./src/screens/InventoryScreen";

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!isCloudConfigured) { setLoading(false); return; }
    supabase.auth.getSession().then(({ data }) => { setSession(data.session); setLoading(false); });
    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => setSession(nextSession));
    return () => data.subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (!isCloudConfigured) return;
    const subscription = AppState.addEventListener("change", (state) => {
      if (state === "active") supabase.auth.startAutoRefresh();
      else supabase.auth.stopAutoRefresh();
    });
    return () => subscription.remove();
  }, []);

  return (
    <SafeAreaProvider>
      <StatusBar style="light" />
      {!isCloudConfigured ? <SetupRequired /> : loading ? <Loading /> : session ? <InventoryScreen session={session} /> : <LoginScreen />}
    </SafeAreaProvider>
  );
}

function Loading() {
  return <View style={styles.center}><ActivityIndicator size="large" color="#f3a952" /><Text style={styles.loading}>Bulut verileri hazırlanıyor…</Text></View>;
}

function SetupRequired() {
  return (
    <View style={styles.setup}>
      <View style={styles.logo}><Text style={styles.logoText}>S</Text></View>
      <Text style={styles.title}>Bulut bağlantısı bekleniyor</Text>
      <Text style={styles.body}>Uygulamanın çalışması için Supabase proje adresi ve yayımlanabilir anahtarının .env dosyasına eklenmesi gerekiyor.</Text>
      <View style={styles.code}><Text style={styles.codeText}>EXPO_PUBLIC_SUPABASE_URL{`\n`}EXPO_PUBLIC_SUPABASE_PUBLISHABLE_KEY</Text></View>
      <Text style={styles.note}>Ana hizmet anahtarını (service_role) kesinlikle uygulamaya eklemeyin.</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  center: { flex: 1, alignItems: "center", justifyContent: "center", backgroundColor: "#172820" },
  loading: { marginTop: 14, color: "#d8e4de", fontSize: 13 },
  setup: { flex: 1, justifyContent: "center", paddingHorizontal: 28, backgroundColor: "#172820" },
  logo: { width: 52, height: 52, borderRadius: 16, borderBottomLeftRadius: 5, alignItems: "center", justifyContent: "center", backgroundColor: "#f3a952" },
  logoText: { color: "#172820", fontSize: 27, fontWeight: "900" },
  title: { marginTop: 24, color: "#fff", fontSize: 27, fontWeight: "800" },
  body: { marginTop: 12, color: "#adbbb4", fontSize: 14, lineHeight: 22 },
  code: { marginTop: 22, padding: 16, borderRadius: 12, backgroundColor: "#243a30" },
  codeText: { color: "#f3c88c", fontFamily: "monospace", fontSize: 12, lineHeight: 21 },
  note: { marginTop: 14, color: "#80938a", fontSize: 11, lineHeight: 17 },
});
