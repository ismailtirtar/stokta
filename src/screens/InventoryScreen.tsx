import { useCallback, useEffect, useMemo, useState } from "react";
import type { ComponentProps } from "react";
import type { Session } from "@supabase/supabase-js";
import {
  ActivityIndicator,
  Alert,
  FlatList,
  Keyboard,
  KeyboardAvoidingView,
  Modal,
  Platform,
  Pressable,
  RefreshControl,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { normalizeUsername, supabase } from "../lib/supabase";
import { retryTransientSupabaseOperation } from "../lib/auth-retry";
import AccountModal from "../components/AccountModal";
import ContentReportModal from "../components/ContentReportModal";
import ForcedPasswordChange from "../components/ForcedPasswordChange";
import PlatformMfaGate from "../components/PlatformMfaGate";
import PlatformModal from "../components/PlatformModal";
import SafetyCenterModal from "../components/SafetyCenterModal";
import SubscriptionModal from "../components/SubscriptionModal";
import TermsModal from "../components/TermsModal";
import { CURRENT_UGC_TERMS_VERSION } from "../lib/ugc";
import type {
  ContentReportReason,
  ContentReportTarget,
  Movement,
  Product,
  ProductDraft,
  ProfileRole,
} from "../types";

const emptyDraft: ProductDraft = { name: "", sku: "", category: "Genel", unit: "adet", stock: "0", minStock: "0" };
const numberFormatter = new Intl.NumberFormat("tr-TR", { maximumFractionDigits: 3 });

export default function InventoryScreen({ session }: { session: Session }) {
  const [products, setProducts] = useState<Product[]>([]);
  const [movements, setMovements] = useState<Movement[]>([]);
  const [displayName, setDisplayName] = useState(session.user.email?.split("@")[0] ?? "Kullanıcı");
  const [username, setUsername] = useState(session.user.email?.split("@")[0] ?? "");
  const [role, setRole] = useState<ProfileRole | null>(null);
  const [organizationId, setOrganizationId] = useState("");
  const [organizationName, setOrganizationName] = useState("İşletme");
  const [subscriptionStatus, setSubscriptionStatus] = useState("active");
  const [trialEndsAt, setTrialEndsAt] = useState<string | null>(null);
  const [currentPeriodEnd, setCurrentPeriodEnd] = useState<string | null>(null);
  const [isPlatformOperator, setIsPlatformOperator] = useState(false);
  const [platformMfaVerifiedToken, setPlatformMfaVerifiedToken] = useState<string | null>(null);
  const [mustChangePassword, setMustChangePassword] = useState(false);
  const [termsChecked, setTermsChecked] = useState(false);
  const [serverTermsVersion, setServerTermsVersion] = useState<string | null>(null);
  const [acceptedTermsVersion, setAcceptedTermsVersion] = useState<string | null>(null);
  const [termsError, setTermsError] = useState("");
  const [acceptingTerms, setAcceptingTerms] = useState(false);
  const [reviewTermsModal, setReviewTermsModal] = useState(false);
  const [search, setSearch] = useState("");
  const [onlyLow, setOnlyLow] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [productModal, setProductModal] = useState(false);
  const [movementModal, setMovementModal] = useState(false);
  const [coworkerModal, setCoworkerModal] = useState(false);
  const [accountModal, setAccountModal] = useState(false);
  const [subscriptionModal, setSubscriptionModal] = useState(false);
  const [platformModal, setPlatformModal] = useState(false);
  const [safetyCenterModal, setSafetyCenterModal] = useState(false);
  const [safetyCenterScope, setSafetyCenterScope] = useState<"organization" | "platform">("organization");
  const [reportTarget, setReportTarget] = useState<ContentReportTarget | null>(null);
  const [reportSaving, setReportSaving] = useState(false);
  const [reportError, setReportError] = useState("");
  const [editing, setEditing] = useState<Product | null>(null);
  const [selectedProduct, setSelectedProduct] = useState<Product | null>(null);
  const [draft, setDraft] = useState<ProductDraft>(emptyDraft);
  const [movementType, setMovementType] = useState<"in" | "out">("out");
  const [quantity, setQuantity] = useState("");
  const [note, setNote] = useState("");
  const [coworkerName, setCoworkerName] = useState("");
  const [coworkerUsername, setCoworkerUsername] = useState("");
  const [coworkerEmail, setCoworkerEmail] = useState("");
  const [coworkerPassword, setCoworkerPassword] = useState("");
  const [coworkerPasswordAgain, setCoworkerPasswordAgain] = useState("");
  const [saving, setSaving] = useState(false);

  const handlePlatformMfaVerified = useCallback(
    () => setPlatformMfaVerifiedToken(session.access_token),
    [session.access_token],
  );

  const loadData = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    const profileResult = await retryTransientSupabaseOperation(() => supabase
      .from("profiles")
      .select("display_name, username, role, organization_id, is_platform_operator, must_change_password, ugc_terms_version, organizations(name, subscription_status, trial_ends_at, current_period_end)")
      .eq("id", session.user.id)
      .maybeSingle());

    if (profileResult.error || !profileResult.data?.organization_id) {
      const profileError = profileResult.error?.message ?? "İşletme profili bulunamadı.";
      setError(profileError);
      setTermsError(profileError);
      setTermsChecked(false);
      setLoading(false);
      setRefreshing(false);
      return;
    }

    if (profileResult.data.must_change_password) {
      setMustChangePassword(true);
      setLoading(false);
      setRefreshing(false);
      return;
    }
    setMustChangePassword(false);

    const termsResult = await supabase.rpc("get_ugc_terms_status");
    if (termsResult.error || !termsResult.data) {
      const statusError = termsResult.error?.message ?? "Kullanım koşulları durumu alınamadı.";
      setTermsError(statusError);
      setTermsChecked(false);
      setLoading(false);
      setRefreshing(false);
      return;
    }
    const termsStatus = termsResult.data as {
      current_version?: string;
      accepted_version?: string | null;
      accepted_at?: string | null;
      accepted?: boolean;
    };
    const nextServerTermsVersion = termsStatus.current_version ?? null;
    setServerTermsVersion(nextServerTermsVersion);
    setAcceptedTermsVersion(termsStatus.accepted_version ?? null);
    setTermsChecked(true);
    setTermsError(nextServerTermsVersion === CURRENT_UGC_TERMS_VERSION
      ? ""
      : "Kullanım koşulları güncellendi. Devam etmek için Stokdaş'ın güncel sürümünü yükleyin.");

    const profileOrganization = Array.isArray(profileResult.data.organizations)
      ? profileResult.data.organizations[0]
      : profileResult.data.organizations;
    const nextOrganizationId = profileResult.data.organization_id as string;
    const [productResult, movementResult] = await Promise.all([
      supabase.from("products")
        .select("id,name,sku,category,unit,stock,min_stock,active,created_at,updated_at")
        .eq("organization_id", nextOrganizationId)
        .eq("active", true)
        .order("name"),
      supabase.from("stock_movements")
        .select("id,product_id,type,quantity,previous_stock,new_stock,note,actor_id,actor_name,created_at,products(name,unit)")
        .eq("organization_id", nextOrganizationId)
        .order("created_at", { ascending: false })
        .limit(30),
    ]);

    const firstError = productResult.error ?? movementResult.error;
    if (firstError) setError(firstError.message);
    else {
      setProducts((productResult.data ?? []).map((item) => ({ ...item, stock: Number(item.stock), min_stock: Number(item.min_stock) })) as Product[]);
      setMovements((movementResult.data ?? []).map((item) => ({
        ...item,
        quantity: Number(item.quantity),
        previous_stock: Number(item.previous_stock),
        new_stock: Number(item.new_stock),
        products: Array.isArray(item.products) ? (item.products[0] ?? null) : item.products,
      })) as Movement[]);
      if (profileResult.data?.display_name) setDisplayName(profileResult.data.display_name);
      if (profileResult.data?.username) setUsername(profileResult.data.username);
      if (profileResult.data?.role) setRole(profileResult.data.role as ProfileRole);
      setOrganizationId(nextOrganizationId);
      setOrganizationName(profileOrganization?.name ?? "İşletme");
      setSubscriptionStatus(profileOrganization?.subscription_status ?? "active");
      setTrialEndsAt(profileOrganization?.trial_ends_at ?? null);
      setCurrentPeriodEnd(profileOrganization?.current_period_end ?? null);
      setIsPlatformOperator(Boolean(profileResult.data?.is_platform_operator));
      setError("");
    }
    setLoading(false);
    setRefreshing(false);
  }, [session.user.id]);

  useEffect(() => { void loadData(); }, [loadData]);

  useEffect(() => {
    if (!organizationId) return;
    const filter = `organization_id=eq.${organizationId}`;
    const channel = supabase.channel(`stokta-live-${organizationId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "products", filter }, () => void loadData(true))
      .on("postgres_changes", { event: "*", schema: "public", table: "stock_movements", filter }, () => void loadData(true))
      .subscribe();
    return () => { void supabase.removeChannel(channel); };
  }, [loadData, organizationId]);

  const filteredProducts = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("tr-TR");
    return products.filter((product) => {
      const matches = !query || `${product.name} ${product.sku} ${product.category}`.toLocaleLowerCase("tr-TR").includes(query);
      return matches && (!onlyLow || product.stock <= product.min_stock);
    });
  }, [products, search, onlyLow]);

  const lowCount = products.filter((product) => product.stock <= product.min_stock).length;
  const criticalCount = products.filter((product) => product.stock === 0).length;
  const todayKey = new Date().toDateString();
  const todayMovementCount = movements.filter((movement) => new Date(movement.created_at).toDateString() === todayKey).length;
  const firstName = displayName.split(" ")[0] || displayName;
  const isAdmin = role === "admin";
  const requiresTerms = !termsChecked
    || serverTermsVersion !== CURRENT_UGC_TERMS_VERSION
    || acceptedTermsVersion !== serverTermsVersion;
  const now = Date.now();
  const canWrite = (subscriptionStatus === "trial" && Boolean(trialEndsAt) && new Date(trialEndsAt ?? 0).getTime() > now)
    || (subscriptionStatus === "active" && (!currentPeriodEnd || new Date(currentPeriodEnd).getTime() > now));
  const subscriptionLabel = subscriptionStatus === "trial" ? "Deneme"
    : subscriptionStatus === "active" ? "Aktif"
    : subscriptionStatus === "inactive" ? "İnaktif"
    : subscriptionStatus === "past_due" ? "Erişim kapalı"
    : subscriptionStatus === "suspended" ? "Askıda"
    : "İptal edildi";

  function requireWritable() {
    if (canWrite) return true;
    Alert.alert("İşletme hesabı işlem yapmaya kapalı", "Abonelik durumunu yenilemek için işletme yöneticisinin Google Play üzerinden ödeme yapması gerekiyor.");
    return false;
  }

  async function acceptTerms() {
    setAcceptingTerms(true);
    setTermsError("");
    const { data, error: acceptError } = await supabase.rpc("accept_current_ugc_terms", {
      p_version: CURRENT_UGC_TERMS_VERSION,
    });
    setAcceptingTerms(false);
    if (acceptError) {
      setTermsError(acceptError.message);
      return;
    }
    const response = data as { accepted?: boolean; accepted_version?: string; current_version?: string } | null;
    if (!response?.accepted || response.accepted_version !== CURRENT_UGC_TERMS_VERSION || response.current_version !== CURRENT_UGC_TERMS_VERSION) {
      setTermsError("Koşul kabulü doğrulanamadı. Lütfen yeniden deneyin.");
      return;
    }
    setAcceptedTermsVersion(response.accepted_version);
    setServerTermsVersion(response.current_version);
    setTermsChecked(true);
    setReviewTermsModal(false);
  }

  function reviewTerms() {
    setAccountModal(false);
    setReviewTermsModal(true);
  }

  function openSubscription() {
    if (!isAdmin || isPlatformOperator || !organizationId) return;
    setAccountModal(false);
    setSubscriptionModal(true);
  }

  function openSafetyCenter(scope: "organization" | "platform") {
    if ((scope === "organization" && !isAdmin) || (scope === "platform" && !isPlatformOperator)) return;
    setAccountModal(false);
    setSafetyCenterScope(scope);
    setSafetyCenterModal(true);
  }

  function openProductReport(product: Product) {
    setReportError("");
    setReportTarget({ type: "product", id: product.id, label: `${product.name} · ${product.sku}` });
  }

  function openMovementReport(movement: Movement) {
    setReportError("");
    setReportTarget({
      type: "movement",
      id: movement.id,
      label: `${movement.products?.name ?? "Ürün"} · ${movement.actor_name} · ${shortTime(movement.created_at)}`,
    });
  }

  function openActorReport(movement: Movement) {
    if (!movement.actor_id) return;
    if (movement.actor_id === session.user.id) {
      Alert.alert("Kendi hesabınızı bildiremezsiniz", "Başka bir ekip üyesinin hareketindeki \"Kullanıcıyı bildir\" butonunu seçin.");
      return;
    }
    setReportError("");
    setReportTarget({ type: "user", id: movement.actor_id, label: movement.actor_name });
  }

  async function submitReport(reason: ContentReportReason, details: string) {
    if (!reportTarget) return;
    setReportSaving(true);
    setReportError("");
    const { error: submitError } = await supabase.rpc("report_content", {
      p_target_type: reportTarget.type,
      p_target_id: reportTarget.id,
      p_reason: reason,
      p_details: details,
    });
    setReportSaving(false);
    if (submitError) {
      setReportError(submitError.message);
      return;
    }
    setReportTarget(null);
    Alert.alert("Bildirim alındı", "Yetkili inceleme ekibi bildirimi Güvenlik Merkezi’nden değerlendirecek.");
  }

  function openCreate() {
    if (!isAdmin || !requireWritable()) return;
    setEditing(null);
    setDraft(emptyDraft);
    setProductModal(true);
  }

  function openEdit(product: Product) {
    if (!isAdmin || !requireWritable()) return;
    setEditing(product);
    setDraft({
      name: product.name,
      sku: product.sku,
      category: product.category,
      unit: product.unit,
      stock: String(product.stock),
      minStock: String(product.min_stock),
    });
    setProductModal(true);
  }

  function openMovement(product: Product, type: "in" | "out") {
    if (!requireWritable()) return;
    setSelectedProduct(product);
    setMovementType(type);
    setQuantity("");
    setNote("");
    setMovementModal(true);
  }

  async function saveProduct() {
    if (!isAdmin) return;
    if (!draft.name.trim() || !draft.sku.trim()) {
      Alert.alert("Eksik bilgi", "Ürün adı ve ürün kodu zorunludur.");
      return;
    }
    const stock = Number(draft.stock.replace(",", "."));
    const minStock = Number(draft.minStock.replace(",", "."));
    if (!Number.isFinite(stock) || stock < 0 || !Number.isFinite(minStock) || minStock < 0) {
      Alert.alert("Hatalı değer", "Stok miktarları geçerli sayı olmalıdır.");
      return;
    }
    setSaving(true);
    const args = editing ? {
      p_product_id: editing.id,
      p_name: draft.name,
      p_sku: draft.sku,
      p_category: draft.category,
      p_unit: draft.unit,
      p_min_stock: minStock,
    } : {
      p_name: draft.name,
      p_sku: draft.sku,
      p_category: draft.category,
      p_unit: draft.unit,
      p_stock: stock,
      p_min_stock: minStock,
    };
    const { error: saveError } = await supabase.rpc(editing ? "update_inventory_product" : "create_inventory_product", args);
    setSaving(false);
    if (saveError) {
      Alert.alert("Kaydedilemedi", friendlyError(saveError.message));
      return;
    }
    setProductModal(false);
    await loadData(true);
  }

  async function saveMovement() {
    if (!selectedProduct) return;
    const amount = Number(quantity.replace(",", "."));
    if (!Number.isFinite(amount) || amount <= 0) {
      Alert.alert("Hatalı miktar", "Sıfırdan büyük bir miktar girin.");
      return;
    }
    if (movementType === "out" && amount > selectedProduct.stock) {
      Alert.alert("Yetersiz stok", `Stokta yalnızca ${selectedProduct.stock} ${selectedProduct.unit} var.`);
      return;
    }
    setSaving(true);
    const { error: movementError } = await supabase.rpc("record_stock_movement", {
      p_product_id: selectedProduct.id,
      p_type: movementType,
      p_quantity: amount,
      p_note: note,
    });
    setSaving(false);
    if (movementError) {
      Alert.alert("İşlem yapılamadı", friendlyError(movementError.message));
      await loadData(true);
      return;
    }
    setMovementModal(false);
    await loadData(true);
  }

  function openCoworker() {
    if (!isAdmin || !requireWritable()) return;
    setCoworkerName("");
    setCoworkerUsername("");
    setCoworkerEmail("");
    setCoworkerPassword("");
    setCoworkerPasswordAgain("");
    setCoworkerModal(true);
  }

  async function saveCoworker() {
    if (!isAdmin) return;
    const normalizedUsername = normalizeUsername(coworkerUsername);
    const normalizedEmail = coworkerEmail.trim().toLowerCase();
    if (!coworkerName.trim()) {
      Alert.alert("Eksik bilgi", "Çalışanın adını girin.");
      return;
    }
    if (normalizedUsername.length < 3) {
      Alert.alert("Hatalı kullanıcı adı", "Kullanıcı adı en az 3 karakter olmalı.");
      return;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) {
      Alert.alert("Hatalı e-posta", "Çalışanın doğrulama kodlarını alabilmesi için geçerli bir e-posta adresi girin.");
      return;
    }
    if (!isStrongPassword(coworkerPassword)) {
      Alert.alert("Hatalı şifre", "Şifre 8-72 karakter olmalı; büyük harf, küçük harf ve rakam içermelidir.");
      return;
    }
    if (coworkerPassword !== coworkerPasswordAgain) {
      Alert.alert("Şifreler eşleşmiyor", "İki alana aynı şifreyi girin.");
      return;
    }

    setSaving(true);
    const { error: createError } = await supabase.functions.invoke("create-coworker", {
      body: {
        username: normalizedUsername,
        displayName: coworkerName.trim(),
        recoveryEmail: normalizedEmail,
        password: coworkerPassword,
      },
    });
    setSaving(false);
    if (createError) {
      Alert.alert("Çalışan oluşturulamadı", await edgeFunctionError(createError));
      return;
    }
    setCoworkerModal(false);
    Alert.alert("Doğrulama gönderildi", `${coworkerName.trim()} için doğrulama kodu ${normalizedEmail} adresine gönderildi.`);
  }

  async function signOut() {
    Alert.alert("Çıkış yapılsın mı?", "Bu cihazdaki oturum kapatılacak.", [
      { text: "Vazgeç", style: "cancel" },
      { text: "Çıkış yap", style: "destructive", onPress: () => void supabase.auth.signOut() },
    ]);
  }

  async function deleteAccount(confirmation: string, currentPassword: string) {
    setSaving(true);
    const { data: deletion, error: deleteError } = await supabase.functions.invoke("delete-account", {
      body: { confirmation, currentPassword },
    });
    setSaving(false);
    if (deleteError) {
      try {
        const result = await (deleteError as { context?: Response }).context?.clone().json() as
          { code?: string; error?: string; dataDeleted?: boolean } | undefined;
        if (result?.code === "DELETION_REVIEW_REQUESTED") {
          Alert.alert("Silme talebi kaydedildi", result.error ?? "Ödeme kayıtları inceleniyor. Hesap henüz silinmedi.");
          return;
        }
        if (result?.code === "AUTH_CLEANUP_PENDING" && result.dataDeleted === true) {
          setAccountModal(false);
          await supabase.auth.signOut({ scope: "local" });
          Alert.alert("Giriş hesabı temizliği sürüyor", result.error ?? "Veriler silindi. Giriş kimliğinin temizliği tamamlanıyor.");
          return;
        }
      } catch { /* Fall through to the ordinary Edge error message. */ }
      Alert.alert("Hesap silinemedi", await edgeFunctionError(deleteError));
      return;
    }
    if (deletion?.deleted !== true) {
      Alert.alert("Silme doğrulanamadı", "Hesap silme işleminin tamamlandığı doğrulanamadı. Destek ile iletişime geçin.");
      return;
    }
    setAccountModal(false);
    await supabase.auth.signOut({ scope: "local" });
    Alert.alert("Silme tamamlandı", isAdmin ? "Çalışma alanı ve tüm hesaplar kalıcı olarak silindi." : "Hesabınız silindi.");
  }

  if (mustChangePassword) return <ForcedPasswordChange />;
  if (isPlatformOperator && platformMfaVerifiedToken !== session.access_token) {
    return (
      <PlatformMfaGate
        visible
        onVerified={handlePlatformMfaVerified}
        onSignOut={signOut}
      />
    );
  }

  return (
    <SafeAreaView style={styles.safe} edges={["top"]}>
      <FlatList
        data={filteredProducts}
        scrollEnabled={!requiresTerms}
        keyExtractor={(item) => item.id}
        refreshControl={<RefreshControl refreshing={refreshing} tintColor="#1f7353" colors={["#1f7353"]} onRefresh={() => void loadData(true)} />}
        contentContainerStyle={styles.listContent}
        ListHeaderComponent={<>
          <View style={styles.header}>
            <View><Text style={styles.date}>{formatDate(new Date())}</Text><Text style={styles.greeting}>Merhaba, {firstName}</Text></View>
            <View style={styles.headerActions}>
              {isPlatformOperator ? <Pressable style={styles.platformButton} onPress={() => setPlatformModal(true)}><Text style={styles.platformButtonText}>Platform Operatörü</Text></Pressable> : null}
              {isAdmin ? <Pressable style={styles.addCoworker} onPress={openCoworker}><Text style={styles.addCoworkerText}>+ Çalışan</Text></Pressable> : null}
              <Pressable style={styles.avatar} onPress={() => setAccountModal(true)}><Text style={styles.avatarText}>{firstName.slice(0, 2).toUpperCase()}</Text></Pressable>
            </View>
          </View>
          {error ? <Pressable style={styles.errorBanner} onPress={() => void loadData()}><Text style={styles.errorText}>{error}</Text></Pressable> : null}
          {!canWrite ? <View style={styles.subscriptionBanner}>
            <Text style={styles.subscriptionBannerTitle}>Abonelik durumu: {subscriptionLabel}</Text>
            <Text style={styles.subscriptionBannerText}>Veriler görüntülenebilir; stok ve kullanıcı değişiklikleri durduruldu.</Text>
            {isAdmin && !isPlatformOperator ? <Pressable
              style={styles.subscriptionAction}
              onPress={openSubscription}
              accessibilityRole="button"
              accessibilityLabel="Google Play aboneliğini yenile"
            >
              <Text style={styles.subscriptionActionText}>{["Erişim kapalı", "İnaktif", "Askıda"].includes(subscriptionLabel) ? "Google Play ile Aboneliği Yenile" : "Abonelik Detaylarını Gör"}</Text>
            </Pressable> : null}
          </View> : null}
          <View style={styles.statsGrid}>
            <StatCard label="TOPLAM ÜRÜN" value={products.length} caption="Aktif ürün çeşidi" tone="green" />
            <StatCard label="AZALAN STOK" value={lowCount} caption={criticalCount ? `${criticalCount} ürün tükendi` : "Kritik seviyede ürün yok"} tone={lowCount ? "amber" : "gray"} />
            <StatCard label="BUGÜNKÜ İŞLEM" value={todayMovementCount} caption="Buluta kaydedildi" tone="blue" />
          </View>
          <View style={styles.sectionHead}><View><Text style={styles.eyebrow}>ANLIK LİSTE</Text><Text style={styles.sectionTitle}>Ürün Listesi</Text></View>{isAdmin ? <Pressable style={styles.smallAddButton} onPress={openCreate}><Text style={styles.smallAddButtonText}>+ Yeni Ürün</Text></Pressable> : null}</View>
          <View style={styles.searchBox}><Text style={styles.searchIcon}>🔍</Text><TextInput style={styles.searchInput} value={search} onChangeText={setSearch} placeholder="Ürün adı, SKU veya kategori ara..." placeholderTextColor="#8a978f" /><Pressable style={[styles.filterChip, onlyLow && styles.filterChipActive]} onPress={() => setOnlyLow((v) => !v)}><Text style={[styles.filterChipText, onlyLow && styles.filterChipTextActive]}>Azalanlar ({lowCount})</Text></Pressable></View>
          {loading ? <View style={styles.loadingBox}><ActivityIndicator color="#1f7353" /><Text style={styles.loadingText}>Stok verileri yükleniyor...</Text></View> : null}
        </>}
        renderItem={({ item }) => <ProductCard product={item} canEdit={isAdmin} onEdit={() => openEdit(item)} onIn={() => openMovement(item, "in")} onOut={() => openMovement(item, "out")} onReport={() => openProductReport(item)} />}
        ListEmptyComponent={!loading ? <View style={styles.empty}><Text style={styles.emptyIcon}>📦</Text><Text style={styles.emptyTitle}>Ürün Bulunamadı</Text><Text style={styles.emptySubtitle}>Arama kriterine uyan ürün yok veya henüz kayıt açılmadı.</Text></View> : null}
        ListFooterComponent={<MovementHistory movements={movements.slice(0, 8)} onReportContent={openMovementReport} onReportUser={openActorReport} />}
      />
      {isAdmin && canWrite ? <Pressable style={styles.fab} onPress={openCreate}><Text style={styles.fabText}>+</Text></Pressable> : null}
      {isAdmin ? <ProductEditor visible={productModal} editing={editing} draft={draft} setDraft={setDraft} saving={saving} onClose={() => setProductModal(false)} onSave={() => void saveProduct()} /> : null}
      <MovementEditor visible={movementModal} product={selectedProduct} type={movementType} setType={setMovementType} quantity={quantity} setQuantity={setQuantity} note={note} setNote={setNote} saving={saving} onClose={() => setMovementModal(false)} onSave={() => void saveMovement()} />
      {isAdmin ? <CoworkerEditor visible={coworkerModal} name={coworkerName} setName={setCoworkerName} username={coworkerUsername} setUsername={setCoworkerUsername} email={coworkerEmail} setEmail={setCoworkerEmail} password={coworkerPassword} setPassword={setCoworkerPassword} passwordAgain={coworkerPasswordAgain} setPasswordAgain={setCoworkerPasswordAgain} saving={saving} onClose={() => setCoworkerModal(false)} onSave={() => void saveCoworker()} /> : null}
      <AccountModal visible={accountModal} displayName={displayName} username={username} role={role} organizationName={organizationName} subscriptionStatus={subscriptionStatus} trialEndsAt={trialEndsAt} currentPeriodEnd={currentPeriodEnd} isPlatformOperator={isPlatformOperator} saving={saving} onClose={() => setAccountModal(false)} onSignOut={() => void signOut()} onDeleteAccount={(c: string, p: string) => void deleteAccount(c, p)} onReviewTerms={reviewTerms} onOpenSubscription={openSubscription} onOpenSafetyCenter={() => openSafetyCenter("organization")} />
      {isAdmin && !isPlatformOperator ? <SubscriptionModal
        visible={subscriptionModal}
        userId={session.user.id}
        organizationId={organizationId}
        subscriptionLabel={subscriptionLabel}
        trialEndsAt={trialEndsAt}
        currentPeriodEnd={currentPeriodEnd}
        onClose={() => setSubscriptionModal(false)}
        onSubscriptionUpdated={() => void loadData(true)}
      /> : null}
      {isPlatformOperator ? <PlatformModal visible={platformModal} onClose={() => setPlatformModal(false)} /> : null}
      {isAdmin || isPlatformOperator ? <SafetyCenterModal scope={safetyCenterScope} visible={safetyCenterModal} onClose={() => setSafetyCenterModal(false)} /> : null}
      <ContentReportModal target={reportTarget} saving={reportSaving} error={reportError} onClose={() => { if (!reportSaving) setReportTarget(null); }} onSubmit={(reason, details) => void submitReport(reason, details)} />
      <TermsModal
        visible={requiresTerms || reviewTermsModal}
        mandatory={requiresTerms}
        accepted={termsChecked
          && serverTermsVersion === CURRENT_UGC_TERMS_VERSION
          && acceptedTermsVersion === CURRENT_UGC_TERMS_VERSION}
        checking={!termsChecked && !termsError}
        saving={acceptingTerms}
        error={termsError}
        onAccept={acceptTerms}
        onClose={() => setReviewTermsModal(false)}
        onDecline={() => void supabase.auth.signOut()}
        onRetry={() => void loadData()}
      />
    </SafeAreaView>
  );
}

function StatCard({ label, value, caption, tone }: { label: string; value: number; caption: string; tone: "green" | "amber" | "blue" | "gray" }) {
  const toneStyle = { green: styles.stat_green, amber: styles.stat_amber, blue: styles.stat_blue, gray: styles.stat_gray }[tone];
  return <View style={styles.statCard}><View style={[styles.statDot, toneStyle]} /><Text style={styles.statLabel}>{label}</Text><Text style={styles.statValue}>{numberFormatter.format(value)}</Text><Text style={styles.statCaption}>{caption}</Text></View>;
}

function ProductCard({ product, canEdit, onEdit, onIn, onOut, onReport }: { product: Product; canEdit: boolean; onEdit: () => void; onIn: () => void; onOut: () => void; onReport: () => void }) {
  const status = product.stock === 0 ? "Tükendi" : product.stock <= product.min_stock ? "Azaldı" : "Yeterli";
  return (
    <View style={styles.productCard}>
      <Pressable style={styles.productInfo} onPress={onEdit} disabled={!canEdit}>
        <View style={styles.productTop}><View style={styles.productMark}><Text style={styles.productMarkText}>{product.name.slice(0, 2).toUpperCase()}</Text></View><View><Text style={styles.productName}>{product.name}</Text><Text style={styles.productSub}>{product.sku} · {product.category}</Text></View></View>
        <View style={styles.stockRow}><View><Text style={styles.stockLabel}>MEVCUT STOK</Text><Text style={styles.stockValue}>{numberFormatter.format(product.stock)} {product.unit}</Text></View><Text style={[styles.statusBadge, status === "Tükendi" ? styles.badgeRed : status === "Azaldı" ? styles.badgeAmber : styles.badgeGreen]}>{status}</Text></View>
      </Pressable>
      <View style={styles.productActions}>
        <Pressable accessibilityRole="button" accessibilityLabel={`${product.name} ürününe stok ekle`} style={styles.actionGreen} onPress={onIn}><Text style={styles.actionText}>+ Stok Ekle</Text></Pressable>
        <Pressable accessibilityRole="button" accessibilityLabel={`${product.name} ürününden stok düş`} style={styles.actionAmber} onPress={onOut}><Text style={styles.actionText}>- Stok Düş</Text></Pressable>
        <Pressable accessibilityRole="button" accessibilityLabel={`${product.name} ürününü bildir`} style={styles.actionReport} onPress={onReport}><Text style={styles.actionReportText}>🚩 Bildir</Text></Pressable>
      </View>
    </View>
  );
}

function MovementHistory({ movements, onReportContent, onReportUser }: { movements: Movement[]; onReportContent: (m: Movement) => void; onReportUser: (m: Movement) => void }) {
  return (
    <View style={styles.history}>
      <Text style={styles.eyebrow}>CANLI KAYIT</Text>
      <Text style={styles.sectionTitle}>Son hareketler</Text>
      {movements.length ? movements.map((movement) => (
        <View style={styles.movementItem} key={movement.id}>
          <View style={styles.movementRow}>
            <View style={[styles.movementIcon, movement.type === "in" ? styles.movementIn : styles.movementOut]}><Text style={styles.movementIconText}>{movement.type === "in" ? "↓" : "↑"}</Text></View>
            <View style={styles.movementBody}><Text style={styles.movementName}>{movement.products?.name ?? "Ürün"}</Text><Text style={styles.movementSub}>{movement.type === "in" ? "+" : "-"}{numberFormatter.format(movement.quantity)} {movement.products?.unit ?? "adet"} · {movement.actor_name}</Text>{movement.note ? <Text style={styles.movementNote}>"{movement.note}"</Text> : null}</View>
            <Text style={styles.movementTime}>{shortTime(movement.created_at)}</Text>
          </View>
          <View style={styles.movementReportActions}>
            {movement.note ? <Pressable accessibilityRole="button" accessibilityLabel="Bu stok hareketinin içeriğini veya notunu bildir" style={styles.inlineReport} onPress={() => onReportContent(movement)}><Text style={styles.inlineReportText}>🚩 İçeriği bildir</Text></Pressable> : null}
            {movement.actor_id ? <Pressable accessibilityRole="button" accessibilityLabel={`${movement.actor_name} kullanıcısını bildir`} style={styles.inlineReport} onPress={() => onReportUser(movement)}><Text style={styles.inlineReportText}>🚩 Kullanıcıyı bildir</Text></Pressable> : null}
          </View>
        </View>
      )) : <Text style={styles.historyEmpty}>Henüz stok hareketi yok.</Text>}
    </View>
  );
}

function useKeyboardOffset() {
  const [keyboardHeight, setKeyboardHeight] = useState(0);

  useEffect(() => {
    const showEvent = Platform.OS === "ios" ? "keyboardWillShow" : "keyboardDidShow";
    const hideEvent = Platform.OS === "ios" ? "keyboardWillHide" : "keyboardDidHide";

    const showSub = Keyboard.addListener(showEvent, (event) => {
      setKeyboardHeight(event.endCoordinates.height);
    });
    const hideSub = Keyboard.addListener(hideEvent, () => {
      setKeyboardHeight(0);
    });

    return () => {
      showSub.remove();
      hideSub.remove();
    };
  }, []);

  return keyboardHeight;
}

function ProductEditor({ visible, editing, draft, setDraft, saving, onClose, onSave }: { visible: boolean; editing: Product | null; draft: ProductDraft; setDraft: (value: ProductDraft) => void; saving: boolean; onClose: () => void; onSave: () => void }) {
  const keyboardHeight = useKeyboardOffset();
  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <KeyboardAvoidingView
        style={[
          styles.modalBackdrop,
          Platform.OS === "android" && keyboardHeight > 0 ? { paddingBottom: keyboardHeight } : null,
        ]}
        behavior={Platform.OS === "ios" ? "padding" : "height"}
      >
        <View style={styles.modalSheet}>
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>{editing ? "Ürünü Düzenle" : "Yeni Ürün"}</Text>
            <Pressable onPress={onClose}><Text style={styles.closeText}>×</Text></Pressable>
          </View>
          <ScrollView
            keyboardShouldPersistTaps="handled"
            showsVerticalScrollIndicator={false}
            contentContainerStyle={styles.modalScrollContent}
          >
            <Field label="Ürün Adı" value={draft.name} onChangeText={(name) => setDraft({ ...draft, name })} placeholder="Örn. Koli Bandı 45 mm" autoFocus />
            <View style={{ flexDirection: "row", gap: 10 }}>
              <View style={{ flex: 1 }}>
                <Field label="Ürün Kodu" value={draft.sku} onChangeText={(sku) => setDraft({ ...draft, sku })} placeholder="Örn. KB-45" autoCapitalize="characters" />
              </View>
              <View style={{ flex: 1 }}>
                <Field label="Birim" value={draft.unit} onChangeText={(unit) => setDraft({ ...draft, unit })} placeholder="Örn. Adet" />
              </View>
            </View>
            <View style={{ flexDirection: "row", gap: 10 }}>
              <View style={{ flex: 1 }}>
                <Field label="Mevcut Stok" value={draft.stock} onChangeText={(stock) => setDraft({ ...draft, stock })} placeholder="0" keyboardType="numeric" />
              </View>
              <View style={{ flex: 1 }}>
                <Field label="Kritik Stok" value={draft.minStock} onChangeText={(minStock) => setDraft({ ...draft, minStock })} placeholder="0" keyboardType="numeric" />
              </View>
            </View>
            <Pressable style={[styles.saveButton, saving && styles.saveButtonDisabled]} onPress={onSave} disabled={saving}>
              {saving ? <ActivityIndicator color="#fff" /> : <Text style={styles.saveText}>{editing ? "Kaydet" : "Ürün Ekle"}</Text>}
            </Pressable>
          </ScrollView>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function MovementEditor({ visible, product, type, setType, quantity, setQuantity, note, setNote, saving, onClose, onSave }: { visible: boolean; product: Product | null; type: "in" | "out"; setType: (type: "in" | "out") => void; quantity: string; setQuantity: (value: string) => void; note: string; setNote: (value: string) => void; saving: boolean; onClose: () => void; onSave: () => void }) {
  const keyboardHeight = useKeyboardOffset();
  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <KeyboardAvoidingView
        style={[
          styles.modalBackdrop,
          Platform.OS === "android" && keyboardHeight > 0 ? { paddingBottom: keyboardHeight } : null,
        ]}
        behavior={Platform.OS === "ios" ? "padding" : "height"}
      >
        <View style={styles.modalSheet}>
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>{product?.name ?? "Stok Hareketi"}</Text>
            <Pressable onPress={onClose}><Text style={styles.closeText}>×</Text></Pressable>
          </View>
          <ScrollView
            keyboardShouldPersistTaps="handled"
            showsVerticalScrollIndicator={false}
            contentContainerStyle={styles.modalScrollContent}
          >
            <View style={styles.segment}>
              <Pressable style={[styles.segmentItem, type === "in" && styles.segmentActive]} onPress={() => setType("in")}>
                <Text style={[styles.segmentText, type === "in" && styles.segmentTextActive]}>Stok Girişi (+)</Text>
              </Pressable>
              <Pressable style={[styles.segmentItem, type === "out" && styles.segmentActive]} onPress={() => setType("out")}>
                <Text style={[styles.segmentText, type === "out" && styles.segmentTextActive]}>Stok Çıkışı (-)</Text>
              </Pressable>
            </View>
            <Field label="Miktar" value={quantity} onChangeText={setQuantity} placeholder="0" keyboardType="numeric" autoFocus />
            <Field label="Not (Opsiyonel)" value={note} onChangeText={setNote} placeholder="Örn. Müşteri teslimatı / Yeni sevkiyat" />
            <Pressable style={[styles.saveButton, saving && styles.saveButtonDisabled]} onPress={onSave} disabled={saving}>
              {saving ? <ActivityIndicator color="#fff" /> : <Text style={styles.saveText}>Hareketi Kaydet</Text>}
            </Pressable>
          </ScrollView>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function CoworkerEditor({ visible, name, setName, username, setUsername, email, setEmail, password, setPassword, passwordAgain, setPasswordAgain, saving, onClose, onSave }: { visible: boolean; name: string; setName: (value: string) => void; username: string; setUsername: (value: string) => void; email: string; setEmail: (value: string) => void; password: string; setPassword: (value: string) => void; passwordAgain: string; setPasswordAgain: (value: string) => void; saving: boolean; onClose: () => void; onSave: () => void }) {
  const keyboardHeight = useKeyboardOffset();
  return (
    <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}>
      <KeyboardAvoidingView
        style={[
          styles.modalBackdrop,
          Platform.OS === "android" && keyboardHeight > 0 ? { paddingBottom: keyboardHeight } : null,
        ]}
        behavior={Platform.OS === "ios" ? "padding" : "height"}
      >
        <View style={styles.modalSheet}>
          <View style={styles.modalHeader}>
            <Text style={styles.modalTitle}>Çalışan Ekle</Text>
            <Pressable onPress={onClose}><Text style={styles.closeText}>×</Text></Pressable>
          </View>
          <ScrollView
            keyboardShouldPersistTaps="handled"
            showsVerticalScrollIndicator={false}
            contentContainerStyle={styles.modalScrollContent}
          >
            <Field label="Ad ve soyad" value={name} onChangeText={setName} placeholder="Örn. Ahmet Yılmaz" autoFocus />
            <Field label="Kullanıcı adı" value={username} onChangeText={setUsername} placeholder="Örn. ahmetyilmaz" autoCapitalize="none" autoCorrect={false} />
            <Field label="E-posta adresi" value={email} onChangeText={setEmail} placeholder="Örn. ahmet@firma.com" keyboardType="email-address" autoCapitalize="none" autoCorrect={false} />
            <Field label="Şifre" value={password} onChangeText={setPassword} placeholder="En az 8 karakter" secureTextEntry />
            <Field label="Şifre (Tekrar)" value={passwordAgain} onChangeText={setPasswordAgain} placeholder="Şifrenizi doğrulayın" secureTextEntry />
            <Pressable style={[styles.saveButton, saving && styles.saveButtonDisabled]} onPress={onSave} disabled={saving}>
              {saving ? <ActivityIndicator color="#fff" /> : <Text style={styles.saveText}>Çalışanı Ekle</Text>}
            </Pressable>
          </ScrollView>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function Field(props: ComponentProps<typeof TextInput> & { label: string }) {
  const { label, ...inputProps } = props;
  return (
    <View style={styles.field}>
      <Text style={styles.fieldLabel}>{label}</Text>
      <TextInput style={styles.fieldInput} placeholderTextColor="#98a09b" {...inputProps} />
    </View>
  );
}

function formatDate(value: Date) {
  return value.toLocaleDateString("tr-TR", { day: "numeric", month: "long", weekday: "long" }).toLocaleUpperCase("tr-TR");
}

function shortTime(value: string) {
  const date = new Date(value);
  return date.toDateString() === new Date().toDateString()
    ? date.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString("tr-TR", { day: "numeric", month: "short" });
}

function friendlyError(message: string) {
  if (message.includes("duplicate key")) return "Bu ürün kodu zaten kullanılıyor.";
  return message;
}

function isStrongPassword(value: string) {
  return (
    value.length >= 8 &&
    value.length <= 72 &&
    /[a-z]/.test(value) &&
    /[A-Z]/.test(value) &&
    /[0-9]/.test(value)
  );
}

async function edgeFunctionError(error: unknown) {
  const candidate = error as { context?: Response; message?: string };
  try {
    const body = (await candidate.context?.json()) as { error?: string } | undefined;
    if (body?.error) return body.error;
  } catch { /* fallback */ }
  return candidate.message ?? "İşlem tamamlanamadı.";
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#172820" },
  listContent: { paddingBottom: 110, backgroundColor: "#f4f5f1" },
  header: { paddingHorizontal: 18, paddingTop: 17, paddingBottom: 24, flexDirection: "row", justifyContent: "space-between", alignItems: "center", backgroundColor: "#172820" },
  date: { marginBottom: 4, color: "#86a095", fontSize: 9, fontWeight: "800", letterSpacing: 1 },
  greeting: { color: "#ffffff", fontSize: 21, fontWeight: "800" },
  headerActions: { flexDirection: "row", alignItems: "center", gap: 8 },
  addCoworker: { height: 36, paddingHorizontal: 12, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "rgba(255,255,255,0.12)" },
  addCoworkerText: { color: "#ffffff", fontSize: 10, fontWeight: "800" },
  platformButton: { height: 36, paddingHorizontal: 9, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "rgba(255,255,255,0.12)" },
  platformButtonText: { color: "#ffffff", fontSize: 13, fontWeight: "800" },
  avatar: { width: 43, height: 43, borderRadius: 14, alignItems: "center", justifyContent: "center", backgroundColor: "#3a5146" },
  avatarText: { color: "#ffffff", fontSize: 12, fontWeight: "800" },
  errorBanner: { marginHorizontal: 14, marginTop: 13, padding: 12, flexDirection: "row", alignItems: "center", gap: 8, borderWidth: 1, borderColor: "#f2c1c1", borderRadius: 15, backgroundColor: "#fdf0f0" },
  errorText: { flex: 1, color: "#992121", fontSize: 11, fontWeight: "600" },
  subscriptionBanner: { marginHorizontal: 14, marginTop: 13, padding: 12, borderWidth: 1, borderColor: "#efd5ad", borderRadius: 15, backgroundColor: "#fcf6ec" },
  subscriptionBannerTitle: { color: "#825008", fontSize: 12, fontWeight: "800" },
  subscriptionBannerText: { marginTop: 2, color: "#9e6919", fontSize: 10, fontWeight: "600" },
  subscriptionAction: { marginTop: 10, height: 38, borderRadius: 10, backgroundColor: "#245039", alignItems: "center", justifyContent: "center", paddingHorizontal: 12 },
  subscriptionActionText: { color: "#ffffff", fontSize: 11, fontWeight: "800" },
  statsGrid: { marginTop: -1, padding: 14, flexDirection: "row", gap: 9, backgroundColor: "#f4f5f1" },
  statCard: { flex: 1, padding: 12, borderRadius: 15, backgroundColor: "#ffffff" },
  statDot: { width: 8, height: 8, borderRadius: 4, marginBottom: 6 },
  stat_green: { backgroundColor: "#1f7353" },
  stat_amber: { backgroundColor: "#d97706" },
  stat_blue: { backgroundColor: "#2563eb" },
  stat_gray: { backgroundColor: "#9ca3af" },
  statLabel: { color: "#77807b", fontSize: 9, fontWeight: "800" },
  statValue: { marginTop: 4, color: "#172820", fontSize: 20, fontWeight: "800" },
  statCaption: { marginTop: 2, color: "#8a9690", fontSize: 9, fontWeight: "600" },
  sectionHead: { paddingHorizontal: 16, paddingTop: 13, paddingBottom: 10, flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  eyebrow: { color: "#8a9690", fontSize: 8, fontWeight: "800", letterSpacing: 1 },
  sectionTitle: { marginTop: 2, color: "#172820", fontSize: 16, fontWeight: "800" },
  smallAddButton: { paddingHorizontal: 12, paddingVertical: 8, borderRadius: 10, backgroundColor: "#245039" },
  smallAddButtonText: { color: "#ffffff", fontSize: 11, fontWeight: "800" },
  searchBox: { height: 45, marginHorizontal: 14, marginBottom: 11, paddingHorizontal: 13, flexDirection: "row", alignItems: "center", gap: 8, borderWidth: 1, borderColor: "#dbe0db", borderRadius: 13, backgroundColor: "#ffffff" },
  searchIcon: { fontSize: 13 },
  searchInput: { flex: 1, color: "#172820", fontSize: 12, fontWeight: "600" },
  filterChip: { paddingHorizontal: 10, paddingVertical: 6, borderRadius: 8, borderWidth: 1, borderColor: "#dbe0db", backgroundColor: "#f4f5f1" },
  filterChipActive: { borderColor: "#245039", backgroundColor: "#245039" },
  filterChipText: { color: "#4f5a54", fontSize: 10, fontWeight: "800" },
  filterChipTextActive: { color: "#ffffff" },
  loadingBox: { paddingVertical: 30, alignItems: "center", gap: 9 },
  loadingText: { color: "#77807b", fontSize: 11, fontWeight: "700" },
  productCard: { marginHorizontal: 14, marginBottom: 11, overflow: "hidden", borderWidth: 1, borderColor: "#e2e5e1", borderRadius: 16, backgroundColor: "#ffffff" },
  productInfo: { padding: 14 },
  productTop: { flexDirection: "row", alignItems: "center", gap: 10 },
  productMark: { width: 38, height: 38, borderRadius: 11, backgroundColor: "#e8f5ed", alignItems: "center", justifyContent: "center" },
  productMarkText: { color: "#245039", fontSize: 12, fontWeight: "800" },
  productName: { color: "#172820", fontSize: 14, fontWeight: "800" },
  productSub: { marginTop: 2, color: "#77807b", fontSize: 10, fontWeight: "600" },
  stockRow: { marginTop: 14, paddingTop: 12, flexDirection: "row", justifyContent: "space-between", alignItems: "center", borderTopWidth: 1, borderTopColor: "#edf0ec" },
  stockLabel: { color: "#8a9690", fontSize: 8, fontWeight: "800", letterSpacing: 0.6 },
  stockValue: { marginTop: 2, color: "#172820", fontSize: 15, fontWeight: "800" },
  statusBadge: { paddingHorizontal: 9, paddingVertical: 4, borderRadius: 8, fontSize: 10, fontWeight: "800", overflow: "hidden" },
  badgeGreen: { backgroundColor: "#e8f5ed", color: "#1f7353" },
  badgeAmber: { backgroundColor: "#fef3c7", color: "#b45309" },
  badgeRed: { backgroundColor: "#fde8e8", color: "#b91c1c" },
  productActions: { minHeight: 44, flexDirection: "row", borderTopWidth: 1, borderTopColor: "#edf0ec" },
  actionGreen: { flex: 1, alignItems: "center", justifyContent: "center" },
  actionAmber: { flex: 1, alignItems: "center", justifyContent: "center", borderLeftWidth: 1, borderLeftColor: "#edf0ec" },
  actionReport: { paddingHorizontal: 14, alignItems: "center", justifyContent: "center", borderLeftWidth: 1, borderLeftColor: "#edf0ec" },
  actionText: { color: "#245039", fontSize: 11, fontWeight: "800" },
  actionReportText: { color: "#8a9690", fontSize: 10, fontWeight: "700" },
  empty: { marginHorizontal: 14, paddingVertical: 43, paddingHorizontal: 20, alignItems: "center", borderWidth: 1, borderColor: "#e2e5e1", borderRadius: 16, backgroundColor: "#ffffff" },
  emptyIcon: { fontSize: 28 },
  emptyTitle: { marginTop: 10, color: "#172820", fontSize: 14, fontWeight: "800" },
  emptySubtitle: { marginTop: 4, textAlign: "center", color: "#77807b", fontSize: 10, fontWeight: "600" },
  history: { margin: 14, marginTop: 22, padding: 15, borderWidth: 1, borderColor: "#e1e5e0", borderRadius: 15, backgroundColor: "#ffffff" },
  historyEmpty: { marginTop: 10, color: "#8a9690", fontSize: 11, fontWeight: "600" },
  movementItem: { marginTop: 10, paddingTop: 10, borderTopWidth: 1, borderTopColor: "#f0f3ef" },
  movementRow: { flexDirection: "row", alignItems: "center", gap: 10 },
  movementIcon: { width: 30, height: 30, borderRadius: 9, alignItems: "center", justifyContent: "center" },
  movementIconText: { fontSize: 13, fontWeight: "800", color: "#172820" },
  movementIn: { backgroundColor: "#e8f5ed" },
  movementOut: { backgroundColor: "#fde8e8" },
  movementBody: { flex: 1 },
  movementName: { color: "#172820", fontSize: 11, fontWeight: "800" },
  movementSub: { marginTop: 1, color: "#77807b", fontSize: 9, fontWeight: "600" },
  movementNote: { marginTop: 2, color: "#4f5a54", fontSize: 9, fontStyle: "italic" },
  movementTime: { color: "#77807b", fontSize: 9, fontWeight: "600" },
  movementReportActions: { marginTop: 6, flexDirection: "row", gap: 12 },
  inlineReport: { paddingVertical: 2 },
  inlineReportText: { color: "#8a9690", fontSize: 9, fontWeight: "800" },
  fab: { position: "absolute", right: 19, bottom: 23, width: 58, height: 58, borderRadius: 19, alignItems: "center", justifyContent: "center", backgroundColor: "#245039", shadowColor: "#000", shadowOffset: { width: 0, height: 4 }, shadowOpacity: 0.2, shadowRadius: 8, elevation: 5 },
  fabText: { color: "#ffffff", fontSize: 26, fontWeight: "300" },
  modalBackdrop: { flex: 1, justifyContent: "flex-end", backgroundColor: "#0c1813a8" },
  modalSheet: { maxHeight: "90%", padding: 18, borderTopLeftRadius: 24, borderTopRightRadius: 24, backgroundColor: "#ffffff" },
  modalHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  modalTitle: { color: "#172820", fontSize: 17, fontWeight: "800" },
  closeText: { color: "#77807b", fontSize: 17, fontWeight: "700" },
  modalScrollContent: { paddingBottom: 12 },
  field: { marginTop: 11 },
  fieldLabel: { color: "#77807b", fontSize: 9, fontWeight: "800" },
  fieldInput: { height: 43, marginTop: 4, paddingHorizontal: 12, borderWidth: 1, borderColor: "#dbe0db", borderRadius: 11, backgroundColor: "#ffffff", color: "#172820", fontSize: 12, fontWeight: "600" },
  segment: { height: 45, marginTop: 13, marginBottom: 6, padding: 3, flexDirection: "row", borderRadius: 11, backgroundColor: "#f0f3ef" },
  segmentItem: { flex: 1, height: 36, alignItems: "center", justifyContent: "center", borderRadius: 9 },
  segmentActive: { backgroundColor: "#ffffff" },
  segmentText: { color: "#77807b", fontSize: 11, fontWeight: "700" },
  segmentTextActive: { color: "#172820", fontWeight: "800" },
  saveButton: { height: 49, marginTop: 14, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#245039" },
  saveButtonDisabled: { opacity: 0.6 },
  saveText: { color: "#ffffff", fontSize: 13, fontWeight: "800" },
});

