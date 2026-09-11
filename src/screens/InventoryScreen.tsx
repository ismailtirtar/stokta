import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ComponentProps } from "react";
import type { Session } from "@supabase/supabase-js";
import { randomUUID } from "expo-crypto";
import {
  ActivityIndicator, Alert, AppState, FlatList, KeyboardAvoidingView, Modal, Platform, Pressable,
  RefreshControl, StyleSheet, Text, TextInput, View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { normalizeUsername, supabase } from "../lib/supabase";
import { isTransientSupabaseError, retryTransientSupabaseOperation } from "../lib/auth-retry";
import {
  clearAccountDeletionIntent,
  isDeletionRequestId,
  readAccountDeletionIntent,
  saveAccountDeletionIntent,
} from "../lib/account-deletion";
import AccountModal from "../components/AccountModal";
import ContentReportModal from "../components/ContentReportModal";
import ForcedPasswordChange from "../components/ForcedPasswordChange";
import PlatformModal from "../components/PlatformModal";
import SafetyCenterModal from "../components/SafetyCenterModal";
import SubscriptionModal from "../components/SubscriptionModal";
import TermsModal from "../components/TermsModal";
import { CURRENT_UGC_TERMS_DIGEST, CURRENT_UGC_TERMS_VERSION } from "../lib/ugc";
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
const PRODUCT_PAGE_SIZE = 200;
const MOVEMENT_PAGE_SIZE = 50;
const CLEARABLE_DELETION_CODES = new Set([
  "PURCHASE_INTENT_IN_PROGRESS",
  "RESTORE_PURCHASES_REQUIRED",
  "PLATFORM_ACCOUNT",
  "INVALID_CONFIRMATION",
  "PASSWORD_INVALID",
  "PASSWORD_REQUIRED",
  "INVALID_REQUEST",
]);

type QueryFailure = { code?: string; message?: string } | Error | unknown;
type LoadResult<T> = { data: T; error: QueryFailure | null };
type WriteAttempt = { signature: string; requestId: string };
type ProductCursor = { name: string; id: string };
type ProductPageResult = LoadResult<Product[]> & { nextCursor: ProductCursor | null; hasMore: boolean };
type InventorySummary = { totalProducts: number; lowStockProducts: number; criticalProducts: number; todayMovements: number };

async function loadProductPage(
  organizationId: string,
  cursor: ProductCursor | null,
  query: string,
  onlyLow: boolean,
): Promise<ProductPageResult> {
  const result = await retryTransientSupabaseOperation(() => supabase.rpc("list_inventory_products", {
    p_after_name: cursor?.name ?? null,
    p_after_id: cursor?.id ?? null,
    p_limit: PRODUCT_PAGE_SIZE,
    p_query: query || null,
    p_only_low: onlyLow,
  }));
  if (result.error) {
    if (isMissingRpc(result.error) && !query && !onlyLow) {
      return loadProductPageDirectly(organizationId, cursor);
    }
    return { data: [], error: result.error, nextCursor: null, hasMore: false };
  }

  const page = Array.isArray(result.data) ? result.data : [];
  const products: Product[] = [];
  for (const raw of page) {
    const product = normalizeProduct(raw);
    if (!product) return { data: [], error: new Error("Sunucudan geçersiz ürün kaydı alındı."), nextCursor: null, hasMore: false };
    products.push(product);
  }
  const lastProduct = products.at(-1);
  return {
    data: products,
    error: null,
    nextCursor: page.length === PRODUCT_PAGE_SIZE && lastProduct ? { name: lastProduct.name, id: lastProduct.id } : null,
    hasMore: page.length === PRODUCT_PAGE_SIZE,
  };
}

async function loadProductPageDirectly(organizationId: string, cursor: ProductCursor | null): Promise<ProductPageResult> {
  let query = supabase.from("products")
    .select("id,name,sku,category,unit,stock,min_stock,active,created_at,updated_at")
    .eq("organization_id", organizationId)
    .eq("active", true)
    .order("id", { ascending: true })
    .limit(PRODUCT_PAGE_SIZE);
  if (cursor) query = query.gt("id", cursor.id);
  const result = await retryTransientSupabaseOperation(() => query);
  if (result.error) return { data: [], error: result.error, nextCursor: null, hasMore: false };
  const page = Array.isArray(result.data) ? result.data : [];
  const products: Product[] = [];
  for (const raw of page) {
    const product = normalizeProduct(raw);
    if (!product) return { data: [], error: new Error("Sunucudan geçersiz ürün kaydı alındı."), nextCursor: null, hasMore: false };
    products.push(product);
  }
  const lastProduct = products.at(-1);
  return {
    data: products,
    error: null,
    nextCursor: page.length === PRODUCT_PAGE_SIZE && lastProduct ? { name: lastProduct.name, id: lastProduct.id } : null,
    hasMore: page.length === PRODUCT_PAGE_SIZE,
  };
}

async function loadRecentMovements(organizationId: string): Promise<LoadResult<Movement[]>> {
  const result = await retryTransientSupabaseOperation(() => supabase.rpc("list_stock_movements", {
    p_before_sequence: null,
    p_limit: MOVEMENT_PAGE_SIZE,
  }));
  if (result.error) {
    if (!isMissingRpc(result.error)) return { data: [], error: result.error };
    const fallback = await retryTransientSupabaseOperation(() => supabase.from("stock_movements")
      .select("id,product_id,type,quantity,previous_stock,new_stock,note,actor_id,actor_name,created_at,products(name,sku,unit)")
      .eq("organization_id", organizationId)
      .order("created_at", { ascending: false })
      .order("id", { ascending: false })
      .limit(MOVEMENT_PAGE_SIZE));
    if (fallback.error) return { data: [], error: fallback.error };
    return normalizeMovementPage(fallback.data);
  }
  return normalizeMovementPage(result.data);
}

async function loadInventorySummary(): Promise<LoadResult<InventorySummary>> {
  const result = await retryTransientSupabaseOperation(() => supabase.rpc("get_inventory_summary"));
  if (result.error) return { data: emptyInventorySummary(), error: result.error };
  if (!result.data || typeof result.data !== "object") {
    return { data: emptyInventorySummary(), error: new Error("Stok özeti doğrulanamadı.") };
  }
  const row = Array.isArray(result.data) ? result.data[0] : result.data;
  if (!row || typeof row !== "object") return { data: emptyInventorySummary(), error: new Error("Stok özeti doğrulanamadı.") };
  const candidate = row as Record<string, unknown>;
  const summary = {
    totalProducts: Number(candidate.total_products),
    lowStockProducts: Number(candidate.low_stock_products),
    criticalProducts: Number(candidate.critical_products),
    todayMovements: Number(candidate.today_movements),
  };
  if (Object.values(summary).some((value) => !Number.isSafeInteger(value) || value < 0)) {
    return { data: emptyInventorySummary(), error: new Error("Stok özeti doğrulanamadı.") };
  }
  return { data: summary, error: null };
}

function normalizeProduct(value: unknown): Product | null {
  if (!value || typeof value !== "object") return null;
  const row = value as Record<string, unknown>;
  const stock = Number(row.stock);
  const minStock = Number(row.min_stock);
  if (typeof row.id !== "string" || typeof row.name !== "string" || typeof row.sku !== "string"
    || typeof row.category !== "string" || typeof row.unit !== "string"
    || typeof row.created_at !== "string" || typeof row.updated_at !== "string"
    || !Number.isFinite(stock) || !Number.isFinite(minStock)) return null;
  return { ...row, stock, min_stock: minStock } as Product;
}

function normalizeMovementPage(value: unknown): LoadResult<Movement[]> {
  const page = Array.isArray(value) ? value : [];
  const movements: Movement[] = [];
  for (const raw of page) {
    if (!raw || typeof raw !== "object") return { data: [], error: new Error("Sunucudan geçersiz stok hareketi alındı.") };
    const row = raw as Record<string, unknown>;
    const quantity = Number(row.quantity);
    const previousStock = Number(row.previous_stock);
    const newStock = Number(row.new_stock);
    if (typeof row.id !== "string" || typeof row.product_id !== "string"
      || (row.type !== "in" && row.type !== "out") || !Number.isFinite(quantity)
      || !Number.isFinite(previousStock) || !Number.isFinite(newStock)
      || typeof row.actor_name !== "string" || typeof row.created_at !== "string") {
      return { data: [], error: new Error("Sunucudan geçersiz stok hareketi alındı.") };
    }
    const joinedProduct = Array.isArray(row.products) ? row.products[0] : row.products;
    const product = joinedProduct && typeof joinedProduct === "object"
      ? joinedProduct as { name: string; sku: string; unit: string }
      : typeof row.product_name === "string"
        ? { name: row.product_name, sku: String(row.product_sku ?? ""), unit: String(row.product_unit ?? "") }
        : null;
    movements.push({
      ...row,
      quantity,
      previous_stock: previousStock,
      new_stock: newStock,
      actor_id: typeof row.actor_id === "string" ? row.actor_id : null,
      note: typeof row.note === "string" ? row.note : "",
      products: product,
      event_sequence: typeof row.event_sequence === "number" ? row.event_sequence : undefined,
    } as Movement);
  }
  return { data: movements, error: null };
}

function compareProducts(left: Product, right: Product) {
  return left.name.localeCompare(right.name, "tr-TR", { sensitivity: "base" }) || left.id.localeCompare(right.id);
}

function isMissingRpc(error: unknown) {
  const candidate = error as { code?: string; message?: string };
  return candidate?.code === "PGRST202" || candidate?.code === "42883"
    || /function .* does not exist|schema cache/i.test(candidate?.message ?? "");
}

function readableQueryError(error: QueryFailure, fallback: string) {
  const candidate = error as { message?: string; name?: string };
  if (candidate?.name === "OperationTimeoutError" || /timeout|zaman aşımı/i.test(candidate?.message ?? "")) {
    return "Sunucu yanıt vermedi. Bağlantınızı kontrol edip yeniden deneyin.";
  }
  return candidate?.message?.trim() || fallback;
}

function emptyInventorySummary(): InventorySummary {
  return { totalProducts: 0, lowStockProducts: 0, criticalProducts: 0, todayMovements: 0 };
}

function requestIdForAttempt(ref: { current: WriteAttempt | null }, signature: string) {
  if (ref.current?.signature === signature) return ref.current.requestId;
  if (ref.current) return null;
  const attempt = { signature, requestId: randomUUID() };
  ref.current = attempt;
  return attempt.requestId;
}

function isAmbiguousWriteError(error: unknown) {
  const status = (error as { context?: { status?: number }; status?: number })?.context?.status
    ?? (error as { status?: number })?.status;
  return isTransientSupabaseError(error, status);
}

function unresolvedAttemptMessage() {
  return "Önceki isteğin sonucu henüz doğrulanmadı. Çifte işlem oluşmaması için alanları önceki değerlerine döndürüp aynı isteği tekrar gönderin.";
}

export default function InventoryScreen({ session }: { session: Session }) {
  const [products, setProducts] = useState<Product[]>([]);
  const [movements, setMovements] = useState<Movement[]>([]);
  const [inventorySummary, setInventorySummary] = useState<InventorySummary>(emptyInventorySummary);
  const [productCursor, setProductCursor] = useState<ProductCursor | null>(null);
  const [hasMoreProducts, setHasMoreProducts] = useState(false);
  const [productPageLoading, setProductPageLoading] = useState(false);
  const [displayName, setDisplayName] = useState(session.user.email?.split("@")[0] ?? "Kullanıcı");
  const [username, setUsername] = useState(session.user.email?.split("@")[0] ?? "");
  const [role, setRole] = useState<ProfileRole | null>(null);
  const [organizationId, setOrganizationId] = useState("");
  const [organizationName, setOrganizationName] = useState("İşletme");
  const [subscriptionStatus, setSubscriptionStatus] = useState("active");
  const [trialEndsAt, setTrialEndsAt] = useState<string | null>(null);
  const [currentPeriodEnd, setCurrentPeriodEnd] = useState<string | null>(null);
  const [isPlatformOperator, setIsPlatformOperator] = useState(false);
  const [mustChangePassword, setMustChangePassword] = useState(false);
  const [termsChecked, setTermsChecked] = useState(false);
  const [serverTermsVersion, setServerTermsVersion] = useState<string | null>(null);
  const [serverTermsDigest, setServerTermsDigest] = useState<string | null>(null);
  const [acceptedTermsVersion, setAcceptedTermsVersion] = useState<string | null>(null);
  const [acceptedTermsDigest, setAcceptedTermsDigest] = useState<string | null>(null);
  const [termsError, setTermsError] = useState("");
  const [acceptingTerms, setAcceptingTerms] = useState(false);
  const [reviewTermsModal, setReviewTermsModal] = useState(false);
  const [search, setSearch] = useState("");
  const [onlyLow, setOnlyLow] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [realtimeError, setRealtimeError] = useState("");
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
  const loadRevisionRef = useRef(0);
  const mountedRef = useRef(true);
  const realtimeRefreshRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const productPageRevisionRef = useRef(0);
  const productPageLoadingRef = useRef(false);
  const productFilterRef = useRef({ query: "", onlyLow: false });
  const savingRef = useRef(false);
  const productAttemptRef = useRef<WriteAttempt | null>(null);
  const movementAttemptRef = useRef<WriteAttempt | null>(null);
  const coworkerAttemptRef = useRef<WriteAttempt | null>(null);
  const reportAttemptRef = useRef<WriteAttempt | null>(null);
  const reportSequenceRef = useRef(0);
  const reportSavingRef = useRef(false);
  const termsAcceptanceSequenceRef = useRef(0);
  const termsAcceptanceInFlightRef = useRef(false);
  const requiresTerms = !termsChecked
    || serverTermsVersion !== CURRENT_UGC_TERMS_VERSION
    || serverTermsDigest !== CURRENT_UGC_TERMS_DIGEST
    || acceptedTermsVersion !== serverTermsVersion
    || acceptedTermsDigest !== serverTermsDigest;

  const loadData = useCallback(async (quiet = false) => {
    const revision = ++loadRevisionRef.current;
    const isCurrent = () => mountedRef.current && revision === loadRevisionRef.current;
    // A newer full load owns product paging immediately, even while its
    // profile/terms checks are still pending. This prevents an older product
    // request from leaving the shared loading latch permanently set.
    productPageRevisionRef.current += 1;
    productPageLoadingRef.current = false;
    setProductPageLoading(false);
    if (!quiet) setLoading(true);
    try {
      const profileResult = await retryTransientSupabaseOperation(() => supabase
        .from("profiles")
        .select("display_name,username,role,organization_id,is_platform_operator,must_change_password,ugc_terms_version,ugc_terms_accepted_at,organizations(name,subscription_status,trial_ends_at,current_period_end)")
        .eq("id", session.user.id)
        .maybeSingle());

      if (!isCurrent()) return;
      if (profileResult.error || !profileResult.data?.organization_id) {
        const profileError = readableQueryError(profileResult.error, "İşletme profili bulunamadı.");
        setError(profileError);
        setTermsError(profileError);
        setTermsChecked(false);
        setProducts([]);
        setProductCursor(null);
        setHasMoreProducts(false);
        setMovements([]);
        setInventorySummary(emptyInventorySummary());
        return;
      }

      if (profileResult.data.must_change_password) {
        setMustChangePassword(true);
        return;
      }
      setMustChangePassword(false);

      const profileOrganization = Array.isArray(profileResult.data.organizations)
        ? profileResult.data.organizations[0]
        : profileResult.data.organizations;
      const nextOrganizationId = profileResult.data.organization_id as string;
      if (profileResult.data.display_name) setDisplayName(profileResult.data.display_name);
      if (profileResult.data.username) setUsername(profileResult.data.username);
      if (profileResult.data.role) setRole(profileResult.data.role as ProfileRole);
      setOrganizationId(nextOrganizationId);
      setOrganizationName(profileOrganization?.name ?? "İşletme");
      setSubscriptionStatus(profileOrganization?.subscription_status ?? "active");
      setTrialEndsAt(profileOrganization?.trial_ends_at ?? null);
      setCurrentPeriodEnd(profileOrganization?.current_period_end ?? null);
      setIsPlatformOperator(Boolean(profileResult.data.is_platform_operator));

      const termsResult = await retryTransientSupabaseOperation(() => supabase.rpc("get_ugc_terms_status"));
      if (!isCurrent()) return;
      if (termsResult.error || !termsResult.data) {
        const statusError = readableQueryError(termsResult.error, "Kullanım koşulları durumu alınamadı.");
        setTermsError(statusError);
        setTermsChecked(false);
        setProducts([]);
        setProductCursor(null);
        setHasMoreProducts(false);
        setMovements([]);
        setInventorySummary(emptyInventorySummary());
        return;
      }
      const termsStatus = termsResult.data as {
        current_version?: string;
        current_digest?: string;
        accepted_version?: string | null;
        accepted_digest?: string | null;
        accepted?: boolean;
      };
      const nextServerTermsVersion = termsStatus.current_version ?? null;
      const nextServerTermsDigest = termsStatus.current_digest ?? null;
      setServerTermsVersion(nextServerTermsVersion);
      setServerTermsDigest(nextServerTermsDigest);
      setAcceptedTermsVersion(termsStatus.accepted_version ?? null);
      setAcceptedTermsDigest(termsStatus.accepted_digest ?? null);
      setTermsChecked(true);
      const termsDocumentMatches = nextServerTermsVersion === CURRENT_UGC_TERMS_VERSION
        && nextServerTermsDigest === CURRENT_UGC_TERMS_DIGEST;
      const termsAcceptanceMatches = termsStatus.accepted === true
        && termsStatus.accepted_version === CURRENT_UGC_TERMS_VERSION
        && termsStatus.accepted_digest === CURRENT_UGC_TERMS_DIGEST;
      setTermsError(termsDocumentMatches
        ? ""
        : "Kullanım koşulları güncellendi. Devam etmek için Stokdaş'ın güncel sürümünü yükleyin.");
      if (!termsDocumentMatches || !termsAcceptanceMatches) {
        productPageRevisionRef.current += 1;
        productPageLoadingRef.current = false;
        setProductPageLoading(false);
        setProducts([]);
        setProductCursor(null);
        setHasMoreProducts(false);
        setMovements([]);
        setInventorySummary(emptyInventorySummary());
        setError("");
        return;
      }

      const productRevision = ++productPageRevisionRef.current;
      productPageLoadingRef.current = true;
      setProductPageLoading(true);
      const activeFilter = productFilterRef.current;
      const [productResult, movementResult, summaryResult] = await Promise.all([
        loadProductPage(nextOrganizationId, null, activeFilter.query, activeFilter.onlyLow),
        loadRecentMovements(nextOrganizationId),
        loadInventorySummary(),
      ]);
      if (!isCurrent()) return;

      const queryErrors: string[] = [];
      if (productRevision === productPageRevisionRef.current) {
        productPageLoadingRef.current = false;
        setProductPageLoading(false);
        if (productResult.error) queryErrors.push(readableQueryError(productResult.error, "Ürünler alınamadı."));
        else {
          setProducts(productResult.data);
          setProductCursor(productResult.nextCursor);
          setHasMoreProducts(productResult.hasMore);
        }
      }
      if (movementResult.error) queryErrors.push(readableQueryError(movementResult.error, "Stok hareketleri alınamadı."));
      else setMovements(movementResult.data);
      if (summaryResult.error) queryErrors.push(readableQueryError(summaryResult.error, "Stok özeti alınamadı."));
      else setInventorySummary(summaryResult.data);
      setError(queryErrors.join(" "));
    } catch (loadError) {
      if (isCurrent()) setError(readableQueryError(loadError, "Stok verileri alınamadı."));
    } finally {
      if (isCurrent()) {
        if (!productPageLoadingRef.current) setProductPageLoading(false);
        setLoading(false);
        setRefreshing(false);
      }
    }
  }, [session.user.id]);

  const reloadProductPage = useCallback(async (query: string, onlyLowFilter: boolean) => {
    if (!organizationId) return;
    const revision = ++productPageRevisionRef.current;
    productPageLoadingRef.current = true;
    setProductPageLoading(true);
    const result = await loadProductPage(organizationId, null, query, onlyLowFilter);
    if (!mountedRef.current || revision !== productPageRevisionRef.current) return;
    productPageLoadingRef.current = false;
    setProductPageLoading(false);
    if (result.error) {
      setError(readableQueryError(result.error, "Ürünler alınamadı."));
      return;
    }
    setProducts(result.data);
    setProductCursor(result.nextCursor);
    setHasMoreProducts(result.hasMore);
    setError("");
  }, [organizationId]);

  const loadMoreProducts = useCallback(async () => {
    if (!organizationId || !hasMoreProducts || !productCursor || productPageLoadingRef.current) return;
    const revision = productPageRevisionRef.current;
    productPageLoadingRef.current = true;
    setProductPageLoading(true);
    const activeFilter = productFilterRef.current;
    const result = await loadProductPage(
      organizationId,
      productCursor,
      activeFilter.query,
      activeFilter.onlyLow,
    );
    if (!mountedRef.current || revision !== productPageRevisionRef.current) return;
    productPageLoadingRef.current = false;
    setProductPageLoading(false);
    if (result.error) {
      setHasMoreProducts(false);
      setError(readableQueryError(result.error, "Daha fazla ürün alınamadı."));
      return;
    }
    setProducts((current) => {
      const byId = new Map(current.map((product) => [product.id, product]));
      for (const product of result.data) byId.set(product.id, product);
      return [...byId.values()].sort(compareProducts);
    });
    setProductCursor(result.nextCursor);
    setHasMoreProducts(result.hasMore);
  }, [hasMoreProducts, organizationId, productCursor]);

  useEffect(() => {
    mountedRef.current = true;
    void loadData();
    return () => {
      mountedRef.current = false;
      loadRevisionRef.current += 1;
      productPageRevisionRef.current += 1;
      reportSequenceRef.current += 1;
      termsAcceptanceSequenceRef.current += 1;
      productPageLoadingRef.current = false;
      reportSavingRef.current = false;
      termsAcceptanceInFlightRef.current = false;
      if (realtimeRefreshRef.current) clearTimeout(realtimeRefreshRef.current);
    };
  }, [loadData]);
  useEffect(() => {
    if (!organizationId || requiresTerms) return;
    const timeout = setTimeout(() => {
      const filter = { query: search.trim(), onlyLow };
      productFilterRef.current = filter;
      void reloadProductPage(filter.query, filter.onlyLow);
    }, 300);
    return () => clearTimeout(timeout);
  }, [onlyLow, organizationId, reloadProductPage, requiresTerms, search]);
  useEffect(() => {
    if (!organizationId || requiresTerms) return;
    const filter = `organization_id=eq.${organizationId}`;
    const scheduleRefresh = () => {
      if (realtimeRefreshRef.current) clearTimeout(realtimeRefreshRef.current);
      realtimeRefreshRef.current = setTimeout(() => {
        realtimeRefreshRef.current = null;
        void loadData(true);
      }, 250);
    };
    const channel = supabase.channel(`stokta-live-${organizationId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "products", filter }, scheduleRefresh)
      .on("postgres_changes", { event: "*", schema: "public", table: "stock_movements", filter }, scheduleRefresh)
      .subscribe((status) => {
        if (!mountedRef.current) return;
        if (status === "SUBSCRIBED") setRealtimeError("");
        else if (status === "CHANNEL_ERROR" || status === "TIMED_OUT") {
          setRealtimeError("Canlı güncellemeler kesildi. Listeyi yenileyerek güncel veriyi alabilirsiniz.");
        }
      });
    return () => {
      if (realtimeRefreshRef.current) clearTimeout(realtimeRefreshRef.current);
      realtimeRefreshRef.current = null;
      void supabase.removeChannel(channel);
    };
  }, [loadData, organizationId, requiresTerms]);
  useEffect(() => {
    const appStateSubscription = AppState.addEventListener("change", (state) => {
      if (state === "active") void loadData(true);
    });
    return () => appStateSubscription.remove();
  }, [loadData]);
  useEffect(() => {
    const selectedId = selectedProduct?.id;
    if (!selectedId) return;
    const latest = products.find((product) => product.id === selectedId);
    if (!latest) {
      setSelectedProduct(null);
      setMovementModal(false);
      return;
    }
    if (latest !== selectedProduct) setSelectedProduct(latest);
  }, [products, selectedProduct]);

  const filteredProducts = useMemo(() => {
    const query = search.trim().toLocaleLowerCase("tr-TR");
    return products.filter((product) => {
      const matches = !query || `${product.name} ${product.sku} ${product.category}`.toLocaleLowerCase("tr-TR").includes(query);
      return matches && (!onlyLow || product.stock <= product.min_stock);
    });
  }, [products, search, onlyLow]);

  const hasProductFilter = Boolean(search.trim()) || onlyLow;
  const firstName = displayName.split(" ")[0] || displayName;
  const isAdmin = role === "admin";
  const now = Date.now();
  const canWrite = (subscriptionStatus === "trial" && Boolean(trialEndsAt) && new Date(trialEndsAt ?? 0).getTime() > now)
    || (subscriptionStatus === "active" && (!currentPeriodEnd || new Date(currentPeriodEnd).getTime() > now));
  const subscriptionLabel = subscriptionStatus === "trial" ? "Deneme"
    : subscriptionStatus === "active" ? "Aktif"
    : subscriptionStatus === "past_due" ? "Ödeme bekliyor"
    : subscriptionStatus === "suspended" ? "Askıda"
    : "İptal edildi";

  function requireWritable() {
    if (canWrite) return true;
    Alert.alert("İşletme hesabı işlem yapmaya kapalı", "Abonelik durumunu yenilemek için işletme yöneticisinin Google Play ödeme ekranını kullanması gerekir.");
    return false;
  }

  async function acceptTerms() {
    if (termsAcceptanceInFlightRef.current) return;
    termsAcceptanceInFlightRef.current = true;
    const sequence = ++termsAcceptanceSequenceRef.current;
    setAcceptingTerms(true);
    setTermsError("");
    const { data, error: acceptError } = await retryTransientSupabaseOperation(() => supabase.rpc("accept_current_ugc_terms", {
      p_version: CURRENT_UGC_TERMS_VERSION,
      p_digest: CURRENT_UGC_TERMS_DIGEST,
    }));
    if (!mountedRef.current || sequence !== termsAcceptanceSequenceRef.current) return;
    termsAcceptanceInFlightRef.current = false;
    setAcceptingTerms(false);
    if (acceptError) {
      setTermsError(acceptError.message);
      return;
    }
    const response = data as {
      accepted?: boolean;
      accepted_version?: string;
      accepted_digest?: string;
      current_version?: string;
      current_digest?: string;
    } | null;
    if (!response?.accepted
      || response.accepted_version !== CURRENT_UGC_TERMS_VERSION
      || response.current_version !== CURRENT_UGC_TERMS_VERSION
      || response.accepted_digest !== CURRENT_UGC_TERMS_DIGEST
      || response.current_digest !== CURRENT_UGC_TERMS_DIGEST) {
      setTermsError("Koşul kabulü doğrulanamadı. Lütfen yeniden deneyin.");
      return;
    }
    setAcceptedTermsVersion(response.accepted_version);
    setAcceptedTermsDigest(response.accepted_digest);
    setServerTermsVersion(response.current_version);
    setServerTermsDigest(response.current_digest);
    setTermsChecked(true);
    setReviewTermsModal(false);
    await loadData(true);
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
      Alert.alert("Kendi hesabınızı bildiremezsiniz", "Başka bir ekip üyesinin hareketindeki “Kullanıcıyı bildir” seçeneğini kullanabilirsiniz.");
      return;
    }
    setReportError("");
    setReportTarget({ type: "user", id: movement.actor_id, label: movement.actor_name });
  }

  async function submitReport(reason: ContentReportReason, details: string) {
    if (!reportTarget || reportSavingRef.current) return;
    const target = reportTarget;
    const normalizedDetails = details.trim();
    const signature = JSON.stringify({ targetType: target.type, targetId: target.id, reason, details: normalizedDetails });
    const requestId = requestIdForAttempt(reportAttemptRef, signature);
    if (!requestId) {
      setReportError(unresolvedAttemptMessage());
      return;
    }
    const sequence = ++reportSequenceRef.current;
    reportSavingRef.current = true;
    setReportSaving(true);
    setReportError("");
    const { data, error: submitError } = await retryTransientSupabaseOperation(() => supabase.rpc("report_content", {
      p_target_type: target.type,
      p_target_id: target.id,
      p_reason: reason,
      p_details: normalizedDetails,
      p_request_id: requestId,
    }));
    if (!mountedRef.current || sequence !== reportSequenceRef.current) return;
    reportSavingRef.current = false;
    setReportSaving(false);
    if (submitError) {
      if (!isAmbiguousWriteError(submitError)) reportAttemptRef.current = null;
      setReportError(submitError.message);
      return;
    }
    const result = data as { report_id?: string; status?: string; request_id?: string } | null;
    if (typeof result?.report_id !== "string" || result.status !== "open" || result.request_id !== requestId) {
      setReportError("Bildirim için sunucu onayı doğrulanamadı. Aynı bilgilerle yeniden deneyin.");
      return;
    }
    reportAttemptRef.current = null;
    setReportTarget(null);
    Alert.alert("Bildirim alındı", "Bildirim, hedefin rolüne göre yetkili inceleme kuyruğuna iletildi.");
  }

  function openCreate() { if (!isAdmin || !requireWritable()) return; setEditing(null); setDraft(emptyDraft); setProductModal(true); }
  function openEdit(product: Product) {
    if (!isAdmin || !requireWritable()) return;
    setEditing(product);
    setDraft({ name: product.name, sku: product.sku, category: product.category, unit: product.unit, stock: String(product.stock), minStock: String(product.min_stock) });
    setProductModal(true);
  }
  function openMovement(product: Product, type: "in" | "out") {
    if (!requireWritable()) return;
    setSelectedProduct(product); setMovementType(type); setQuantity(""); setNote(""); setMovementModal(true);
  }

  function closeProductEditor() {
    if (savingRef.current || productAttemptRef.current) {
      Alert.alert("İşlem sonucu bekleniyor", unresolvedAttemptMessage());
      return;
    }
    setProductModal(false);
  }

  function closeMovementEditor() {
    if (savingRef.current || movementAttemptRef.current) {
      Alert.alert("İşlem sonucu bekleniyor", unresolvedAttemptMessage());
      return;
    }
    setMovementModal(false);
  }

  function closeCoworkerEditor() {
    if (savingRef.current || coworkerAttemptRef.current) {
      Alert.alert("İşlem sonucu bekleniyor", unresolvedAttemptMessage());
      return;
    }
    setCoworkerModal(false);
  }

  function closeContentReport() {
    if (reportSavingRef.current || reportAttemptRef.current) {
      setReportError(unresolvedAttemptMessage());
      return;
    }
    setReportTarget(null);
  }

  async function saveProduct() {
    if (!isAdmin || savingRef.current) return;
    if (!draft.name.trim() || !draft.sku.trim()) { Alert.alert("Eksik bilgi", "Ürün adı ve ürün kodu zorunludur."); return; }
    const stock = Number(draft.stock.replace(",", "."));
    const minStock = Number(draft.minStock.replace(",", "."));
    if (!Number.isFinite(stock) || stock < 0 || !Number.isFinite(minStock) || minStock < 0) { Alert.alert("Hatalı miktar", "Stok değerleri negatif olamaz."); return; }
    const signature = JSON.stringify({
      operation: editing ? "update" : "create",
      productId: editing?.id ?? null,
      expectedUpdatedAt: editing?.updated_at ?? null,
      name: draft.name.trim(),
      sku: draft.sku.trim(),
      category: draft.category.trim(),
      unit: draft.unit.trim(),
      stock,
      minStock,
    });
    const requestId = requestIdForAttempt(productAttemptRef, signature);
    if (!requestId) { Alert.alert("Önceki işlem bekliyor", unresolvedAttemptMessage()); return; }
    savingRef.current = true;
    setSaving(true);
    const args = editing ? {
      p_product_id: editing.id, p_name: draft.name.trim(), p_sku: draft.sku.trim(),
      p_category: draft.category.trim(), p_unit: draft.unit.trim(), p_min_stock: minStock,
      p_expected_updated_at: editing.updated_at, p_request_id: requestId,
    } : {
      p_name: draft.name.trim(), p_sku: draft.sku.trim(), p_category: draft.category.trim(),
      p_unit: draft.unit.trim(), p_stock: stock, p_min_stock: minStock, p_request_id: requestId,
    };
    const { data: saveData, error: saveError } = await retryTransientSupabaseOperation(() => supabase.rpc(
      editing ? "update_inventory_product" : "create_inventory_product",
      args,
    ));
    savingRef.current = false;
    setSaving(false);
    if (saveError) {
      if (!isAmbiguousWriteError(saveError)) productAttemptRef.current = null;
      Alert.alert("Kaydedilemedi", friendlyError(saveError.message));
      return;
    }
    const savedProduct = normalizeProduct(Array.isArray(saveData) ? saveData[0] : saveData);
    const expectedCategory = draft.category.trim() || "Genel";
    const expectedUnit = (draft.unit.trim() || "adet").toLowerCase();
    if (!savedProduct
      || (editing && savedProduct.id !== editing.id)
      || savedProduct.name !== draft.name.trim()
      || savedProduct.sku !== draft.sku.trim().toUpperCase()
      || savedProduct.category !== expectedCategory
      || savedProduct.unit !== expectedUnit
      || Math.abs(savedProduct.min_stock - Math.round(minStock * 1_000) / 1_000) > 0.000_001
      || (!editing && Math.abs(savedProduct.stock - Math.round(stock * 1_000) / 1_000) > 0.000_001)) {
      Alert.alert("Kayıt sonucu doğrulanamadı", "Sunucudan beklenen ürün kaydı alınamadı. Aynı bilgilerle yeniden deneyin.");
      return;
    }
    productAttemptRef.current = null;
    setProductModal(false); await loadData(true);
  }

  async function saveMovement() {
    if (!selectedProduct || savingRef.current) return;
    const amount = Number(quantity.replace(",", "."));
    if (!Number.isFinite(amount) || amount <= 0) { Alert.alert("Hatalı miktar", "Sıfırdan büyük bir miktar girin."); return; }
    if (movementType === "out" && amount > selectedProduct.stock) { Alert.alert("Yetersiz stok", `Stokta yalnızca ${formatQty(selectedProduct.stock)} ${selectedProduct.unit} bulunuyor.`); return; }
    const signature = JSON.stringify({ productId: selectedProduct.id, type: movementType, amount, note: note.trim() });
    const requestId = requestIdForAttempt(movementAttemptRef, signature);
    if (!requestId) { Alert.alert("Önceki işlem bekliyor", unresolvedAttemptMessage()); return; }
    savingRef.current = true;
    setSaving(true);
    const { data: movementData, error: movementError } = await retryTransientSupabaseOperation(() => supabase.rpc(
      "record_stock_movement",
      { p_product_id: selectedProduct.id, p_type: movementType, p_quantity: amount, p_note: note.trim(), p_request_id: requestId },
    ));
    savingRef.current = false;
    setSaving(false);
    if (movementError) {
      if (!isAmbiguousWriteError(movementError)) movementAttemptRef.current = null;
      Alert.alert("İşlem yapılamadı", friendlyError(movementError.message));
      await loadData(true);
      return;
    }
    const movementResult = movementData as {
      movement_id?: unknown;
      event_sequence?: unknown;
      product_id?: unknown;
      previous_stock?: unknown;
      new_stock?: unknown;
      product_updated_at?: unknown;
    } | null;
    const confirmedStock = Number(movementResult?.new_stock);
    if (typeof movementResult?.movement_id !== "string"
      || !Number.isSafeInteger(Number(movementResult.event_sequence))
      || Number(movementResult.event_sequence) < 1
      || movementResult.product_id !== selectedProduct.id
      || !Number.isFinite(Number(movementResult.previous_stock))
      || !Number.isFinite(confirmedStock)
      || confirmedStock < 0
      || typeof movementResult.product_updated_at !== "string"
      || !Number.isFinite(Date.parse(movementResult.product_updated_at))) {
      Alert.alert("İşlem sonucu doğrulanamadı", "Sunucudan beklenen stok hareketi onayı alınamadı. Aynı işlemle yeniden deneyin.");
      await loadData(true);
      return;
    }
    movementAttemptRef.current = null;
    setProducts((current) => current.map((product) => (
      product.id === selectedProduct.id
        ? { ...product, stock: confirmedStock, updated_at: movementResult.product_updated_at as string }
        : product
    )));
    setMovementModal(false); await loadData(true);
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
    if (!isAdmin || savingRef.current) return;
    const normalizedUsername = normalizeUsername(coworkerUsername);
    const normalizedEmail = coworkerEmail.trim().toLowerCase();
    if (!coworkerName.trim()) { Alert.alert("Eksik bilgi", "Çalışanın adını girin."); return; }
    if (normalizedUsername.length < 3) { Alert.alert("Hatalı kullanıcı adı", "Kullanıcı adı en az 3 karakter olmalı."); return; }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normalizedEmail)) { Alert.alert("Hatalı e-posta", "Çalışanın doğrulama e-postasını girin."); return; }
    if (!isStrongPassword(coworkerPassword)) { Alert.alert("Hatalı şifre", "Şifre 8-72 karakter olmalı; büyük harf, küçük harf, rakam ve sembol içermeli."); return; }
    if (coworkerPassword !== coworkerPasswordAgain) { Alert.alert("Şifreler eşleşmiyor", "İki alana aynı şifreyi girin."); return; }

    const signature = JSON.stringify({ username: normalizedUsername, recoveryEmail: normalizedEmail, displayName: coworkerName.trim(), password: coworkerPassword });
    const requestId = requestIdForAttempt(coworkerAttemptRef, signature);
    if (!requestId) { Alert.alert("Önceki işlem bekliyor", unresolvedAttemptMessage()); return; }
    savingRef.current = true;
    setSaving(true);
    const { data: createData, error: createError } = await retryTransientSupabaseOperation(() => supabase.functions.invoke("create-coworker", {
      body: { username: normalizedUsername, displayName: coworkerName.trim(), recoveryEmail: normalizedEmail, password: coworkerPassword, requestId },
    }));
    savingRef.current = false;
    setSaving(false);
    if (createError) {
      if (!isAmbiguousWriteError(createError)) coworkerAttemptRef.current = null;
      Alert.alert("Çalışan oluşturulamadı", await edgeFunctionError(createError));
      return;
    }
    const coworkerResult = createData as {
      accepted?: unknown;
      verificationRequired?: unknown;
      requestId?: unknown;
    } | null;
    if (coworkerResult?.accepted !== true
      || coworkerResult.verificationRequired !== true
      || !isDeletionRequestId(coworkerResult.requestId)) {
      Alert.alert("Çalışan oluşturulamadı", "Sunucunun davet onayı doğrulanamadı. Aynı bilgilerle yeniden deneyin.");
      return;
    }
    coworkerAttemptRef.current = { signature, requestId: coworkerResult.requestId };
    coworkerAttemptRef.current = null;
    setCoworkerModal(false);
    Alert.alert("Doğrulama gönderildi", `${coworkerName.trim()} için doğrulama kodu ${normalizedEmail} adresine gönderildi. Çalışan “${normalizedUsername}” kullanıcı adıyla giriş yapıp kodu tamamlayabilir.`);
  }

  async function signOut() {
    Alert.alert("Çıkış yapılsın mı?", "Bu cihazdaki oturum kapatılacak.", [
      { text: "Vazgeç", style: "cancel" },
      { text: "Çıkış yap", style: "destructive", onPress: () => void supabase.auth.signOut() },
    ]);
  }

  async function deleteAccount(confirmation: string, currentPassword: string) {
    if (savingRef.current) return;
    if (!organizationId) {
      Alert.alert("Hesap silinemedi", "İşletme kimliği doğrulanamadı. Ekranı yenileyip tekrar deneyin.");
      return;
    }
    savingRef.current = true;
    setSaving(true);
    let requestLaunched = false;
    try {
      const savedIntent = await readAccountDeletionIntent(session.user.id, organizationId);
      let deletionRequestId = savedIntent?.deletionRequestId ?? randomUUID();
      await saveAccountDeletionIntent(session.user.id, organizationId, deletionRequestId);

      requestLaunched = true;
      const { data: deleteData, error: deleteError } = await retryTransientSupabaseOperation(
        () => supabase.functions.invoke("delete-account", {
          body: { confirmation, currentPassword, deletionRequestId },
        }),
        750,
        45_000,
      );
      if (deleteError) {
        const details = await deletionFunctionErrorDetails(deleteError);
        if (details.deletionRequestId) {
          deletionRequestId = details.deletionRequestId;
          await saveAccountDeletionIntent(session.user.id, organizationId, deletionRequestId);
        }
        if (details.code && CLEARABLE_DELETION_CODES.has(details.code)) {
          await clearAccountDeletionIntent(session.user.id, organizationId);
        }
        Alert.alert("Hesap silinemedi", details.message);
        return;
      }
      const deletionResult = deleteData as { deleted?: boolean; scope?: unknown; deletionRequestId?: unknown } | null;
      const canonicalRequestId = deletionResult?.deletionRequestId;
      if (deletionResult?.deleted !== true
        || (deletionResult.scope !== "account" && deletionResult.scope !== "organization")
        || !isDeletionRequestId(canonicalRequestId)) {
        Alert.alert("Silme sonucu doğrulanamadı", "Sunucunun silme onayı doğrulanamadı. Aynı ekrandan yeniden deneyin.");
        return;
      }

      // The server can resume a pre-existing saga and return its canonical ID.
      // Persist it before treating the terminal response as complete so a
      // process interruption can still replay the exact server operation.
      await saveAccountDeletionIntent(session.user.id, organizationId, canonicalRequestId);
      await clearAccountDeletionIntent(session.user.id, organizationId).catch(() => undefined);
      setAccountModal(false);
      await retryTransientSupabaseOperation(
        () => supabase.auth.signOut({ scope: "local" }),
        250,
        8_000,
      );
      Alert.alert(
        "Silme tamamlandı",
        isAdmin
          ? "İşletmenin aktif çalışma alanı ve hesap erişimleri kaldırıldı. Sınırlı teknik kayıtların saklama süreleri Gizlilik Politikası'nda açıklanır."
          : "Hesap erişiminiz ve kişisel profiliniz kaldırıldı. Sınırlı teknik kayıtların saklama süreleri Gizlilik Politikası'nda açıklanır.",
      );
    } catch {
      Alert.alert(
        requestLaunched ? "Silme sonucu doğrulanamadı" : "Silme başlatılamadı",
        requestLaunched
          ? "Sunucu sonucu doğrulanamadı. Güvenli silme kimliği bu cihazda korunuyor; aynı ekrandan tekrar deneyin."
          : "Güvenli silme isteği bu cihazda saklanamadığı için işlem başlatılmadı. Depolama erişimini kontrol edip tekrar deneyin.",
      );
    } finally {
      savingRef.current = false;
      if (mountedRef.current) setSaving(false);
    }
  }

  if (mustChangePassword) return <ForcedPasswordChange />;

  return (
    <SafeAreaView style={styles.safe} edges={["top"]}>
      <FlatList
        data={filteredProducts}
        onEndReached={() => void loadMoreProducts()}
        onEndReachedThreshold={0.35}
        scrollEnabled={!requiresTerms}
        keyExtractor={(item) => item.id}
        refreshControl={<RefreshControl refreshing={refreshing} tintColor="#1f7353" colors={["#1f7353"]} onRefresh={() => { setRefreshing(true); void loadData(true); }} />}
        contentContainerStyle={styles.listContent}
        ListHeaderComponent={<>
          <View style={styles.header}>
            <View><Text style={styles.date}>{formatDate(new Date())}</Text><Text style={styles.greeting}>Merhaba, {firstName}</Text><Text style={styles.organization}>{organizationName}</Text></View>
            <View style={styles.headerActions}>
              {isPlatformOperator ? <Pressable style={styles.platformButton} onPress={() => setPlatformModal(true)}><Text style={styles.platformButtonText}>İşletmeler</Text></Pressable> : null}
              {isAdmin ? <Pressable style={styles.addCoworker} onPress={openCoworker}><Text style={styles.addCoworkerText}>＋ Çalışan</Text></Pressable> : null}
              <Pressable style={styles.avatar} onPress={() => setAccountModal(true)}><Text style={styles.avatarText}>{initials(displayName)}</Text></Pressable>
            </View>
          </View>
          {error || realtimeError ? <Pressable style={styles.errorBanner} onPress={() => { setRealtimeError(""); void loadData(); }}><Text style={styles.errorText}>{[error, realtimeError].filter(Boolean).join(" ")}</Text><Text style={styles.retry}>Tekrar dene</Text></Pressable> : null}
          {!canWrite ? <View style={styles.subscriptionBanner}>
            <Text style={styles.subscriptionBannerTitle}>Abonelik durumu: {subscriptionLabel}</Text>
            <Text style={styles.subscriptionBannerText}>Veriler görüntülenebilir; stok ve kullanıcı değişiklikleri geçici olarak kapalıdır.</Text>
            {isAdmin && !isPlatformOperator ? <Pressable
              style={styles.subscriptionAction}
              onPress={openSubscription}
              accessibilityRole="button"
              accessibilityLabel="Google Play aboneliğini yenile"
            >
              <Text style={styles.subscriptionActionText}>{["Ödeme bekliyor", "Askıda"].includes(subscriptionLabel) ? "Google Play'de yönet" : "Google Play'den yenile"}</Text>
            </Pressable> : null}
          </View> : null}
          <View style={styles.statsGrid}>
            <StatCard label="TOPLAM ÜRÜN" value={inventorySummary.totalProducts} caption="Aktif ürün çeşidi" tone="green" />
            <StatCard label="AZALAN STOK" value={inventorySummary.lowStockProducts} caption={inventorySummary.criticalProducts ? `${inventorySummary.criticalProducts} ürün tükendi` : "Kontrol bekliyor"} tone="amber" />
            <StatCard label="BUGÜNKÜ İŞLEM" value={inventorySummary.todayMovements} caption="Buluta kaydedildi" tone="blue" />
          </View>
          <View style={styles.sectionHead}><View><Text style={styles.eyebrow}>ANLIK LİSTE</Text><Text style={styles.sectionTitle}>Stok kontrolü</Text></View><Pressable style={[styles.lowFilter, onlyLow && styles.lowFilterActive]} onPress={() => setOnlyLow((value) => !value)}><Text style={[styles.lowFilterText, onlyLow && styles.lowFilterTextActive]}>{onlyLow ? "Tümü" : "Azalanlar"}</Text></Pressable></View>
          <View style={styles.searchBox}><Text style={styles.searchIcon}>⌕</Text><TextInput style={styles.searchInput} value={search} onChangeText={setSearch} placeholder="Ürün, kod veya kategori ara" placeholderTextColor="#959d98" /></View>
          {loading || (productPageLoading && !products.length) ? <View style={styles.loadingBox}><ActivityIndicator color="#1f7353" /><Text style={styles.loadingText}>Stoklar yükleniyor…</Text></View> : null}
        </>}
        renderItem={({ item }) => <ProductCard product={item} canEdit={isAdmin} onEdit={() => openEdit(item)} onIn={() => openMovement(item, "in")} onOut={() => openMovement(item, "out")} onReport={() => openProductReport(item)} />}
        ListEmptyComponent={!loading && !productPageLoading ? <View style={styles.empty}><Text style={styles.emptyIcon}>□</Text><Text style={styles.emptyTitle}>{hasProductFilter ? "Aramana uygun ürün yok" : isAdmin ? "İlk ürününü ekle" : "Henüz ürün eklenmedi"}</Text><Text style={styles.emptyBody}>{hasProductFilter ? "Aramayı veya filtreyi değiştir." : isAdmin ? "Ürün kodunu, birimini ve uyarı sınırını tanımlayarak başlayabilirsin." : "Yönetici ilk ürünü eklediğinde burada görünecek."}</Text>{!hasProductFilter && isAdmin ? <Pressable style={styles.primaryButton} onPress={openCreate}><Text style={styles.primaryButtonText}>＋ İlk ürünü ekle</Text></Pressable> : null}</View> : null}
        ListFooterComponent={<>
          {productPageLoading && products.length ? <View style={styles.pageLoading}><ActivityIndicator color="#1f7353" /><Text style={styles.loadingText}>Daha fazla ürün yükleniyor…</Text></View> : null}
          <MovementHistory movements={movements.slice(0, 8)} onReportContent={openMovementReport} onReportActor={openActorReport} />
        </>}
      />
      {isAdmin && canWrite ? <Pressable style={styles.fab} onPress={openCreate}><Text style={styles.fabText}>＋</Text></Pressable> : null}
      {isAdmin ? <ProductEditor visible={productModal} editing={editing} draft={draft} setDraft={setDraft} saving={saving} onClose={closeProductEditor} onSave={saveProduct} /> : null}
      <MovementEditor visible={movementModal} product={selectedProduct} type={movementType} setType={setMovementType} quantity={quantity} setQuantity={setQuantity} note={note} setNote={setNote} saving={saving} onClose={closeMovementEditor} onSave={saveMovement} />
      {isAdmin ? <CoworkerEditor visible={coworkerModal} name={coworkerName} setName={setCoworkerName} username={coworkerUsername} setUsername={setCoworkerUsername} email={coworkerEmail} setEmail={setCoworkerEmail} password={coworkerPassword} setPassword={setCoworkerPassword} passwordAgain={coworkerPasswordAgain} setPasswordAgain={setCoworkerPasswordAgain} saving={saving} onClose={closeCoworkerEditor} onSave={saveCoworker} /> : null}
      <AccountModal visible={accountModal} displayName={displayName} username={username} role={role} organizationName={organizationName} subscriptionLabel={subscriptionLabel} isPlatformOperator={isPlatformOperator} saving={saving} onClose={() => setAccountModal(false)} onOpenSubscription={openSubscription} onOpenTerms={reviewTerms} onOpenSafetyCenter={() => openSafetyCenter("organization")} onOpenPlatformSafetyCenter={() => openSafetyCenter("platform")} onSignOut={signOut} onDelete={deleteAccount} />
      {isAdmin && !isPlatformOperator ? <SubscriptionModal
        visible={subscriptionModal}
        userId={session.user.id}
        organizationId={organizationId}
        subscriptionLabel={subscriptionLabel}
        trialEndsAt={trialEndsAt}
        currentPeriodEnd={currentPeriodEnd}
        onClose={() => setSubscriptionModal(false)}
        onSubscriptionUpdated={() => loadData(true)}
      /> : null}
      {isPlatformOperator ? <PlatformModal visible={platformModal} onClose={() => setPlatformModal(false)} /> : null}
      {isAdmin || isPlatformOperator ? <SafetyCenterModal scope={safetyCenterScope} visible={safetyCenterModal} onClose={() => setSafetyCenterModal(false)} onModerated={() => void loadData(true)} /> : null}
      <ContentReportModal target={reportTarget} saving={reportSaving} error={reportError} onClose={closeContentReport} onSubmit={submitReport} />
      <TermsModal
        visible={requiresTerms || reviewTermsModal}
        mandatory={requiresTerms}
        accepted={termsChecked
          && serverTermsVersion === CURRENT_UGC_TERMS_VERSION
          && serverTermsDigest === CURRENT_UGC_TERMS_DIGEST
          && acceptedTermsVersion === CURRENT_UGC_TERMS_VERSION
          && acceptedTermsDigest === CURRENT_UGC_TERMS_DIGEST}
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

function StatCard({ label, value, caption, tone }: { label: string; value: number; caption: string; tone: "green" | "amber" | "blue" }) {
  const toneStyle = { green: styles.stat_green, amber: styles.stat_amber, blue: styles.stat_blue }[tone];
  return <View style={styles.statCard}><View style={[styles.statDot, toneStyle]} /><Text style={styles.statLabel}>{label}</Text><Text style={styles.statValue}>{value}</Text><Text style={styles.statCaption}>{caption}</Text></View>;
}

function ProductCard({ product, canEdit, onEdit, onIn, onOut, onReport }: { product: Product; canEdit: boolean; onEdit: () => void; onIn: () => void; onOut: () => void; onReport: () => void }) {
  const status = product.stock === 0 ? "Tükendi" : product.stock <= product.min_stock ? "Azaldı" : "Yeterli";
  return (
    <View style={styles.productCard}>
      <Pressable style={styles.productInfo} onPress={onEdit} disabled={!canEdit}>
        <View style={styles.productTop}><View style={styles.productMark}><Text style={styles.productMarkText}>{product.name[0]?.toLocaleUpperCase("tr-TR")}</Text></View><View style={styles.productNames}><Text style={styles.productName} numberOfLines={1}>{product.name}</Text><Text style={styles.productMeta}>{product.sku} · {product.category}</Text></View><View style={[styles.badge, status === "Yeterli" ? styles.badgeOk : status === "Tükendi" ? styles.badgeCritical : styles.badgeLow]}><Text style={[styles.badgeText, status === "Yeterli" ? styles.badgeTextOk : status === "Tükendi" ? styles.badgeTextCritical : styles.badgeTextLow]}>{status}</Text></View></View>
        <View style={styles.stockRow}><View><Text style={styles.stockLabel}>MEVCUT STOK</Text><Text style={styles.stockValue}>{formatQty(product.stock)} <Text style={styles.stockUnit}>{product.unit}</Text></Text></View><View style={styles.minBox}><Text style={styles.stockLabel}>UYARI SINIRI</Text><Text style={styles.minValue}>{formatQty(product.min_stock)} {product.unit}</Text></View></View>
      </Pressable>
      <View style={styles.productActions}>
        <Pressable accessibilityRole="button" accessibilityLabel={`${product.name} ürününe stok ekle`} style={styles.actionIn} onPress={onIn}><Text style={styles.actionInText}>＋ Stok ekle</Text></Pressable>
        <Pressable accessibilityRole="button" accessibilityLabel={`${product.name} ürününden stok düş`} style={styles.actionOut} onPress={onOut}><Text style={styles.actionOutText}>− Stoktan düş</Text></Pressable>
        <Pressable accessibilityRole="button" accessibilityLabel={`${product.name} ürününü bildir`} style={styles.actionReport} onPress={onReport}><Text style={styles.actionReportText}>⚑ Bildir</Text></Pressable>
      </View>
    </View>
  );
}

function MovementHistory({ movements, onReportContent, onReportActor }: { movements: Movement[]; onReportContent: (movement: Movement) => void; onReportActor: (movement: Movement) => void }) {
  return (
    <View style={styles.history}>
      <Text style={styles.eyebrow}>CANLI KAYIT</Text>
      <Text style={styles.sectionTitle}>Son hareketler</Text>
      {movements.length ? movements.map((movement) => (
        <View style={styles.movementItem} key={movement.id}>
          <View style={styles.movementRow}>
            <View style={[styles.movementIcon, movement.type === "in" ? styles.movementIn : styles.movementOut]}><Text style={movement.type === "in" ? styles.movementInText : styles.movementOutText}>{movement.type === "in" ? "＋" : "−"}</Text></View>
            <View style={styles.movementBody}><Text style={styles.movementName}>{movement.products?.name ?? "Ürün"}</Text><Text style={styles.movementDetail} numberOfLines={3}>{movement.actor_name} · {formatQty(movement.quantity)} {movement.products?.unit ?? ""}{movement.note ? ` · ${movement.note}` : ""}</Text></View>
            <Text style={styles.movementTime}>{shortTime(movement.created_at)}</Text>
          </View>
          <View style={styles.movementReportActions}>
            {movement.note ? <Pressable accessibilityRole="button" accessibilityLabel="Bu stok hareketinin içeriğini bildir" style={styles.movementReportButton} onPress={() => onReportContent(movement)}><Text style={styles.movementReportText}>⚑ İçeriği bildir</Text></Pressable> : null}
            {movement.actor_id ? <Pressable accessibilityRole="button" accessibilityLabel={`${movement.actor_name} kullanıcısını bildir`} style={styles.movementReportButton} onPress={() => onReportActor(movement)}><Text style={styles.movementReportText}>⚑ Kullanıcıyı bildir</Text></Pressable> : null}
          </View>
        </View>
      )) : <Text style={styles.historyEmpty}>Henüz stok hareketi yok.</Text>}
    </View>
  );
}

function ProductEditor({ visible, editing, draft, setDraft, saving, onClose, onSave }: { visible: boolean; editing: Product | null; draft: ProductDraft; setDraft: (value: ProductDraft) => void; saving: boolean; onClose: () => void; onSave: () => void }) {
  return <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}><KeyboardAvoidingView style={styles.modalBackdrop} behavior={Platform.OS === "ios" ? "padding" : undefined}><View style={styles.modalSheet}><View style={styles.modalHandle} /><View style={styles.modalHead}><View><Text style={styles.eyebrow}>ÜRÜN KARTI</Text><Text style={styles.modalTitle}>{editing ? "Ürünü düzenle" : "Yeni ürün ekle"}</Text></View><Pressable style={styles.closeButton} onPress={onClose}><Text style={styles.closeText}>×</Text></Pressable></View><Field label="Ürün adı" value={draft.name} onChangeText={(name) => setDraft({ ...draft, name })} placeholder="Örn. Koli Bandı 45 mm" autoFocus /><View style={styles.formRow}><View style={styles.half}><Field label="Ürün kodu" value={draft.sku} onChangeText={(sku) => setDraft({ ...draft, sku })} placeholder="AMB-045" autoCapitalize="characters" /></View><View style={styles.half}><Field label="Kategori" value={draft.category} onChangeText={(category) => setDraft({ ...draft, category })} placeholder="Ambalaj" /></View></View><View style={styles.formRow}><View style={styles.half}><Field label="Birim" value={draft.unit} onChangeText={(unit) => setDraft({ ...draft, unit })} placeholder="adet" /></View><View style={styles.half}><Field label="Uyarı sınırı" value={draft.minStock} onChangeText={(minStock) => setDraft({ ...draft, minStock })} placeholder="0" keyboardType="decimal-pad" /></View></View>{!editing ? <Field label="Başlangıç stoku" value={draft.stock} onChangeText={(stock) => setDraft({ ...draft, stock })} placeholder="0" keyboardType="decimal-pad" /> : null}<Pressable style={[styles.saveButton, saving && styles.disabled]} onPress={onSave} disabled={saving}>{saving ? <ActivityIndicator color="#172820" /> : <Text style={styles.saveButtonText}>{editing ? "Değişiklikleri kaydet" : "Ürünü ekle"}</Text>}</Pressable></View></KeyboardAvoidingView></Modal>;
}

function MovementEditor({ visible, product, type, setType, quantity, setQuantity, note, setNote, saving, onClose, onSave }: { visible: boolean; product: Product | null; type: "in" | "out"; setType: (type: "in" | "out") => void; quantity: string; setQuantity: (value: string) => void; note: string; setNote: (value: string) => void; saving: boolean; onClose: () => void; onSave: () => void }) {
  return <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}><KeyboardAvoidingView style={styles.modalBackdrop} behavior={Platform.OS === "ios" ? "padding" : undefined}><View style={styles.modalSheet}><View style={styles.modalHandle} /><View style={styles.modalHead}><View><Text style={styles.eyebrow}>STOK HAREKETİ</Text><Text style={styles.modalTitle}>{product?.name}</Text><Text style={styles.modalStock}>Mevcut: {formatQty(product?.stock ?? 0)} {product?.unit}</Text></View><Pressable style={styles.closeButton} onPress={onClose}><Text style={styles.closeText}>×</Text></Pressable></View><View style={styles.segment}><Pressable style={[styles.segmentItem, type === "in" && styles.segmentInActive]} onPress={() => setType("in")}><Text style={[styles.segmentText, type === "in" && styles.segmentInText]}>＋ Stok ekle</Text></Pressable><Pressable style={[styles.segmentItem, type === "out" && styles.segmentOutActive]} onPress={() => setType("out")}><Text style={[styles.segmentText, type === "out" && styles.segmentOutText]}>− Stoktan düş</Text></Pressable></View><Field label={`Miktar (${product?.unit ?? ""})`} value={quantity} onChangeText={setQuantity} placeholder="0" keyboardType="decimal-pad" autoFocus /><Field label="İşlem notu (isteğe bağlı)" value={note} onChangeText={setNote} placeholder="Örn. Raf dolumu" /><Pressable style={[styles.saveButton, type === "out" && styles.saveButtonOut, saving && styles.disabled]} onPress={onSave} disabled={saving}>{saving ? <ActivityIndicator color="#172820" /> : <Text style={[styles.saveButtonText, type === "out" && styles.saveButtonOutText]}>{type === "in" ? "Stoğa ekle" : "Stoktan düş"}</Text>}</Pressable></View></KeyboardAvoidingView></Modal>;
}

function CoworkerEditor({ visible, name, setName, username, setUsername, email, setEmail, password, setPassword, passwordAgain, setPasswordAgain, saving, onClose, onSave }: { visible: boolean; name: string; setName: (value: string) => void; username: string; setUsername: (value: string) => void; email: string; setEmail: (value: string) => void; password: string; setPassword: (value: string) => void; passwordAgain: string; setPasswordAgain: (value: string) => void; saving: boolean; onClose: () => void; onSave: () => void }) {
  return <Modal visible={visible} transparent animationType="slide" onRequestClose={onClose}><KeyboardAvoidingView style={styles.modalBackdrop} behavior={Platform.OS === "ios" ? "padding" : undefined}><View style={styles.modalSheet}><View style={styles.modalHandle} /><View style={styles.modalHead}><View><Text style={styles.eyebrow}>EKİP YÖNETİMİ</Text><Text style={styles.modalTitle}>Yeni çalışan hesabı</Text><Text style={styles.modalStock}>Doğrulama kodu çalışanın e-posta adresine gönderilir.</Text></View><Pressable style={styles.closeButton} onPress={onClose}><Text style={styles.closeText}>×</Text></Pressable></View><Field label="Ad ve soyad" value={name} onChangeText={setName} placeholder="Örn. Ayşe Yılmaz" autoCapitalize="words" autoFocus /><Field label="Doğrulama e-postası" value={email} onChangeText={setEmail} placeholder="ayse@ornek.com" autoCapitalize="none" autoCorrect={false} keyboardType="email-address" textContentType="emailAddress" /><Field label="Kullanıcı adı" value={username} onChangeText={setUsername} placeholder="örn. ayse" autoCapitalize="none" autoCorrect={false} /><Field label="Geçici şifre" value={password} onChangeText={setPassword} placeholder="En az 8 karakter" secureTextEntry textContentType="newPassword" /><Field label="Geçici şifre tekrar" value={passwordAgain} onChangeText={setPasswordAgain} placeholder="Şifreyi yeniden gir" secureTextEntry textContentType="newPassword" onSubmitEditing={onSave} /><Pressable style={[styles.saveButton, saving && styles.disabled]} onPress={onSave} disabled={saving}>{saving ? <ActivityIndicator color="#172820" /> : <Text style={styles.saveButtonText}>Doğrulama kodu gönder</Text>}</Pressable></View></KeyboardAvoidingView></Modal>;
}

function Field(props: ComponentProps<typeof TextInput> & { label: string }) {
  const { label, ...inputProps } = props;
  return <View style={styles.field}><Text style={styles.fieldLabel}>{label}</Text><TextInput style={styles.fieldInput} placeholderTextColor="#98a09b" {...inputProps} /></View>;
}

function formatQty(value: number) { return numberFormatter.format(value); }
function formatDate(value: Date) { return value.toLocaleDateString("tr-TR", { day: "numeric", month: "long", weekday: "long" }).toLocaleUpperCase("tr-TR"); }
function initials(value: string) { return value.split(/\s+/).filter(Boolean).slice(0, 2).map((part) => part[0]?.toLocaleUpperCase("tr-TR")).join("") || "?"; }
function shortTime(value: string) { const date = new Date(value); return date.toDateString() === new Date().toDateString() ? date.toLocaleTimeString("tr-TR", { hour: "2-digit", minute: "2-digit" }) : date.toLocaleDateString("tr-TR", { day: "numeric", month: "short" }); }
function friendlyError(message: string) { if (message.includes("duplicate key")) return "Bu ürün kodu zaten kullanılıyor."; if (message.includes("Stokta yalnızca")) return message; return message; }
function isStrongPassword(value: string) { return value.length >= 8 && value.length <= 72 && /[a-z]/.test(value) && /[A-Z]/.test(value) && /[0-9]/.test(value) && /[^A-Za-z0-9]/.test(value); }
async function edgeFunctionError(error: unknown) { const candidate = error as { context?: Response; message?: string }; try { const body = await candidate.context?.json() as { error?: string } | undefined; if (body?.error) return body.error; } catch { /* İstemci mesajına dönülür. */ } return candidate.message ?? "İşlem tamamlanamadı."; }

type DeletionFunctionErrorDetails = {
  message: string;
  code?: string;
  deletionRequestId?: string;
};

async function deletionFunctionErrorDetails(error: unknown): Promise<DeletionFunctionErrorDetails> {
  const candidate = error as { context?: Response; message?: string };
  try {
    const body = await candidate.context?.json() as {
      error?: unknown;
      code?: unknown;
      deletionRequestId?: unknown;
    } | undefined;
    return {
      message: typeof body?.error === "string"
        ? body.error
        : candidate.message ?? "Hesap silme işlemi tamamlanamadı.",
      code: typeof body?.code === "string" ? body.code : undefined,
      deletionRequestId: isDeletionRequestId(body?.deletionRequestId)
        ? body.deletionRequestId
        : undefined,
    };
  } catch {
    return { message: candidate.message ?? "Hesap silme işlemi tamamlanamadı." };
  }
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#172820" }, listContent: { paddingBottom: 110, backgroundColor: "#f4f5f1" },
  header: { paddingHorizontal: 18, paddingTop: 17, paddingBottom: 24, flexDirection: "row", justifyContent: "space-between", alignItems: "center", backgroundColor: "#172820" },
  date: { marginBottom: 4, color: "#86a095", fontSize: 9, fontWeight: "800", letterSpacing: 1 }, greeting: { color: "#fff", fontSize: 26, fontWeight: "800" },
  organization: { marginTop: 4, color: "#9fb0a7", fontSize: 9, fontWeight: "700" },
  headerActions: { flexDirection: "row", alignItems: "center", gap: 8 }, addCoworker: { height: 36, paddingHorizontal: 10, alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "#3f5c4e", borderRadius: 11, backgroundColor: "#223a2f" }, addCoworkerText: { color: "#cce0d5", fontSize: 9, fontWeight: "900" },
  platformButton: { height: 36, paddingHorizontal: 9, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#f3a952" }, platformButtonText: { color: "#172820", fontSize: 8, fontWeight: "900" },
  avatar: { width: 43, height: 43, borderRadius: 14, alignItems: "center", justifyContent: "center", backgroundColor: "#f3a952" }, avatarText: { color: "#172820", fontSize: 12, fontWeight: "900" },
  errorBanner: { marginHorizontal: 14, marginTop: 13, padding: 12, flexDirection: "row", alignItems: "center", gap: 8, borderRadius: 11, backgroundColor: "#fae9e5" }, errorText: { flex: 1, color: "#92483f", fontSize: 11 }, retry: { color: "#7e3c34", fontSize: 10, fontWeight: "900" },
  subscriptionBanner: { marginHorizontal: 14, marginTop: 13, padding: 12, borderWidth: 1, borderColor: "#efd5ad", borderRadius: 11, backgroundColor: "#fff4df" }, subscriptionBannerTitle: { color: "#8d5a16", fontSize: 11, fontWeight: "900" }, subscriptionBannerText: { marginTop: 4, color: "#9a713d", fontSize: 9, lineHeight: 14 }, subscriptionAction: { minHeight: 36, marginTop: 9, alignItems: "center", justifyContent: "center", borderRadius: 9, backgroundColor: "#f3a952" }, subscriptionActionText: { color: "#553713", fontSize: 9, fontWeight: "900" },
  statsGrid: { marginTop: -1, padding: 14, flexDirection: "row", gap: 9, backgroundColor: "#f4f5f1" }, statCard: { flex: 1, minHeight: 111, padding: 13, borderWidth: 1, borderColor: "#e3e6e1", borderRadius: 14, backgroundColor: "#fff" }, statDot: { width: 9, height: 9, marginBottom: 10, borderRadius: 5 }, stat_green: { backgroundColor: "#3f936d" }, stat_amber: { backgroundColor: "#e9a34d" }, stat_blue: { backgroundColor: "#5f8da5" }, statLabel: { color: "#848c87", fontSize: 8, fontWeight: "900", letterSpacing: .6 }, statValue: { marginTop: 7, color: "#18231e", fontSize: 25, fontWeight: "800" }, statCaption: { marginTop: 3, color: "#929994", fontSize: 8, lineHeight: 12 },
  sectionHead: { paddingHorizontal: 16, paddingTop: 13, paddingBottom: 10, flexDirection: "row", justifyContent: "space-between", alignItems: "flex-end" }, eyebrow: { marginBottom: 3, color: "#848c87", fontSize: 8, fontWeight: "900", letterSpacing: 1.1 }, sectionTitle: { color: "#1b2721", fontSize: 20, fontWeight: "800" },
  lowFilter: { paddingHorizontal: 11, paddingVertical: 8, borderWidth: 1, borderColor: "#dbe0db", borderRadius: 9, backgroundColor: "#fff" }, lowFilterActive: { borderColor: "#c6dfd2", backgroundColor: "#e7f3ed" }, lowFilterText: { color: "#65706a", fontSize: 10, fontWeight: "800" }, lowFilterTextActive: { color: "#277053" },
  searchBox: { height: 45, marginHorizontal: 14, marginBottom: 11, paddingHorizontal: 13, flexDirection: "row", alignItems: "center", gap: 9, borderWidth: 1, borderColor: "#dfe3df", borderRadius: 12, backgroundColor: "#fff" }, searchIcon: { color: "#66736c", fontSize: 19 }, searchInput: { flex: 1, color: "#1b2721", fontSize: 12 },
  loadingBox: { paddingVertical: 30, alignItems: "center", gap: 9 }, loadingText: { color: "#77807b", fontSize: 11 },
  pageLoading: { minHeight: 54, marginHorizontal: 14, flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 9 },
  productCard: { marginHorizontal: 14, marginBottom: 11, overflow: "hidden", borderWidth: 1, borderColor: "#e2e5e1", borderRadius: 15, backgroundColor: "#fff" }, productInfo: { padding: 14 }, productTop: { flexDirection: "row", alignItems: "center" }, productMark: { width: 38, height: 38, borderRadius: 11, alignItems: "center", justifyContent: "center", backgroundColor: "#e7f1ec" }, productMarkText: { color: "#337559", fontSize: 15, fontWeight: "900" }, productNames: { flex: 1, minWidth: 0, marginLeft: 10 }, productName: { color: "#1b2721", fontSize: 13, fontWeight: "800" }, productMeta: { marginTop: 4, color: "#909792", fontSize: 9 }, badge: { paddingHorizontal: 8, paddingVertical: 5, borderRadius: 20 }, badgeOk: { backgroundColor: "#e6f2eb" }, badgeLow: { backgroundColor: "#fff0db" }, badgeCritical: { backgroundColor: "#f9e4e0" }, badgeText: { fontSize: 8, fontWeight: "900" }, badgeTextOk: { color: "#347457" }, badgeTextLow: { color: "#a56620" }, badgeTextCritical: { color: "#ad4e44" },
  stockRow: { marginTop: 16, paddingTop: 13, flexDirection: "row", justifyContent: "space-between", alignItems: "flex-end", borderTopWidth: 1, borderTopColor: "#eff1ee" }, stockLabel: { color: "#929994", fontSize: 7, fontWeight: "900", letterSpacing: .8 }, stockValue: { marginTop: 4, color: "#1a2721", fontSize: 22, fontWeight: "800" }, stockUnit: { color: "#68716c", fontSize: 10, fontWeight: "600" }, minBox: { alignItems: "flex-end" }, minValue: { marginTop: 5, color: "#69726d", fontSize: 10, fontWeight: "700" },
  productActions: { minHeight: 44, flexDirection: "row", borderTopWidth: 1, borderTopColor: "#edf0ec" }, actionIn: { flex: 1, minHeight: 44, alignItems: "center", justifyContent: "center", backgroundColor: "#edf6f1" }, actionOut: { flex: 1, minHeight: 44, alignItems: "center", justifyContent: "center", borderLeftWidth: 1, borderLeftColor: "#e5e9e5", backgroundColor: "#fff8ee" }, actionReport: { width: 76, minHeight: 44, alignItems: "center", justifyContent: "center", borderLeftWidth: 1, borderLeftColor: "#e5e9e5", backgroundColor: "#f7f7f4" }, actionInText: { color: "#2b7354", fontSize: 10, fontWeight: "900" }, actionOutText: { color: "#9b6323", fontSize: 10, fontWeight: "900" }, actionReportText: { color: "#747d78", fontSize: 9, fontWeight: "900" },
  empty: { marginHorizontal: 14, paddingVertical: 43, paddingHorizontal: 20, alignItems: "center", borderWidth: 1, borderColor: "#e1e5e0", borderRadius: 15, backgroundColor: "#fff" }, emptyIcon: { color: "#4c856b", fontSize: 35 }, emptyTitle: { marginTop: 10, color: "#1c2822", fontSize: 17, fontWeight: "800" }, emptyBody: { maxWidth: 280, marginTop: 6, color: "#858d88", textAlign: "center", fontSize: 11, lineHeight: 17 }, primaryButton: { marginTop: 16, paddingHorizontal: 16, paddingVertical: 12, borderRadius: 10, backgroundColor: "#1f7353" }, primaryButtonText: { color: "#fff", fontSize: 11, fontWeight: "900" },
  history: { margin: 14, marginTop: 22, padding: 15, borderWidth: 1, borderColor: "#e1e5e0", borderRadius: 15, backgroundColor: "#fff" }, movementItem: { paddingVertical: 8, borderTopWidth: 1, borderTopColor: "#eff1ee" }, movementRow: { minHeight: 49, flexDirection: "row", alignItems: "center", gap: 10 }, movementIcon: { width: 31, height: 31, borderRadius: 9, alignItems: "center", justifyContent: "center" }, movementIn: { backgroundColor: "#e6f2eb" }, movementOut: { backgroundColor: "#fae8e4" }, movementInText: { color: "#337758", fontWeight: "900" }, movementOutText: { color: "#ad5348", fontWeight: "900" }, movementBody: { flex: 1 }, movementName: { color: "#26322c", fontSize: 10, fontWeight: "800" }, movementDetail: { marginTop: 3, color: "#8a918d", fontSize: 8, lineHeight: 12 }, movementTime: { color: "#969d98", fontSize: 8 }, movementReportActions: { paddingLeft: 41, flexDirection: "row", gap: 7 }, movementReportButton: { minHeight: 29, paddingHorizontal: 8, alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "#e0e4df", borderRadius: 8, backgroundColor: "#fafaf8" }, movementReportText: { color: "#79827d", fontSize: 8, fontWeight: "800" }, historyEmpty: { paddingVertical: 25, color: "#929994", textAlign: "center", fontSize: 10 },
  fab: { position: "absolute", right: 19, bottom: 23, width: 58, height: 58, borderRadius: 19, alignItems: "center", justifyContent: "center", backgroundColor: "#f3a952", elevation: 7, shadowColor: "#15271f", shadowOffset: { width: 0, height: 5 }, shadowOpacity: .25, shadowRadius: 9 }, fabText: { color: "#172820", fontSize: 28, fontWeight: "700" },
  modalBackdrop: { flex: 1, justifyContent: "flex-end", backgroundColor: "#0c1813a8" }, modalSheet: { maxHeight: "92%", padding: 20, paddingTop: 10, borderTopLeftRadius: 24, borderTopRightRadius: 24, backgroundColor: "#f8f8f5" }, modalHandle: { width: 40, height: 4, alignSelf: "center", marginBottom: 17, borderRadius: 2, backgroundColor: "#cbd0cc" }, modalHead: { marginBottom: 18, flexDirection: "row", justifyContent: "space-between", alignItems: "flex-start" }, modalTitle: { color: "#1b2721", fontSize: 21, fontWeight: "800" }, modalStock: { marginTop: 5, color: "#7d8681", fontSize: 10 }, closeButton: { width: 34, height: 34, borderRadius: 10, alignItems: "center", justifyContent: "center", backgroundColor: "#e9ece8" }, closeText: { color: "#5c6861", fontSize: 22 }, field: { marginBottom: 14 }, fieldLabel: { marginBottom: 6, color: "#5e6863", fontSize: 10, fontWeight: "800" }, fieldInput: { height: 46, paddingHorizontal: 12, borderWidth: 1, borderColor: "#dde2dd", borderRadius: 10, backgroundColor: "#fff", color: "#17201d", fontSize: 13 }, formRow: { flexDirection: "row", gap: 10 }, half: { flex: 1 },
  saveButton: { height: 49, marginTop: 5, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#f3a952" }, saveButtonOut: { backgroundColor: "#b85c4e" }, saveButtonText: { color: "#172820", fontSize: 12, fontWeight: "900" }, saveButtonOutText: { color: "#fff" }, disabled: { opacity: .55 },
  segment: { height: 45, marginBottom: 17, padding: 3, flexDirection: "row", borderRadius: 11, backgroundColor: "#e9ece8" }, segmentItem: { flex: 1, alignItems: "center", justifyContent: "center", borderRadius: 8 }, segmentInActive: { backgroundColor: "#ddefe5" }, segmentOutActive: { backgroundColor: "#f6dfda" }, segmentText: { color: "#77807b", fontSize: 10, fontWeight: "800" }, segmentInText: { color: "#2c7254" }, segmentOutText: { color: "#a64c41" },
});
