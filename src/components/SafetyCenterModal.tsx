import { useCallback, useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  Modal,
  Pressable,
  RefreshControl,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from "react-native";
import { SafeAreaView } from "react-native-safe-area-context";
import { supabase } from "../lib/supabase";
import type {
  ContentModerationAction,
  ContentReport,
  ContentReportAction,
  ContentReportReason,
  ContentReportTargetType,
  PlatformContentReportAction,
} from "../types";

type Filter = "open" | "resolved" | "all";
type SafetyCenterScope = "organization" | "platform";

type Props = {
  visible: boolean;
  scope: SafetyCenterScope;
  onClose: () => void;
  onModerated?: () => void;
};

export default function SafetyCenterModal({ visible, scope, onClose, onModerated }: Props) {
  const [filter, setFilter] = useState<Filter>("open");
  const [reports, setReports] = useState<ContentReport[]>([]);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");
  const [moderatingId, setModeratingId] = useState<string | null>(null);
  const loadSequence = useRef(0);

  const loadReports = useCallback(async (quiet = false) => {
    const requestId = ++loadSequence.current;
    if (quiet) setRefreshing(true);
    else {
      setLoading(true);
      setReports([]);
    }
    setError("");
    const { data, error: listError } = scope === "platform"
      ? await supabase.rpc("list_platform_content_reports", { p_status: filter })
      : await supabase.rpc("list_content_reports", { p_status: filter });
    if (requestId !== loadSequence.current) return;
    if (listError) setError(safeModerationError(listError.message, scope));
    else setReports((data ?? []) as ContentReport[]);
    setLoading(false);
    setRefreshing(false);
  }, [filter, scope]);

  useEffect(() => {
    if (visible) void loadReports();
  }, [loadReports, visible]);

  function requestModeration(report: ContentReport, action: ContentModerationAction) {
    const copy = moderationCopy(report, action);
    Alert.alert(copy.title, copy.message, [
      { text: "Vazgeç", style: "cancel" },
      {
        text: copy.confirm,
        style: action === "dismiss" ? "default" : "destructive",
        onPress: () => void moderate(report.report_id, action),
      },
    ]);
  }

  async function moderate(reportId: string, action: ContentModerationAction) {
    setModeratingId(reportId);
    setError("");
    const args = { p_report_id: reportId, p_action: action, p_note: "" };
    const { error: moderationError } = scope === "platform"
      ? await supabase.rpc("moderate_platform_content_report", args)
      : await supabase.rpc("moderate_content_report", args);
    setModeratingId(null);
    if (moderationError) {
      Alert.alert("İşlem tamamlanamadı", safeModerationError(
        moderationError.message,
        scope,
        "Moderasyon işlemi tamamlanamadı. Lütfen yeniden deneyin.",
      ));
      return;
    }
    onModerated?.();
    await loadReports();
  }

  return (
    <Modal visible={visible} animationType="slide" presentationStyle="fullScreen" onRequestClose={moderatingId ? () => undefined : onClose}>
      <SafeAreaView style={styles.safe} edges={["top", "bottom"]}>
        <View style={styles.header}>
          <View style={styles.headerText}>
            <Text style={styles.eyebrow}>{scope === "platform" ? "PLATFORM OPERATÖRÜ" : "YÖNETİCİ ARAÇLARI"}</Text>
            <Text style={[styles.title, scope === "platform" && styles.platformTitle]}>{scope === "platform" ? "Platform Güvenlik Kuyruğu" : "Güvenlik Merkezi"}</Text>
            <Text style={styles.subtitle}>{scope === "platform" ? "İşletme yöneticileri hakkındaki bildirimler" : "İşletmenizde bildirilen içerik ve kullanıcılar"}</Text>
          </View>
          <Pressable
            accessibilityRole="button"
            accessibilityLabel={scope === "platform" ? "Platform Güvenlik Kuyruğunu kapat" : "Güvenlik Merkezini kapat"}
            style={styles.closeButton}
            onPress={onClose}
            disabled={Boolean(moderatingId)}
          >
            <Text style={styles.closeText}>×</Text>
          </Pressable>
        </View>

        <View style={styles.filters} accessibilityRole="tablist">
          <FilterButton label="Açık" active={filter === "open"} onPress={() => setFilter("open")} />
          <FilterButton label="Çözülen" active={filter === "resolved"} onPress={() => setFilter("resolved")} />
          <FilterButton label="Tümü" active={filter === "all"} onPress={() => setFilter("all")} />
        </View>

        {error ? (
          <Pressable accessibilityRole="button" accessibilityLabel="Bildirimleri yeniden yükle" style={styles.errorBox} onPress={() => void loadReports()}>
            <Text accessibilityRole="alert" style={styles.errorText}>{error}</Text>
            <Text style={styles.retryText}>Tekrar dene</Text>
          </Pressable>
        ) : null}

        {loading ? (
          <View style={styles.center}>
            <ActivityIndicator color="#1f7353" />
            <Text style={styles.loadingText}>Bildirimler yükleniyor…</Text>
          </View>
        ) : (
          <ScrollView
            style={styles.list}
            contentContainerStyle={reports.length ? styles.listContent : styles.emptyContent}
            refreshControl={<RefreshControl refreshing={refreshing} colors={["#1f7353"]} tintColor="#1f7353" onRefresh={() => void loadReports(true)} />}
            showsVerticalScrollIndicator={false}
          >
            {reports.length ? reports.map((report) => (
              <ReportCard
                key={report.report_id}
                report={report}
                scope={scope}
                busy={moderatingId === report.report_id}
                disabled={Boolean(moderatingId)}
                onAction={(action) => requestModeration(report, action)}
              />
            )) : (
              <View style={styles.empty}>
                <Text style={styles.emptyIcon}>✓</Text>
                <Text style={styles.emptyTitle}>{filter === "open" ? "Açık bildirim yok" : "Bu görünümde bildirim yok"}</Text>
                <Text style={styles.emptyText}>Yeni bildirimler burada görünür. Listeyi aşağı çekerek yenileyebilirsiniz.</Text>
              </View>
            )}
          </ScrollView>
        )}
      </SafeAreaView>
    </Modal>
  );
}

function FilterButton({ label, active, onPress }: { label: string; active: boolean; onPress: () => void }) {
  return (
    <Pressable
      accessibilityRole="tab"
      accessibilityState={{ selected: active }}
      style={[styles.filterButton, active && styles.filterButtonActive]}
      onPress={onPress}
    >
      <Text style={[styles.filterText, active && styles.filterTextActive]}>{label}</Text>
    </Pressable>
  );
}

function ReportCard({
  report,
  scope,
  busy,
  disabled,
  onAction,
}: {
  report: ContentReport;
  scope: SafetyCenterScope;
  busy: boolean;
  disabled: boolean;
  onAction: (action: ContentModerationAction) => void;
}) {
  const targetAction = actionForTarget(report.target_type);
  const platformContentAction = actionForPlatformTarget(report.target_type);
  return (
    <View style={styles.card}>
      <View style={styles.cardTop}>
        <View style={styles.targetBadge}><Text style={styles.targetBadgeText}>{targetLabel(report.target_type)}</Text></View>
        <Text style={[styles.statusBadge, report.status === "open" ? styles.statusOpen : styles.statusResolved]}>
          {report.status === "open" ? "AÇIK" : "ÇÖZÜLDÜ"}
        </Text>
      </View>
      {scope === "platform" ? <Text style={styles.organizationName}>İşletme: {report.organization_name ?? "Bilinmeyen işletme"}</Text> : null}
      <Text style={styles.targetLabel} numberOfLines={2}>{report.target_label}</Text>
      <Text style={styles.meta}>{reasonLabel(report.reason)} · {formatTimestamp(report.created_at)}</Text>
      {report.target_content_snapshot ? (
        <View style={styles.snapshotBox}>
          <Text style={styles.snapshotTitle}>BİLDİRİLEN İÇERİK</Text>
          <Text style={styles.snapshotText}>{report.target_content_snapshot}</Text>
        </View>
      ) : null}
      {report.details ? <Text style={styles.details}>{report.details}</Text> : <Text style={styles.noDetails}>Bildiren kişi açıklama eklememiş.</Text>}
      <Text style={styles.reporter}>Bildiren: {report.reporter_name}</Text>

      {report.status === "open" ? (
        busy ? (
          <View style={styles.busyBox}><ActivityIndicator color="#1f7353" /><Text style={styles.busyText}>İşleniyor…</Text></View>
        ) : scope === "platform" ? (
          <PlatformActions report={report} contentAction={platformContentAction} disabled={disabled} onAction={onAction} />
        ) : (
          <View style={styles.actions}>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={`${report.target_label} bildirimini kapat`}
              style={[styles.dismissButton, disabled && styles.disabled]}
              onPress={() => onAction("dismiss")}
              disabled={disabled}
            >
              <Text style={styles.dismissText}>İşlem gerekmiyor</Text>
            </Pressable>
            <Pressable
              accessibilityRole="button"
              accessibilityLabel={`${actionButtonLabel(targetAction)}: ${report.target_label}`}
              style={[styles.moderateButton, disabled && styles.disabled]}
              onPress={() => onAction(targetAction)}
              disabled={disabled}
            >
              <Text style={styles.moderateText}>{actionButtonLabel(targetAction)}</Text>
            </Pressable>
          </View>
        )
      ) : (
        <View style={styles.resolutionBox}>
          <Text style={styles.resolutionTitle}>{resolutionLabel(report.resolution_action)}</Text>
          <Text style={styles.resolutionText}>{report.resolved_by_name ? `${report.resolved_by_name} · ` : ""}{report.resolved_at ? formatTimestamp(report.resolved_at) : ""}</Text>
        </View>
      )}
    </View>
  );
}

function PlatformActions({
  report,
  contentAction,
  disabled,
  onAction,
}: {
  report: ContentReport;
  contentAction: Exclude<PlatformContentReportAction, "dismiss" | "suspend_organization"> | null;
  disabled: boolean;
  onAction: (action: PlatformContentReportAction) => void;
}) {
  const dismissButton = (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`${report.target_label} bildirimini işlem yapmadan kapat`}
      style={[styles.dismissButton, disabled && styles.disabled]}
      onPress={() => onAction("dismiss")}
      disabled={disabled}
    >
      <Text style={styles.dismissText}>Bildirimi kapat</Text>
    </Pressable>
  );
  const suspendButton = (
    <Pressable
      accessibilityRole="button"
      accessibilityLabel={`${actionButtonLabel("suspend_organization")}: ${report.organization_name ?? report.target_label}`}
      style={[styles.moderateButton, disabled && styles.disabled]}
      onPress={() => onAction("suspend_organization")}
      disabled={disabled}
    >
      <Text style={styles.moderateText}>{actionButtonLabel("suspend_organization")}</Text>
    </Pressable>
  );

  if (!contentAction) return <View style={styles.actions}>{dismissButton}{suspendButton}</View>;

  return (
    <View style={styles.platformActionStack}>
      <View style={styles.platformActionRow}>
        {dismissButton}
        <Pressable
          accessibilityRole="button"
          accessibilityLabel={`${actionButtonLabel(contentAction)}: ${report.target_label}`}
          style={[styles.moderateButton, disabled && styles.disabled]}
          onPress={() => onAction(contentAction)}
          disabled={disabled}
        >
          <Text style={styles.moderateText}>{actionButtonLabel(contentAction)}</Text>
        </Pressable>
      </View>
      <Pressable
        accessibilityRole="button"
        accessibilityLabel={`${actionButtonLabel("suspend_organization")}: ${report.organization_name ?? report.target_label}`}
        style={[styles.moderateButton, styles.platformFullButton, disabled && styles.disabled]}
        onPress={() => onAction("suspend_organization")}
        disabled={disabled}
      >
        <Text style={styles.moderateText}>{actionButtonLabel("suspend_organization")}</Text>
      </Pressable>
    </View>
  );
}

function actionForTarget(target: ContentReportTargetType): ContentReportAction {
  if (target === "product") return "remove_product";
  if (target === "movement") return "redact_movement_note";
  return "deactivate_user";
}

function actionForPlatformTarget(
  target: ContentReportTargetType,
): Exclude<PlatformContentReportAction, "dismiss" | "suspend_organization"> | null {
  if (target === "product") return "remove_product";
  if (target === "movement") return "redact_movement_note";
  return null;
}

function actionButtonLabel(action: ContentModerationAction) {
  if (action === "remove_product") return "Ürünü kaldır";
  if (action === "redact_movement_note") return "Notu gizle";
  if (action === "deactivate_user") return "Çalışanı devre dışı bırak";
  if (action === "suspend_organization") return "İşletmeyi askıya al";
  return "Bildirimi kapat";
}

function moderationCopy(report: ContentReport, action: ContentModerationAction) {
  if (action === "dismiss") return {
    title: "Bildirim kapatılsın mı?",
    message: `“${report.target_label}” için işlem yapılmadan bildirim çözüldü olarak işaretlenecek.`,
    confirm: "Bildirimi kapat",
  };
  if (action === "remove_product") return {
    title: "Ürün kaldırılsın mı?",
    message: `“${report.target_label}” aktif stok listesinden kaldırılacak. Geçmiş hareketler kayıt bütünlüğü için korunur.`,
    confirm: "Ürünü kaldır",
  };
  if (action === "redact_movement_note") return {
    title: "Hareket notu gizlensin mi?",
    message: `“${report.target_label}” kaydındaki kullanıcı notu kaldırılacak; stok miktarı ve işlem geçmişi korunacak.`,
    confirm: "Notu gizle",
  };
  if (action === "suspend_organization") return {
    title: "İşletme askıya alınsın mı?",
    message: `“${report.organization_name ?? "Bu işletme"}” çalışma alanındaki yeni işlemler durdurulacak. İşletme, platform işletmeler ekranından yeniden etkinleştirilebilir.`,
    confirm: "İşletmeyi askıya al",
  };
  return {
    title: "Çalışan devre dışı bırakılsın mı?",
    message: `“${report.target_label}” hesabının bu işletmeye erişimi durdurulacak.`,
    confirm: "Devre dışı bırak",
  };
}

function targetLabel(target: ContentReportTargetType) {
  return target === "product" ? "ÜRÜN" : target === "movement" ? "HAREKET" : "KULLANICI";
}

function reasonLabel(reason: ContentReportReason) {
  return {
    spam: "Spam veya izinsiz reklam",
    harassment: "Taciz veya zorbalık",
    offensive: "Uygunsuz ya da saldırgan içerik",
    fraud: "Dolandırıcılık veya yanıltma",
    privacy: "Gizlilik ihlali",
    other: "Diğer",
  }[reason];
}

function resolutionLabel(action: ContentModerationAction | null) {
  if (action === "remove_product") return "Ürün kaldırıldı";
  if (action === "redact_movement_note") return "Hareket notu gizlendi";
  if (action === "deactivate_user") return "Çalışan devre dışı bırakıldı";
  if (action === "suspend_organization") return "İşletme askıya alındı";
  return "İşlem gerektirmedi";
}

function formatTimestamp(value: string) {
  return new Date(value).toLocaleString("tr-TR", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit" });
}

function safeModerationError(message: string, scope: SafetyCenterScope, fallback = "Bildirimler yüklenemedi. Lütfen yeniden deneyin.") {
  const normalized = message.toLocaleLowerCase("tr-TR");
  if (normalized.includes("oturum")) return "Oturumunuz sona erdi. Yeniden giriş yapın.";
  if (scope === "platform" && normalized.includes("platform operat")) return "Bu bölüm yalnızca yetkili platform operatörlerine açıktır.";
  if (normalized.includes("yalnızca işletme yöneticisine")) return "Bu bölüm yalnızca işletme yöneticisine açıktır.";
  if (message.includes("şikâyet") || message.includes("bildirim")) return message;
  return fallback;
}

const styles = StyleSheet.create({
  safe: { flex: 1, backgroundColor: "#f4f5f1" },
  header: { paddingHorizontal: 18, paddingVertical: 17, flexDirection: "row", alignItems: "center", justifyContent: "space-between", backgroundColor: "#172820" },
  headerText: { flex: 1, paddingRight: 12 },
  eyebrow: { color: "#8fa69a", fontSize: 8, fontWeight: "900", letterSpacing: 1.1 },
  title: { marginTop: 4, color: "#fff", fontSize: 24, fontWeight: "800" },
  platformTitle: { fontSize: 20 },
  subtitle: { marginTop: 4, color: "#9fb0a7", fontSize: 9 },
  closeButton: { width: 39, height: 39, alignItems: "center", justifyContent: "center", borderRadius: 11, backgroundColor: "#294237" },
  closeText: { color: "#dce7e1", fontSize: 24 },
  filters: { margin: 14, padding: 3, flexDirection: "row", borderRadius: 12, backgroundColor: "#e5e9e4" },
  filterButton: { flex: 1, minHeight: 40, alignItems: "center", justifyContent: "center", borderRadius: 9 },
  filterButtonActive: { backgroundColor: "#fff" },
  filterText: { color: "#7c8680", fontSize: 10, fontWeight: "800" },
  filterTextActive: { color: "#276f52" },
  errorBox: { marginHorizontal: 14, marginBottom: 10, padding: 12, flexDirection: "row", alignItems: "center", borderRadius: 11, backgroundColor: "#fae8e4" },
  errorText: { flex: 1, color: "#92483f", fontSize: 10 },
  retryText: { color: "#813e36", fontSize: 10, fontWeight: "900" },
  center: { flex: 1, alignItems: "center", justifyContent: "center", gap: 10 },
  loadingText: { color: "#78827c", fontSize: 11 },
  list: { flex: 1 },
  listContent: { paddingHorizontal: 14, paddingBottom: 30 },
  emptyContent: { flexGrow: 1, padding: 14 },
  empty: { flex: 1, alignItems: "center", justifyContent: "center", paddingHorizontal: 28 },
  emptyIcon: { color: "#39805f", fontSize: 38, fontWeight: "900" },
  emptyTitle: { marginTop: 10, color: "#213029", fontSize: 17, fontWeight: "800" },
  emptyText: { maxWidth: 300, marginTop: 7, color: "#818a85", textAlign: "center", fontSize: 10, lineHeight: 16 },
  card: { marginBottom: 12, padding: 15, borderWidth: 1, borderColor: "#e0e4df", borderRadius: 15, backgroundColor: "#fff" },
  cardTop: { flexDirection: "row", alignItems: "center", justifyContent: "space-between" },
  targetBadge: { paddingHorizontal: 8, paddingVertical: 5, borderRadius: 20, backgroundColor: "#e6f1eb" },
  targetBadgeText: { color: "#347457", fontSize: 8, fontWeight: "900", letterSpacing: .6 },
  statusBadge: { overflow: "hidden", paddingHorizontal: 8, paddingVertical: 5, borderRadius: 20, fontSize: 8, fontWeight: "900" },
  statusOpen: { color: "#9a601f", backgroundColor: "#fff0db" },
  statusResolved: { color: "#347457", backgroundColor: "#e6f2eb" },
  targetLabel: { marginTop: 11, color: "#1d2a24", fontSize: 13, fontWeight: "900", lineHeight: 18 },
  organizationName: { marginTop: 10, color: "#46658e", fontSize: 9, fontWeight: "800" },
  meta: { marginTop: 5, color: "#828b86", fontSize: 9 },
  details: { marginTop: 11, padding: 11, color: "#5e6963", fontSize: 10, lineHeight: 16, borderRadius: 10, backgroundColor: "#f5f6f3" },
  snapshotBox: { marginTop: 11, padding: 11, borderWidth: 1, borderColor: "#ead8be", borderRadius: 10, backgroundColor: "#fff9ef" },
  snapshotTitle: { color: "#906129", fontSize: 8, fontWeight: "900", letterSpacing: .6 },
  snapshotText: { marginTop: 5, color: "#684e30", fontSize: 10, lineHeight: 16 },
  noDetails: { marginTop: 9, color: "#9ba19d", fontSize: 9, fontStyle: "italic" },
  reporter: { marginTop: 10, color: "#597365", fontSize: 9, fontWeight: "700" },
  actions: { marginTop: 14, flexDirection: "row", gap: 8 },
  platformActionStack: { marginTop: 14, gap: 8 },
  platformActionRow: { flexDirection: "row", gap: 8 },
  dismissButton: { flex: 1, minHeight: 43, paddingHorizontal: 9, alignItems: "center", justifyContent: "center", borderWidth: 1, borderColor: "#d9ded9", borderRadius: 10, backgroundColor: "#fff" },
  dismissText: { color: "#626e67", textAlign: "center", fontSize: 9, fontWeight: "900" },
  moderateButton: { flex: 1, minHeight: 43, paddingHorizontal: 9, alignItems: "center", justifyContent: "center", borderRadius: 10, backgroundColor: "#ac5146" },
  platformFullButton: { flex: 0 },
  moderateText: { color: "#fff", textAlign: "center", fontSize: 9, fontWeight: "900" },
  busyBox: { minHeight: 43, marginTop: 14, flexDirection: "row", alignItems: "center", justifyContent: "center", gap: 9, borderRadius: 10, backgroundColor: "#eef2ed" },
  busyText: { color: "#68736d", fontSize: 10, fontWeight: "700" },
  resolutionBox: { marginTop: 13, padding: 11, borderRadius: 10, backgroundColor: "#edf5f0" },
  resolutionTitle: { color: "#347457", fontSize: 10, fontWeight: "900" },
  resolutionText: { marginTop: 4, color: "#718078", fontSize: 8 },
  disabled: { opacity: .5 },
});
