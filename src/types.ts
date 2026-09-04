export type Product = {
  id: string;
  organization_id?: string;
  name: string;
  sku: string;
  category: string;
  unit: string;
  stock: number;
  min_stock: number;
  active?: boolean;
  created_at: string;
  updated_at: string;
};

export type ProfileRole = "admin" | "member";

export type Movement = {
  id: string;
  organization_id?: string;
  product_id: string;
  type: "in" | "out";
  quantity: number;
  previous_stock: number;
  new_stock: number;
  note: string;
  actor_name: string;
  actor_id: string | null;
  created_at: string;
  products: { name: string; sku: string; unit: string } | null;
};

export type ContentReportTargetType = "product" | "movement" | "user";

export type ContentReportReason = "spam" | "harassment" | "offensive" | "fraud" | "privacy" | "other";

export type ContentReportStatus = "open" | "resolved";

export type ContentReportAction = "dismiss" | "remove_product" | "redact_movement_note" | "deactivate_user";

export type PlatformContentReportAction = "dismiss" | "remove_product" | "redact_movement_note" | "suspend_organization";

export type ContentModerationAction = ContentReportAction | PlatformContentReportAction;

export type ContentReportTarget = {
  type: ContentReportTargetType;
  id: string;
  label: string;
};

export type ContentReport = {
  organization_id?: string;
  organization_name?: string;
  report_id: string;
  created_at: string;
  status: ContentReportStatus;
  target_type: ContentReportTargetType;
  target_id: string | null;
  target_label: string;
  target_content_snapshot: string | null;
  reason: ContentReportReason;
  details: string;
  reporter_id: string | null;
  reporter_name: string;
  resolution_action: ContentModerationAction | null;
  resolution_note: string | null;
  resolved_at: string | null;
  resolved_by: string | null;
  resolved_by_name: string | null;
};

export type ProductDraft = {
  name: string;
  sku: string;
  category: string;
  unit: string;
  stock: string;
  minStock: string;
};
