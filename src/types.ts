export type Product = {
  id: string;
  organization_id?: string;
  name: string;
  sku: string;
  category: string;
  unit: string;
  stock: number;
  min_stock: number;
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
  created_at: string;
  products: { name: string; sku: string; unit: string } | null;
};

export type ProductDraft = {
  name: string;
  sku: string;
  category: string;
  unit: string;
  stock: string;
  minStock: string;
};
