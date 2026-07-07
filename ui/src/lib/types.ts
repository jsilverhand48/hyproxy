// Mirrors the admin API Pydantic schemas (server/src/hyproxy/admin/schemas.py).
// The server remains authoritative; these types are for editor/type safety only.

export interface User {
  id: string;
  external_id: string;
  email: string;
  display_name: string;
  status: string;
  auth_tier: string;
  is_protected: boolean;
  created_at: string;
}

export interface Role {
  id: string;
  name: string;
  description: string | null;
}

export interface Resource {
  id: string;
  name: string;
  protocol: string;
  public_host: string | null;
  host: string;
  ports: number[];
  path_prefix: string | null;
  description: string | null;
  enabled: boolean;
}

export interface Policy {
  id: string;
  role_id: string;
  resource_id: string;
  action: "allow" | "deny";
  allowed_ports: number[] | null;
  allowed_paths: string[] | null;
  conditions_json: Record<string, unknown>;
  enabled: boolean;
}

export interface Page<T> {
  items: T[];
  next_cursor: number | null;
}

export interface AccessAudit {
  id: number;
  ts: string;
  user_id: string | null;
  resource_id: string | null;
  port: number | null;
  decision: string;
  reason: string | null;
  source_ip: string;
}

export interface AuthEvent {
  id: number;
  ts: string;
  event_type: string;
  user_id: string | null;
  session_id: string | null;
  client_id: string | null;
  source_ip: string;
  success: boolean;
  detail: Record<string, unknown>;
}

export interface MyResource {
  id: string;
  name: string;
  protocol: string;
  public_host: string | null;
  description: string | null;
}

export interface DownloadRequest {
  id: string;
  user_id: string;
  user_email: string | null;
  magnet: string;
  target: "shows" | "movies";
  status: "pending" | "approved" | "denied";
  created_at: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
  submitted_at: string | null;
  error: string | null;
}

export interface PolicyChange {
  id: number;
  ts: string;
  actor_id: string;
  actor_email: string | null;
  entity_type: string;
  entity_id: string | null;
  action: string;
  change_json: Record<string, unknown>;
}
