// Shapes returned by the VULNEX API (engines/api, OpenAPI at /api/v1/openapi.json).

export type Role = 'owner' | 'admin' | 'analyst' | 'remediation_contributor' | 'viewer';

export type Permission =
	| 'organization.read'
	| 'members.read'
	| 'members.manage'
	| 'audit.read'
	| 'scope.read'
	| 'scope.manage'
	| 'assets.read'
	| 'assets.manage';

export const ROLE_LABEL: Record<Role, string> = {
	owner: 'Owner',
	admin: 'Administrator',
	analyst: 'Analyst',
	remediation_contributor: 'Remediation contributor',
	viewer: 'Viewer'
};

export const ROLES = Object.keys(ROLE_LABEL) as Role[];

export interface Organization {
	id: string;
	name: string;
}

export interface Session {
	user: { id: string; email: string; display_name: string };
	organization: Organization;
	role: Role;
	permissions: Permission[];
	expires_at: string;
	memberships: { organization: Organization; role: Role }[];
}

export interface LoginResponse {
	token: string;
	session: Session;
}

export interface Member {
	user_id: string;
	email: string;
	display_name: string;
	is_active: boolean;
	role: Role;
	joined_at: string;
}

export interface AuditEvent {
	id: number;
	occurred_at: string;
	actor_user_id: string | null;
	actor_email: string | null;
	action: string;
	target_type: string | null;
	target_id: string | null;
	ip: string | null;
	request_id: string | null;
	detail: Record<string, unknown>;
}

export interface AuditPage {
	items: AuditEvent[];
	next_before_id: number | null;
}

export const can = (session: Session, permission: Permission) =>
	session.permissions.includes(permission);

export type AuthorizationStatus = 'authorized' | 'changed_since_authorization' | 'not_authorized';

export interface ScopeEntry {
	id: string;
	kind: 'cidr' | 'hostname' | 'hostname_wildcard';
	value: string;
	exclude: boolean;
	note: string;
	created_at: string;
}

export interface ScopeGroup {
	id: string;
	name: string;
	description: string;
	created_at: string;
	entries: ScopeEntry[];
	authorization: {
		status: AuthorizationStatus;
		authorized_at: string | null;
		authorized_by_email: string | null;
		statement: string | null;
	};
	active_assets: number;
	retired_assets: number;
}

export type Criticality = 'low' | 'medium' | 'high' | 'critical';

export const CRITICALITIES: Criticality[] = ['low', 'medium', 'high', 'critical'];

export interface Asset {
	id: string;
	scope_group_id: string;
	scope_group_name: string;
	kind: 'ip' | 'cidr' | 'hostname';
	target: string;
	name: string;
	criticality: Criticality;
	notes: string;
	source: 'user' | 'discovered';
	status: 'active' | 'retired';
	created_at: string;
	updated_at: string;
	retired_at: string | null;
	first_seen_at: string | null;
	last_seen_at: string | null;
	scope: { in_scope: boolean; problem: string | null; authorized: boolean };
}

export interface AssetPage {
	items: Asset[];
	total: number;
}
