// Shapes returned by the VULNEX API (engines/api, OpenAPI at /api/v1/openapi.json).

export type Role = 'owner' | 'admin' | 'analyst' | 'remediation_contributor' | 'viewer';

export type Permission = 'organization.read' | 'members.read' | 'members.manage' | 'audit.read';

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
