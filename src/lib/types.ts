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
	| 'assets.manage'
	| 'workers.read'
	| 'workers.manage'
	| 'scans.read'
	| 'scans.run'
	| 'findings.read'
	| 'findings.work'
	| 'findings.triage'
	| 'findings.accept'
	| 'intel.read';

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

export interface Worker {
	id: string;
	name: string;
	scope_group_id: string;
	scope_group_name: string;
	status: 'active' | 'disabled' | 'revoked';
	connection: 'online' | 'stale' | 'never_connected';
	last_seen_at: string | null;
	version: string | null;
	created_at: string;
	revoked_at: string | null;
}

export interface Enrollment {
	id: string;
	scope_group_id: string;
	name: string;
	created_at: string;
	expires_at: string;
	status: 'pending' | 'used' | 'expired' | 'revoked';
	worker_id: string | null;
}

export interface EnrollmentCreated {
	id: string;
	expires_at: string;
	bundle: { control_plane_url: string; ca_pem: string; ca_sha256: string; token: string };
}

export type ScanState = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface ScopeCheckResult {
	profile: 'scope_check';
	allowed: { target: string; kind: string; addresses: number | null }[];
	refused: { target: string; reason: string }[];
}

export type ScanProfile = 'scope_check' | 'discovery';

export interface DiscoverySummary {
	open_ports: number;
	services_new: number;
	services_closed: number;
	dropped: number;
	hosts_probed: number;
	hosts_responding: number;
	probes: number;
	ports: number;
	stopped: string | null;
	refused_targets: string[];
	scanner_version: string;
	started_at: string;
	finished_at: string;
	findings?: { new: number; updated: number; resolved: number; reopened: number };
}

export interface Scan {
	id: string;
	scope_group_id: string;
	scope_group_name: string;
	profile: ScanProfile;
	ports: number[];
	summary: DiscoverySummary | null;
	asset_ids: string[];
	targets: string[];
	requested_by_email: string | null;
	created_at: string;
	state: ScanState;
	attempt: number;
	max_attempts: number;
	last_error: string | null;
	cancel_requested: boolean;
	finished_at: string | null;
	result: Partial<ScopeCheckResult> | null;
}

export interface ScanPage {
	items: Scan[];
	total: number;
}

export interface Service {
	id: string;
	asset_id: string;
	asset_target: string;
	asset_name: string;
	address: string;
	port: number;
	transport: string;
	state: 'open' | 'closed';
	name: string | null;
	product: string | null;
	version: string | null;
	tls: boolean;
	detail: Record<string, unknown>;
	fingerprint_method: string | null;
	rules_version: string | null;
	first_seen_at: string;
	last_seen_at: string;
	closed_at: string | null;
	last_scan_id: string;
	last_evidence_id: string | null;
}

export interface ServicePage {
	items: Service[];
	total: number;
}

export interface Evidence {
	id: string;
	scan_id: string;
	kind: 'dns' | 'service';
	address: string | null;
	port: number | null;
	data: Record<string, unknown>;
	observed_at: string;
	scanner_version: string;
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Confidence = 'confirmed' | 'probable' | 'potential' | 'unknown';
export type RiskBand = 'urgent' | 'high' | 'medium' | 'low';
export type FindingStatus =
	| 'open'
	| 'triaged'
	| 'in_remediation'
	| 'fix_claimed'
	| 'resolved'
	| 'risk_accepted'
	| 'false_positive'
	| 'closed_unverified';

export const STATUS_LABEL: Record<FindingStatus, string> = {
	open: 'Open',
	triaged: 'Triaged',
	in_remediation: 'In remediation',
	fix_claimed: 'Fix claimed',
	resolved: 'Resolved (verified)',
	risk_accepted: 'Risk accepted',
	false_positive: 'False positive',
	closed_unverified: 'Closed (unverified)'
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
	confirmed: 'Confirmed',
	probable: 'Probable',
	potential: 'Potential',
	unknown: 'Unknown'
};

export interface Finding {
	id: string;
	asset_id: string;
	asset_target: string;
	asset_name: string;
	asset_criticality: Criticality;
	service_id: string | null;
	address: string | null;
	port: number | null;
	service_name: string | null;
	check_id: string;
	check_version: string;
	title: string;
	category: 'vulnerability' | 'misconfiguration' | 'exposure';
	severity: Severity;
	severity_score: number;
	severity_source: string;
	confidence: Confidence;
	status: FindingStatus;
	cves: string[];
	kev: boolean;
	epss: number | null;
	risk_score: number;
	risk_band: RiskBand;
	risk_model: string;
	first_seen_at: string;
	last_seen_at: string;
	not_observed_since: string | null;
	resolved_at: string | null;
	assignee_id: string | null;
	assignee_email: string | null;
	due_date: string | null;
	overdue: boolean;
	accepted_until: string | null;
	status_reason: string | null;
	reopen_count: number;
}

export interface RiskFactor {
	factor: string;
	value: unknown;
	contribution: number;
	source: string;
	provisional: boolean;
}

export interface CveIntel {
	id: string;
	description: string;
	cvss_version: string | null;
	cvss_score: number | null;
	cvss_vector: string | null;
	cvss_severity: string | null;
	cvss_source: string | null;
	cwes: string[];
	published: string | null;
	last_modified: string | null;
	vuln_status: string | null;
	refs: { url: string; tags: string[] }[];
	kev: boolean;
	kev_added: string | null;
	kev_due: string | null;
	kev_ransomware: string | null;
	kev_action: string | null;
	epss: number | null;
	epss_percentile: number | null;
	epss_date: string | null;
}

export interface FindingEvent {
	id: number;
	at: string;
	actor_id: string | null;
	actor_email: string | null;
	kind: string;
	scan_id: string | null;
	detail: Record<string, unknown>;
}

export interface FindingDetail extends Finding {
	explanation: string;
	remediation: string;
	detail: Record<string, unknown>;
	risk_factors: {
		model: string;
		score: number;
		band: RiskBand;
		factors: RiskFactor[];
		note: string;
	};
	evidence: (Evidence & { scanner_version: string })[];
	events: FindingEvent[];
	intel: CveIntel[];
	last_scan_id: string | null;
	resolved_by_scan_id: string | null;
}

export interface FindingPage {
	items: Finding[];
	total: number;
}

export interface FindingSummary {
	by_severity: Partial<Record<Severity, number>>;
	by_band: Partial<Record<RiskBand, number>>;
	by_confidence: Partial<Record<Confidence, number>>;
	by_status: Partial<Record<FindingStatus, number>>;
	kev: number;
	overdue: number;
	unassigned: number;
	not_observed: number;
	active: number;
	mean_age_days: number;
	opened_30d: number;
	resolved_30d: number;
	top_assets: {
		id: string;
		target: string;
		name: string;
		criticality: Criticality;
		findings: number;
		max_risk: number;
	}[];
	trend_30d: { day: string; opened: number; resolved: number }[];
	risk_model: string;
}

export interface IntelSource {
	name: 'nvd' | 'kev' | 'epss';
	url: string;
	status: 'never' | 'ok' | 'error';
	last_attempt_at: string | null;
	last_success_at: string | null;
	source_version: string | null;
	records: number;
	error: string | null;
	stale: boolean;
	max_age_hours: number;
}
