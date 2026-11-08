"""Vulnerability intelligence (M6), findings and remediation workflow (M7/M8).

- Schema `intel`: global reference data (not tenant data): CVE records and their CPE match
  ranges from NVD, the CISA KEV catalog, FIRST EPSS scores, and per-source sync status. The
  application role may only read it; the sync job writes it with the owner role.
- `app.finding`: one deduplicated condition on one asset/address/port, with confidence (PRD
  Amendment A1), workflow status (PRD §13, A3), the evidence it cites and its risk score with
  the model version and factor breakdown (PRD §15).
- `app.finding_event`: append-only history of every observation, status change, assignment,
  comment and verification outcome.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-08
"""

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

INTEL_TABLES = ("intel.source", "intel.cve", "intel.cve_match", "intel.kev", "intel.epss")
APP_TABLES = ("app.finding", "app.finding_event")


def upgrade() -> None:
    op.execute("CREATE SCHEMA intel")
    op.execute("REVOKE ALL ON SCHEMA intel FROM PUBLIC")
    op.execute("GRANT USAGE ON SCHEMA intel TO vulnex_app")
    op.execute(
        """
        CREATE TABLE intel.source (
          name text PRIMARY KEY CHECK (name IN ('nvd', 'kev', 'epss')),
          url text NOT NULL,
          status text NOT NULL DEFAULT 'never' CHECK (status IN ('never', 'ok', 'error')),
          last_attempt_at timestamptz,
          last_success_at timestamptz,
          source_version text,
          records integer NOT NULL DEFAULT 0,
          error text CHECK (length(error) <= 1000),
          cursor jsonb NOT NULL DEFAULT '{}'
        )
        """
    )
    op.execute(
        """
        INSERT INTO intel.source (name, url) VALUES
          ('nvd', 'https://services.nvd.nist.gov/rest/json/cves/2.0'),
          ('kev', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
          ('epss', 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz')
        """
    )
    op.execute(
        """
        CREATE TABLE intel.cve (
          id text PRIMARY KEY CHECK (id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
          published timestamptz,
          last_modified timestamptz,
          vuln_status text,
          description text NOT NULL DEFAULT '',
          cvss_version text,
          cvss_score numeric(3, 1) CHECK (cvss_score BETWEEN 0 AND 10),
          cvss_vector text,
          cvss_severity text,
          cvss_source text,
          cwes text[] NOT NULL DEFAULT '{}',
          refs jsonb NOT NULL DEFAULT '[]',
          raw_sha256 text NOT NULL,
          retrieved_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE intel.cve_match (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          cve_id text NOT NULL REFERENCES intel.cve (id) ON DELETE CASCADE,
          vendor text NOT NULL,
          product text NOT NULL,
          version text,             -- an exact version from the CPE, or NULL with a range
          start_including text,
          start_excluding text,
          end_including text,
          end_excluding text,
          criteria text NOT NULL,
          conditional boolean NOT NULL  -- the node is ANDed with platform conditions
        )
        """
    )
    op.execute("CREATE INDEX cve_match_product_idx ON intel.cve_match (vendor, product)")
    op.execute("CREATE INDEX cve_match_cve_idx ON intel.cve_match (cve_id)")
    op.execute(
        """
        CREATE TABLE intel.kev (
          cve_id text PRIMARY KEY,
          vendor_project text,
          product text,
          name text,
          date_added date,
          due_date date,
          ransomware text,
          required_action text,
          short_description text,
          notes text,
          catalog_version text NOT NULL,
          retrieved_at timestamptz NOT NULL DEFAULT now()
        )
        """
    )
    op.execute(
        """
        CREATE TABLE intel.epss (
          cve_id text PRIMARY KEY,
          score numeric(6, 5) NOT NULL CHECK (score BETWEEN 0 AND 1),
          percentile numeric(6, 5) NOT NULL CHECK (percentile BETWEEN 0 AND 1),
          score_date date NOT NULL,
          model_version text
        )
        """
    )
    for table in INTEL_TABLES:
        op.execute(f"REVOKE ALL ON {table} FROM vulnex_app")
        op.execute(f"GRANT SELECT ON {table} TO vulnex_app")

    op.execute(
        """
        CREATE TABLE app.finding (
          id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          asset_id uuid NOT NULL,
          service_id uuid,
          address inet,
          port integer CHECK (port BETWEEN 1 AND 65535),
          check_id text NOT NULL CHECK (length(check_id) <= 100),
          check_version text NOT NULL CHECK (length(check_version) <= 50),
          dedupe_key text NOT NULL CHECK (length(dedupe_key) <= 300),
          title text NOT NULL CHECK (length(title) <= 300),
          category text NOT NULL
            CHECK (category IN ('vulnerability', 'misconfiguration', 'exposure')),
          severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
          severity_score numeric(3, 1) NOT NULL CHECK (severity_score BETWEEN 0 AND 10),
          severity_source text NOT NULL CHECK (length(severity_source) <= 100),
          confidence text NOT NULL
            CHECK (confidence IN ('confirmed', 'probable', 'potential', 'unknown')),
          status text NOT NULL DEFAULT 'open' CHECK (status IN (
            'open', 'triaged', 'in_remediation', 'fix_claimed', 'resolved', 'risk_accepted',
            'false_positive', 'closed_unverified')),
          cves text[] NOT NULL DEFAULT '{}',
          kev boolean NOT NULL DEFAULT false,
          epss numeric(6, 5),
          explanation text NOT NULL CHECK (length(explanation) <= 4000),
          remediation text NOT NULL DEFAULT '' CHECK (length(remediation) <= 4000),
          evidence_ids uuid[] NOT NULL DEFAULT '{}',
          detail jsonb NOT NULL DEFAULT '{}',
          risk_score integer NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
          risk_band text NOT NULL CHECK (risk_band IN ('urgent', 'high', 'medium', 'low')),
          risk_model text NOT NULL,
          risk_factors jsonb NOT NULL,
          first_seen_at timestamptz NOT NULL,
          last_seen_at timestamptz NOT NULL,
          last_scan_id uuid,
          not_observed_since timestamptz,
          resolved_at timestamptz,
          resolved_by_scan_id uuid,
          assignee_id uuid,
          due_date date,
          status_reason text CHECK (length(status_reason) <= 1000),
          accepted_until date,
          reopen_count integer NOT NULL DEFAULT 0,
          status_changed_at timestamptz NOT NULL DEFAULT now(),
          created_at timestamptz NOT NULL DEFAULT now(),
          updated_at timestamptz NOT NULL DEFAULT now(),
          UNIQUE (tenant_id, id),
          UNIQUE (tenant_id, dedupe_key),
          CHECK ((status = 'resolved') = (resolved_at IS NOT NULL)),
          CHECK (status <> 'risk_accepted' OR accepted_until IS NOT NULL),
          FOREIGN KEY (tenant_id, asset_id) REFERENCES app.asset (tenant_id, id),
          FOREIGN KEY (tenant_id, service_id) REFERENCES app.service (tenant_id, id),
          FOREIGN KEY (tenant_id, last_scan_id) REFERENCES app.scan (tenant_id, id),
          FOREIGN KEY (tenant_id, resolved_by_scan_id) REFERENCES app.scan (tenant_id, id),
          FOREIGN KEY (tenant_id, assignee_id) REFERENCES app.membership (tenant_id, user_id)
            ON DELETE SET NULL (assignee_id)
        )
        """
    )
    op.execute("CREATE INDEX finding_list_idx ON app.finding (tenant_id, status, risk_score DESC)")
    op.execute("CREATE INDEX finding_asset_idx ON app.finding (tenant_id, asset_id)")
    op.execute("CREATE INDEX finding_assignee_idx ON app.finding (tenant_id, assignee_id)")
    op.execute(
        """
        CREATE TABLE app.finding_event (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          tenant_id uuid NOT NULL REFERENCES app.tenant (id),
          finding_id uuid NOT NULL,
          at timestamptz NOT NULL DEFAULT now(),
          actor_id uuid,  -- NULL: the system (a scan or an intelligence update)
          kind text NOT NULL CHECK (kind IN (
            'detected', 'observed', 'status_changed', 'assigned', 'comment',
            'verification_passed', 'verification_inconclusive', 'reopened', 'reassessed')),
          scan_id uuid,
          detail jsonb NOT NULL DEFAULT '{}',
          FOREIGN KEY (tenant_id, finding_id) REFERENCES app.finding (tenant_id, id),
          FOREIGN KEY (tenant_id, scan_id) REFERENCES app.scan (tenant_id, id)
        )
        """
    )
    op.execute(
        "CREATE INDEX finding_event_idx ON app.finding_event (tenant_id, finding_id, at DESC)"
    )
    op.execute("REVOKE DELETE, TRUNCATE ON app.finding FROM vulnex_app")
    op.execute("REVOKE UPDATE, DELETE, TRUNCATE ON app.finding_event FROM vulnex_app")
    for table in APP_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
              USING (tenant_id = app.current_tenant())
              WITH CHECK (tenant_id = app.current_tenant())
            """
        )


def downgrade() -> None:
    op.execute("DROP TABLE app.finding_event, app.finding")
    op.execute("DROP SCHEMA intel CASCADE")
