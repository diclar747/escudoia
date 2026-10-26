CREATE TABLE IF NOT EXISTS threat_reports (
 id BIGSERIAL PRIMARY KEY,
 indicator_hash CHAR(64) NOT NULL,
 category VARCHAR(30) NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threat_reports_created ON threat_reports(created_at);
