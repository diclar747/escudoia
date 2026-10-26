CREATE TABLE IF NOT EXISTS threat_indicators (
 indicator_hash CHAR(64) PRIMARY KEY, category VARCHAR(20) NOT NULL CHECK (category IN ('url','phone')),
 verdict VARCHAR(20) NOT NULL CHECK (verdict IN ('malicious','suspicious')),
 reason VARCHAR(300) NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threat_indicators_category ON threat_indicators(category);
