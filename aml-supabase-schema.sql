-- ============================================================
-- AML·CDD Supabase Schema
-- Run this in: Supabase Dashboard → SQL Editor → New Query
-- ============================================================

-- Enable fuzzy string matching extension (required for trigram search)
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS unaccent;

-- ── TABLE: watchlist_entities ────────────────────────────────
-- Core watchlist — both individuals and companies
CREATE TABLE IF NOT EXISTS watchlist_entities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_type     TEXT NOT NULL CHECK (entity_type IN ('INDIVIDUAL','CORPORATE','PARTNERSHIP','TRUST')),
    full_name       TEXT NOT NULL,
    full_name_upper TEXT GENERATED ALWAYS AS (UPPER(full_name)) STORED,
    risk_tier       TEXT NOT NULL CHECK (risk_tier IN ('LOW','MEDIUM','HIGH','CRITICAL')),

    -- Identification
    id_number       TEXT,            -- NRIC / passport / UEN / company reg
    date_of_birth   DATE,
    nationality     TEXT,
    country_of_inc  TEXT,            -- For corporates

    -- Classification
    reason_codes    TEXT[] NOT NULL DEFAULT '{}',
    -- Possible values:
    -- 'BLACKLIST','PEP','SANCTIONS','ADVERSE_MEDIA','STR_FILED',
    -- 'FRAUD','SHELL_COMPANY','HIGH_RISK_JURISDICTION',
    -- 'NOMINEE_DIRECTOR','UBO_CONCEALMENT','DRUG_TRAFFICKING',
    -- 'TERRORISM_FINANCING','MONEY_LAUNDERING','INTERNAL_FLAG'

    -- Narrative
    reason_text     TEXT,            -- Human-readable reason for listing
    source          TEXT,            -- e.g. 'Internal', 'MAS', 'OFAC', 'Police Report'
    case_reference  TEXT,            -- Internal case/file number
    listed_by       TEXT,            -- Analyst who added the record
    listed_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_reviewed   TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,     -- NULL = permanent listing
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,

    -- Address
    address         TEXT,
    country         TEXT,

    -- Metadata
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── TABLE: watchlist_aliases ─────────────────────────────────
-- Alternative names / aliases / transliterations for each entity
CREATE TABLE IF NOT EXISTS watchlist_aliases (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id   UUID NOT NULL REFERENCES watchlist_entities(id) ON DELETE CASCADE,
    alias       TEXT NOT NULL,
    alias_upper TEXT GENERATED ALWAYS AS (UPPER(alias)) STORED,
    alias_type  TEXT CHECK (alias_type IN ('AKA','MAIDEN_NAME','ROMANISATION','CHINESE','MALAY','ABBREVIATION','FORMER_NAME','TRADE_NAME')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── TABLE: watchlist_linked_entities ────────────────────────
-- Corporate links, UBO chains, associated individuals/companies
CREATE TABLE IF NOT EXISTS watchlist_linked_entities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity_id       UUID NOT NULL REFERENCES watchlist_entities(id) ON DELETE CASCADE,
    linked_name     TEXT NOT NULL,
    linked_type     TEXT CHECK (linked_type IN ('INDIVIDUAL','CORPORATE','PARTNERSHIP','TRUST')),
    relationship    TEXT NOT NULL,
    -- e.g. 'Director', 'Shareholder >25%', 'UBO', 'Subsidiary',
    --      'Nominee Director', 'Associated Person', 'Spouse', 'Parent Company'
    ownership_pct   NUMERIC(5,2),   -- Ownership percentage if applicable
    country         TEXT,
    notes           TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── TABLE: screening_log ─────────────────────────────────────
-- Audit trail of every screening run against this database
CREATE TABLE IF NOT EXISTS screening_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    screened_name   TEXT NOT NULL,
    entity_type     TEXT,
    risk_score      INT,
    risk_level      TEXT,
    db_matches      INT DEFAULT 0,          -- Number of watchlist matches found
    confirmed_hits  INT DEFAULT 0,          -- High-confidence matches
    analyst         TEXT,
    api_key_hash    TEXT,                   -- Hashed API key (never store raw)
    screened_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration_ms     INT,
    payload_summary JSONB                   -- Summary of fields screened (no PII)
);

-- ── TABLE: api_keys ──────────────────────────────────────────
-- API key management
CREATE TABLE IF NOT EXISTS api_keys (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash    TEXT UNIQUE NOT NULL,   -- SHA-256 hash of the key
    label       TEXT NOT NULL,          -- e.g. "Edmund's Frontend", "Production"
    is_active   BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used   TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ
);

-- ── INDEXES ──────────────────────────────────────────────────
-- Trigram indexes for fuzzy matching
CREATE INDEX IF NOT EXISTS idx_entity_name_trgm
    ON watchlist_entities USING GIN (full_name_upper gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_alias_trgm
    ON watchlist_aliases USING GIN (alias_upper gin_trgm_ops);

-- Standard indexes
CREATE INDEX IF NOT EXISTS idx_entity_active     ON watchlist_entities(is_active);
CREATE INDEX IF NOT EXISTS idx_entity_risk_tier  ON watchlist_entities(risk_tier);
CREATE INDEX IF NOT EXISTS idx_entity_type       ON watchlist_entities(entity_type);
CREATE INDEX IF NOT EXISTS idx_entity_id_number  ON watchlist_entities(id_number);
CREATE INDEX IF NOT EXISTS idx_alias_entity_id   ON watchlist_aliases(entity_id);
CREATE INDEX IF NOT EXISTS idx_linked_entity_id  ON watchlist_linked_entities(entity_id);
CREATE INDEX IF NOT EXISTS idx_screening_at      ON screening_log(screened_at DESC);

-- ── AUTO-UPDATE TIMESTAMP ─────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_entity_updated
    BEFORE UPDATE ON watchlist_entities
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ── FUZZY SEARCH FUNCTION ─────────────────────────────────────
-- Returns matches from both entity names and aliases with confidence score
CREATE OR REPLACE FUNCTION search_watchlist(
    p_name      TEXT,
    p_threshold FLOAT DEFAULT 0.25
)
RETURNS TABLE (
    entity_id       UUID,
    full_name       TEXT,
    entity_type     TEXT,
    risk_tier       TEXT,
    reason_codes    TEXT[],
    reason_text     TEXT,
    source          TEXT,
    id_number       TEXT,
    nationality     TEXT,
    is_active       BOOLEAN,
    match_source    TEXT,   -- 'NAME' or 'ALIAS'
    matched_value   TEXT,   -- The name/alias that matched
    similarity      FLOAT
)
LANGUAGE sql STABLE AS $$
    -- Match on primary name
    SELECT
        e.id, e.full_name, e.entity_type, e.risk_tier,
        e.reason_codes, e.reason_text, e.source, e.id_number,
        e.nationality, e.is_active,
        'NAME'::TEXT AS match_source,
        e.full_name AS matched_value,
        similarity(e.full_name_upper, UPPER(p_name)) AS sim
    FROM watchlist_entities e
    WHERE e.is_active = TRUE
      AND similarity(e.full_name_upper, UPPER(p_name)) >= p_threshold

    UNION ALL

    -- Match on aliases
    SELECT
        e.id, e.full_name, e.entity_type, e.risk_tier,
        e.reason_codes, e.reason_text, e.source, e.id_number,
        e.nationality, e.is_active,
        'ALIAS'::TEXT AS match_source,
        a.alias AS matched_value,
        similarity(a.alias_upper, UPPER(p_name)) AS sim
    FROM watchlist_aliases a
    JOIN watchlist_entities e ON e.id = a.entity_id
    WHERE e.is_active = TRUE
      AND similarity(a.alias_upper, UPPER(p_name)) >= p_threshold

    ORDER BY sim DESC
    LIMIT 20;
$$;

-- ── ROW LEVEL SECURITY ────────────────────────────────────────
ALTER TABLE watchlist_entities     ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlist_aliases      ENABLE ROW LEVEL SECURITY;
ALTER TABLE watchlist_linked_entities ENABLE ROW LEVEL SECURITY;
ALTER TABLE screening_log          ENABLE ROW LEVEL SECURITY;

-- Service role can do everything (your backend uses service role key)
CREATE POLICY "service_all_entities" ON watchlist_entities
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY "service_all_aliases" ON watchlist_aliases
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY "service_all_linked" ON watchlist_linked_entities
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);
CREATE POLICY "service_all_log" ON screening_log
    FOR ALL TO service_role USING (TRUE) WITH CHECK (TRUE);

-- ── SAMPLE SEED DATA ──────────────────────────────────────────
-- Load a few demo entries so you can test screening immediately
INSERT INTO watchlist_entities (
    entity_type, full_name, risk_tier, id_number,
    nationality, reason_codes, reason_text, source, listed_by, case_reference
) VALUES
(
    'INDIVIDUAL', 'John Tan Wei Ming', 'HIGH', 'S8812345A',
    'Singapore',
    ARRAY['BLACKLIST','STR_FILED','MONEY_LAUNDERING'],
    'Subject of internal investigation for structuring transactions below SGD 10,000 threshold. STR filed Jun 2024.',
    'Internal', 'Edmund Ker', 'CASE-2024-0012'
),
(
    'INDIVIDUAL', 'Li Wei', 'CRITICAL', 'G87654321A',
    'China',
    ARRAY['SANCTIONS','TERRORISM_FINANCING'],
    'Matches UN Security Council designation. Suspected financing links to designated group.',
    'UN Security Council', 'Edmund Ker', 'CASE-2024-0031'
),
(
    'CORPORATE', 'Global Trade Solutions Pte Ltd', 'HIGH', '202312345A',
    'Singapore',
    ARRAY['SHELL_COMPANY','UBO_CONCEALMENT','HIGH_RISK_JURISDICTION'],
    'Complex layered ownership. UBO traced to Myanmar-registered holding company. No verifiable business activity.',
    'Internal', 'Edmund Ker', 'CASE-2024-0045'
),
(
    'INDIVIDUAL', 'Ahmad Bin Hassan', 'MEDIUM', 'S9023456B',
    'Singapore',
    ARRAY['PEP','ADVERSE_MEDIA'],
    'Former civil servant. Adverse media coverage relating to corruption investigation (2022). No charges filed.',
    'Internal', 'Edmund Ker', 'CASE-2024-0018'
),
(
    'CORPORATE', 'Crypto Assets International Ltd', 'HIGH', '1234567-X',
    'Malaysia',
    ARRAY['HIGH_RISK_JURISDICTION','FRAUD','ADVERSE_MEDIA'],
    'Multiple customer complaints. Suspected unlicensed money service business. MAS advisory issued.',
    'MAS Advisory', 'Edmund Ker', 'CASE-2024-0067'
);

-- Add aliases for the seed entities
INSERT INTO watchlist_aliases (entity_id, alias, alias_type)
SELECT id, 'John Tan', 'AKA' FROM watchlist_entities WHERE full_name = 'John Tan Wei Ming';

INSERT INTO watchlist_aliases (entity_id, alias, alias_type)
SELECT id, '李威', 'CHINESE' FROM watchlist_entities WHERE full_name = 'Li Wei';

INSERT INTO watchlist_aliases (entity_id, alias, alias_type)
SELECT id, 'GTS Pte Ltd', 'ABBREVIATION' FROM watchlist_entities WHERE full_name = 'Global Trade Solutions Pte Ltd';

-- ── VERIFY SETUP ─────────────────────────────────────────────
-- Run these to confirm everything is working:
-- SELECT COUNT(*) FROM watchlist_entities;
-- SELECT * FROM search_watchlist('John Tan', 0.3);
-- SELECT * FROM search_watchlist('Global Trade', 0.2);
