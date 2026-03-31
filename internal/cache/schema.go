package cache

const createTableSQL = `
CREATE TABLE IF NOT EXISTS decisions (
    script_hash TEXT NOT NULL,
    verdict     TEXT NOT NULL,
    source      TEXT NOT NULL,
    identity    TEXT,
    reason      TEXT,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    PRIMARY KEY (script_hash)
);
`
