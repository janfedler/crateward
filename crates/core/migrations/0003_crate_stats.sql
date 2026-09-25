-- Popularity from the daily crates.io database dump.
CREATE TABLE crate_stats (
    canonical_name        text        PRIMARY KEY,
    crate_name            text        NOT NULL,
    downloads             bigint      NOT NULL,
    reverse_dependencies  bigint      NOT NULL,
    updated_at            timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX crate_stats_reverse ON crate_stats (reverse_dependencies DESC);
