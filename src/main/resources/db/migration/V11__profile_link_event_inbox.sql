SET search_path TO app, extensions, public;

-- Durable inbox for cross-topic lifecycle events. Profile-linked and
-- profile-link-requested are deliberately separate contracts, so Kafka cannot
-- guarantee their relative arrival order.
CREATE TABLE consumer_event_receipts (
    event_id uuid NOT NULL,
    consumer_name varchar(120) NOT NULL,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (event_id, consumer_name)
);

CREATE TABLE pending_profile_link_completions (
    account_id uuid PRIMARY KEY,
    account_type varchar(16) NOT NULL,
    profile_id uuid NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_pending_profile_link_type
        CHECK (account_type IN ('CUSTOMER', 'ADMIN', 'HOST'))
);

COMMENT ON TABLE consumer_event_receipts IS
    'Idempotency inbox for Authentication consumers; independent from removed legacy credential tables.';
COMMENT ON TABLE pending_profile_link_completions IS
    'Buffers profile-linked events that arrive before their profile-link-requested account projection.';
