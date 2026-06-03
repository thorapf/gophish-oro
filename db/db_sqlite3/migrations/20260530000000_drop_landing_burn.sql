-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
-- The one-shot landing burn is replaced by time-bound signed URLs, so the
-- two boolean columns are no longer used. SQLite < 3.35 has no
-- ALTER TABLE ... DROP COLUMN, so recreate-and-copy.
DROP TABLE IF EXISTS results_new;

CREATE TABLE results_new (
    "id" integer primary key autoincrement,
    "campaign_id" bigint,
    "user_id" bigint,
    "r_id" varchar(255),
    "email" varchar(255),
    "first_name" varchar(255),
    "last_name" varchar(255),
    "status" varchar(255) NOT NULL,
    "ip" varchar(255),
    "latitude" real,
    "longitude" real,
    "position" varchar(255),
    "send_date" datetime,
    "modified_date" datetime
);

INSERT INTO results_new (id, campaign_id, user_id, r_id, email, first_name, last_name, status, ip, latitude, longitude, position, send_date, modified_date)
SELECT id, campaign_id, user_id, r_id, email, first_name, last_name, status, ip, latitude, longitude, position, send_date, modified_date FROM results;

DROP TABLE results;
ALTER TABLE results_new RENAME TO results;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
