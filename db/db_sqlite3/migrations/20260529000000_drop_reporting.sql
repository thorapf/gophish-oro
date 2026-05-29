-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
DELETE FROM events WHERE message = 'Email Reported';
DROP TABLE IF EXISTS imap;

-- SQLite < 3.35 doesn't support ALTER TABLE ... DROP COLUMN, so we use the
-- canonical recreate-and-copy pattern. results_new is dropped first in case
-- a prior failed run left an artifact.
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
    "modified_date" datetime,
    "landing_get_served" boolean default 0,
    "landing_post_served" boolean default 0
);

INSERT INTO results_new (id, campaign_id, user_id, r_id, email, first_name, last_name, status, ip, latitude, longitude, position, send_date, modified_date, landing_get_served, landing_post_served)
SELECT id, campaign_id, user_id, r_id, email, first_name, last_name, status, ip, latitude, longitude, position, send_date, modified_date, landing_get_served, landing_post_served FROM results;

DROP TABLE results;
ALTER TABLE results_new RENAME TO results;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
