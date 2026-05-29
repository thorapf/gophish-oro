-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
DELETE FROM events WHERE message = 'Email Reported';
DROP TABLE IF EXISTS imap;
ALTER TABLE results DROP COLUMN reported;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
