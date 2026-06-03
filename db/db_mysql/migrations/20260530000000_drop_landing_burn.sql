-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
ALTER TABLE `results` DROP COLUMN landing_get_served;
ALTER TABLE `results` DROP COLUMN landing_post_served;

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
