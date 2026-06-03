-- +goose Up
-- SQL in section 'Up' is executed when this migration is applied
-- The "Bot Click" event was appended by the upstream redirector's /beep
-- endpoint, which has been removed along with its bot detection. The admin
-- timeline no longer has a rendering mapping for this event type, so drop any
-- historical rows to keep campaign result pages from choking on them.
DELETE FROM `events` WHERE message = 'Bot Click';

-- +goose Down
-- SQL section 'Down' is executed when this migration is rolled back
