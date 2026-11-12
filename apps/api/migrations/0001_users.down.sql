-- Reversible migration: drop the users cache. Refresh sessions live in
-- Redis and are unaffected.
DROP TABLE IF EXISTS users;
