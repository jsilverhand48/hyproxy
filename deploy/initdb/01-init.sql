-- Dev-only bootstrap for the Docker Compose Postgres.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
CREATE DATABASE hyproxy_test OWNER hyproxy;
\connect hyproxy_test
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;
