# D1 migrations

Schema changes for the `avital-heal-crm` D1 database live here as numbered
SQL files, applied via Cloudflare's own D1 migrations tooling — not by any
code that runs in the Worker's request path.

## Deploying a schema change

1. Create the migration: `npx wrangler d1 migrations create avital-heal-crm <short-name>`
   (from the `worker/` directory). This creates `migrations/000N_<short-name>.sql`.
2. Write the SQL. Prefer additive, non-destructive changes (`CREATE TABLE`,
   `ADD COLUMN`, `CREATE INDEX`). SQLite's `ALTER TABLE` cannot add a
   constraint or foreign key to an existing table — doing that requires
   rebuilding the table (rename → create → copy → drop), which rewrites
   every row. Do not do that to a table holding real client/session data
   without an explicit go-ahead and a fresh backup — this is a schema
   change with real data-rewrite risk, not a pure metadata operation.
3. Test it locally first (safe, fully offline, no Cloudflare credentials
   needed): `npx wrangler d1 migrations apply avital-heal-crm --local`
4. Apply it to production **before** deploying the Worker code that depends
   on it: `npx wrangler d1 migrations apply avital-heal-crm --remote`
   A failing migration rolls itself back and halts here — the deploy must
   not proceed past a failed `apply`.
5. Deploy the Worker: `npx wrangler deploy` (from `worker/`).

Applying migrations requires a Cloudflare API token — see the project's
established pattern for supplying one without pasting it into chat (save it
to a local file, inject via `CLOUDFLARE_API_TOKEN=$(cat ...)`, delete the
file immediately after).

## `0001_baseline.sql` — special case, already applied

This file is a byte-accurate snapshot of the schema as it already existed in
production on 2026-08-29, from before this migrations system existed (most
of these tables were previously created ad hoc by a migration runner that
used to live in `worker/index.js`'s request path — removed in the same
change that added this directory). It was **not run** against the
production database — running `CREATE TABLE users (...)` etc. against a
database that already has those tables would simply fail.

Instead, production's `d1_migrations` bookkeeping table was seeded directly
with a row recording `0001_baseline.sql` as already applied, so `wrangler`
treats it as satisfied and moves straight to later migrations. The file
still serves its real purpose: `wrangler d1 migrations apply --local`
against a brand new, empty D1 database reconstructs the exact current
schema from scratch — the "can stand up a fresh D1 from nothing" property
this whole directory exists to provide.

Every migration after `0001` is a normal one: written, tested `--local`,
and actually applied `--remote` for real.

## Known gap: missing foreign keys on a few newer tables

`refresh_tokens.user_id`, `mfa_backup_codes.user_id`, and
`password_resets.user_id` all reference `users.id` but have no declared
foreign key — they were created via `CREATE TABLE IF NOT EXISTS` without
one. Adding it now means the table-rebuild procedure described above,
which is why it wasn't done in the same pass that introduced this
migrations system. All three hold only operational/security state (no
client health data) and would be a much lower-stakes place to practice that
procedure than `clients` or `sessions` — but it should still be a deliberate,
explicitly-approved follow-up, not a change bundled into an unrelated
migration.
