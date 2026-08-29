-- Migration number: 0002 	 2026-08-29T12:37:03.622Z
--
-- Every soft-deletable table's normal list/dashboard queries filter on
-- `deleted_at IS NULL` (or the recycle bin filters `IS NOT NULL`) on
-- essentially every read — this is the single hottest predicate in the
-- whole app and had no index at all until now. Also covers two lookups
-- (contacts by status, registrations by workshop) that were doing full
-- table scans. Purely additive — CREATE INDEX does not rewrite existing
-- row data, so this carries none of the risk a column/constraint change
-- to a table already holding real client data would.

CREATE INDEX idx_clients_deleted_at ON clients(deleted_at);
CREATE INDEX idx_sessions_deleted_at ON sessions(deleted_at);
CREATE INDEX idx_contacts_deleted_at ON contacts(deleted_at);
CREATE INDEX idx_contacts_status ON contacts(status);
CREATE INDEX idx_workshop_registrations_deleted_at ON workshop_registrations(deleted_at);
CREATE INDEX idx_workshop_registrations_workshop ON workshop_registrations(workshop_id);
