-- Index for the per-page device-provenance lookup: deviceProvenance() resolves each
-- device's authoritative (latest issued) enrollment with WHERE overlay_ip IN (page)
-- AND status='issued'. This composite index serves that predicate (enrollments had
-- only idx_enrollments_status before). (The scope-filter allow-set is a deliberate
-- status='issued' scan, served by idx_enrollments_status, not this index.)
CREATE INDEX idx_enrollments_overlay_status ON enrollments(overlay_ip, status);
