-- sub_range: the IPAM netblock NAME an enrollment is bound to, resolved + persisted at
-- enroll time (the join key's sub-range, or the matched cloud-trust / user-trust scope;
-- ADR 0010 Phase 2). Approve allocates from this block instead of re-deriving it (which
-- needs the trust config loaded in the approving process). Empty -> the 'default' block.
ALTER TABLE enrollments ADD COLUMN sub_range TEXT NOT NULL DEFAULT '';
