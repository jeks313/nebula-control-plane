DROP TABLE pilot_artifacts;
DROP TABLE nebula_artifacts;
ALTER TABLE pilot_versions  DROP COLUMN goarch;
ALTER TABLE pilot_versions  DROP COLUMN goos;
ALTER TABLE nebula_versions DROP COLUMN goarch;
ALTER TABLE nebula_versions DROP COLUMN goos;
