CREATE TABLE IF NOT EXISTS images (
    image                           TEXT        PRIMARY KEY,
    submitted_timestamp             TIMESTAMP   DEFAULT CURRENT_TIMESTAMP,

    docker_pull_failed              INTEGER     DEFAULT 0,
    docker_pull_failed_timestamp    TIMESTAMP   DEFAULT NULL,

    sbom_timestamp                  TIMESTAMP   DEFAULT NULL,
    sbom_json                       JSONB       DEFAULT NULL,
    sbom_json_size                  INTEGER     DEFAULT NULL,
    sbom_duration_sec               INTEGER     DEFAULT NULL,

    vscan_timestamp                 TIMESTAMP   DEFAULT NULL,
    vscan_json                      JSONB       DEFAULT NULL,
    vscan_json_size                 INTEGER     DEFAULT NULL,
    vscan_duration_sec              INTEGER     DEFAULT NULL,
    vscan_summary                   JSONB       DEFAULT NULL
);

CREATE INDEX IF NOT EXISTS idx_images_docker_pull_failed            ON images (docker_pull_failed);
CREATE INDEX IF NOT EXISTS idx_images_submitted_timestamp           ON images (submitted_timestamp);
CREATE INDEX IF NOT EXISTS idx_images_docker_pull_failed_timestamp  ON images (docker_pull_failed_timestamp);
CREATE INDEX IF NOT EXISTS idx_images_sbom_timestamp                ON images (sbom_timestamp);
CREATE INDEX IF NOT EXISTS idx_images_vscan_timestamp               ON images (vscan_timestamp);


-- Update *json_size fields on row updates
CREATE OR REPLACE FUNCTION calculate_json_sizes()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.sbom_json IS DISTINCT FROM OLD.sbom_json THEN
        NEW.sbom_json_size := LENGTH(NEW.sbom_json::TEXT);
    END IF;

    IF NEW.vscan_json IS DISTINCT FROM OLD.vscan_json THEN
        NEW.vscan_json_size := LENGTH(NEW.vscan_json::TEXT);
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER update_json_sizes
BEFORE INSERT OR UPDATE OF sbom_json, vscan_json ON images
FOR EACH ROW
EXECUTE FUNCTION calculate_json_sizes();
-- /Update *json_size fields on row updates



-- Backend notification
CREATE OR REPLACE FUNCTION notify_table_change() RETURNS trigger AS $$
BEGIN
    PERFORM pg_notify('table_changed', '');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER images_table_change_trigger
    AFTER INSERT OR UPDATE ON images
    FOR EACH ROW EXECUTE FUNCTION notify_table_change();
-- /Backend notification
