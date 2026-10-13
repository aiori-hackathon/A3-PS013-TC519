

USE cybertrace;

DROP TRIGGER IF EXISTS trg_techniques_audit_update;
DROP TRIGGER IF EXISTS trg_techniques_prevent_self_parent;

DELIMITER $$

CREATE TRIGGER trg_techniques_audit_update
AFTER UPDATE ON techniques
FOR EACH ROW
BEGIN
    IF (OLD.name <> NEW.name OR OLD.description <> NEW.description) THEN
        INSERT INTO technique_audit_log (
            technique_id,
            action_type,
            old_name,
            new_name,
            changed_by,
            changed_at
        ) VALUES (
            OLD.technique_id,
            'UPDATE',
            OLD.name,
            NEW.name,
            CURRENT_USER(),
            CURRENT_TIMESTAMP
        );
    END IF;
END$$

CREATE TRIGGER trg_techniques_prevent_self_parent
BEFORE UPDATE ON techniques
FOR EACH ROW
BEGIN
    IF (NEW.parent_technique_id IS NOT NULL AND NEW.parent_technique_id = NEW.technique_id) THEN
        SIGNAL SQLSTATE '45000'
            SET MESSAGE_TEXT = 'Integrity Error: A technique cannot be its own parent sub-technique.';
    END IF;
END$$

DELIMITER ;
