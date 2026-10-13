

USE cybertrace;

DROP PROCEDURE IF EXISTS sp_search_technique_by_id;
DROP PROCEDURE IF EXISTS sp_search_technique_by_name;
DROP PROCEDURE IF EXISTS sp_get_techniques_by_tactic;
DROP PROCEDURE IF EXISTS sp_get_software_for_technique;
DROP PROCEDURE IF EXISTS sp_get_groups_for_technique;
DROP PROCEDURE IF EXISTS sp_correlate_incident_techniques;

DELIMITER $$

CREATE PROCEDURE sp_search_technique_by_id(
    IN p_technique_id VARCHAR(20)
)
BEGIN
    SELECT 
        t.technique_id,
        t.name AS technique_name,
        t.is_subtechnique,
        t.parent_technique_id,
        p.name AS parent_technique_name,
        t.description,
        t.url,
        t.version,
        GROUP_CONCAT(DISTINCT tac.name SEPARATOR ', ') AS tactics
    FROM techniques t
    LEFT JOIN techniques p ON t.parent_technique_id = p.technique_id
    LEFT JOIN technique_tactics tt ON t.technique_id = tt.technique_id
    LEFT JOIN tactics tac ON tt.tactic_id = tac.tactic_id
    WHERE t.technique_id = p_technique_id
    GROUP BY t.technique_id, t.name, t.is_subtechnique, t.parent_technique_id, p.name, t.description, t.url, t.version;
END$$

CREATE PROCEDURE sp_search_technique_by_name(
    IN p_keyword VARCHAR(100)
)
BEGIN
    SELECT 
        technique_id,
        name,
        is_subtechnique,
        parent_technique_id,
        url
    FROM techniques
    WHERE name LIKE CONCAT('%', p_keyword, '%')
    ORDER BY name ASC;
END$$

CREATE PROCEDURE sp_get_techniques_by_tactic(
    IN p_tactic_id VARCHAR(10)
)
BEGIN
    SELECT 
        t.technique_id,
        t.name AS technique_name,
        t.is_subtechnique,
        t.parent_technique_id,
        t.url
    FROM techniques t
    INNER JOIN technique_tactics tt ON t.technique_id = tt.technique_id
    WHERE tt.tactic_id = p_tactic_id
    ORDER BY t.is_subtechnique ASC, t.name ASC;
END$$

CREATE PROCEDURE sp_get_software_for_technique(
    IN p_technique_id VARCHAR(20)
)
BEGIN
    SELECT 
        s.software_id,
        s.name AS software_name,
        s.type AS software_type,
        r.mapping_description
    FROM software s
    INNER JOIN `relationships` r 
        ON s.software_id = r.source_id 
       AND r.mapping_type = 'uses' 
       AND r.target_type = 'technique'
    WHERE r.target_id = p_technique_id
    ORDER BY s.type ASC, s.name ASC;
END$$

CREATE PROCEDURE sp_get_groups_for_technique(
    IN p_technique_id VARCHAR(20)
)
BEGIN
    SELECT 
        g.group_id,
        g.name AS group_name,
        r.mapping_description
    FROM `groups` g
    INNER JOIN `relationships` r 
        ON g.group_id = r.source_id 
       AND r.mapping_type = 'uses' 
       AND r.target_type = 'technique'
    WHERE r.target_id = p_technique_id
    ORDER BY g.name ASC;
END$$

CREATE PROCEDURE sp_correlate_incident_techniques(
    IN p_technique_id_1 VARCHAR(20),
    IN p_technique_id_2 VARCHAR(20)
)
BEGIN
  
    SELECT 
        'COMMON_THREAT_GROUP' AS correlation_type,
        g.group_id AS entity_id,
        g.name AS entity_name
    FROM `groups` g
    WHERE g.group_id IN (
        SELECT source_id FROM `relationships` WHERE target_id = p_technique_id_1 AND mapping_type = 'uses'
    )
    AND g.group_id IN (
        SELECT source_id FROM `relationships` WHERE target_id = p_technique_id_2 AND mapping_type = 'uses'
    )
    UNION ALL
   
    SELECT 
        'COMMON_SOFTWARE' AS correlation_type,
        s.software_id AS entity_id,
        s.name AS entity_name
    FROM software s
    WHERE s.software_id IN (
        SELECT source_id FROM `relationships` WHERE target_id = p_technique_id_1 AND mapping_type = 'uses'
    )
    AND s.software_id IN (
        SELECT source_id FROM `relationships` WHERE target_id = p_technique_id_2 AND mapping_type = 'uses'
    );
END$$

DELIMITER ;
