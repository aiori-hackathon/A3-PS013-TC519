 USE cybertrace;

SELECT 
    tactic_id,
    name AS tactic_name,
    version,
    url
FROM tactics
ORDER BY tactic_id ASC;

SELECT 
    technique_id,
    name AS technique_name,
    supports_remote,
    version
FROM techniques
WHERE is_subtechnique = 0 
  AND supports_remote IS NOT NULL
ORDER BY name ASC;

SELECT DISTINCT 
    type AS software_classification
FROM software;


SELECT 
    tac.tactic_id,
    tac.name AS tactic_name,
    COUNT(tt.technique_id) AS total_techniques
FROM tactics tac
INNER JOIN technique_tactics tt ON tac.tactic_id = tt.tactic_id
GROUP BY tac.tactic_id, tac.name
ORDER BY total_techniques DESC;

SELECT 
    tac.tactic_id,
    tac.name AS tactic_name,
    COUNT(tt.technique_id) AS total_techniques
FROM tactics tac
INNER JOIN technique_tactics tt ON tac.tactic_id = tt.tactic_id
GROUP BY tac.tactic_id, tac.name
HAVING COUNT(tt.technique_id) > 40
ORDER BY total_techniques DESC;

SELECT 
    type AS software_type,
    COUNT(*) AS total_count,
    ROUND((COUNT(*) / (SELECT COUNT(*) FROM software)) * 100, 2) AS percentage_of_software
FROM software
GROUP BY type;


SELECT 
    t.technique_id,
    t.name AS technique_name,
    tac.tactic_id,
    tac.name AS tactic_name
FROM techniques t
INNER JOIN technique_tactics tt ON t.technique_id = tt.technique_id
INNER JOIN tactics tac ON tt.tactic_id = tac.tactic_id
WHERE tac.tactic_id = 'TA0001' -- Initial Access
ORDER BY t.technique_id ASC;

SELECT 
    sub.technique_id AS sub_technique_id,
    sub.name AS sub_technique_name,
    sub.parent_technique_id,
    parent.name AS parent_technique_name
FROM techniques sub
INNER JOIN techniques parent ON sub.parent_technique_id = parent.technique_id
ORDER BY parent.technique_id, sub.technique_id;
SELECT 
    g.group_id,
    g.name AS group_name,
    s.software_id,
    s.name AS software_name,
    s.type AS software_type,
    r.mapping_description
FROM `groups` g
INNER JOIN `relationships` r ON g.group_id = r.source_id
INNER JOIN software s ON r.target_id = s.software_id
WHERE g.group_id = 'G0007'
  AND r.mapping_type = 'uses'
  AND r.target_type = 'software'
ORDER BY s.name ASC;
SELECT 
    t.technique_id,
    t.name AS technique_name,
    t.is_subtechnique
FROM techniques t
LEFT JOIN `relationships` r 
    ON t.technique_id = r.target_id 
   AND r.source_type = 'software' 
   AND r.mapping_type = 'uses'
WHERE r.relationship_id IS NULL
ORDER BY t.technique_id ASC
LIMIT 15;
SELECT 
    group_id,
    name AS group_name
FROM `groups`
WHERE group_id IN (
    SELECT source_id 
    FROM `relationships` 
    WHERE target_id = 'T1059' 
      AND mapping_type = 'uses' 
      AND source_type = 'group'
)
ORDER BY name ASC;
SELECT 
    p.technique_id,
    p.name AS parent_technique_name,
    (SELECT COUNT(*) FROM techniques s WHERE s.parent_technique_id = p.technique_id) AS sub_technique_count
FROM techniques p
WHERE p.is_subtechnique = 0
  AND (SELECT COUNT(*) FROM techniques s WHERE s.parent_technique_id = p.technique_id) >= 10
ORDER BY sub_technique_count DESC;
SELECT 
    technique_id,
    name,
    CASE 
        WHEN is_subtechnique = 1 THEN 'Specific Implementation (Sub-technique)'
        WHEN is_subtechnique = 0 AND parent_technique_id IS NULL THEN 'Core Adversary Technique'
        ELSE 'Other'
    END AS technique_hierarchy_category,
    CASE 
        WHEN supports_remote IS NOT NULL THEN 'Remote Execution Capable'
        ELSE 'Local / Unspecified'
    END AS execution_scope
FROM techniques
LIMIT 20;
SELECT 
    technique_id,
    technique_name,
    associated_software_count,
    associated_groups_count,
    total_relationships_count
FROM v_technique_connectivity
ORDER BY total_relationships_count DESC
LIMIT 10;

]
CALL sp_correlate_incident_techniques('T1059', 'T1003');
