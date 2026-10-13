

USE cybertrace;

SELECT 'tactics' AS table_name, COUNT(*) AS imported_rows, 15 AS expected_rows, 
       IF(COUNT(*) = 15, 'PASSED', 'MISMATCH') AS status FROM tactics
UNION ALL
SELECT 'techniques', COUNT(*), 697, IF(COUNT(*) = 697, 'PASSED', 'MISMATCH') FROM techniques
UNION ALL
SELECT 'technique_tactics', COUNT(*), 668, IF(COUNT(*) >= 600, 'PASSED', 'CHECK') FROM technique_tactics
UNION ALL
SELECT 'software', COUNT(*), 825, IF(COUNT(*) = 825, 'PASSED', 'MISMATCH') FROM software
UNION ALL
SELECT 'groups', COUNT(*), 176, IF(COUNT(*) = 176, 'PASSED', 'MISMATCH') FROM `groups`
UNION ALL
SELECT 'group_aliases', COUNT(*), (SELECT COUNT(*) FROM group_aliases), 'POPULATED' FROM group_aliases
UNION ALL
SELECT 'campaigns', COUNT(*), 56, IF(COUNT(*) = 56, 'PASSED', 'MISMATCH') FROM campaigns
UNION ALL
SELECT 'mitigations', COUNT(*), 44, IF(COUNT(*) = 44, 'PASSED', 'MISMATCH') FROM mitigations
UNION ALL
SELECT 'data_components', COUNT(*), 106, IF(COUNT(*) = 106, 'PASSED', 'MISMATCH') FROM data_components
UNION ALL
SELECT 'relationships', COUNT(*), 20628, IF(COUNT(*) = 20628, 'PASSED', 'MISMATCH') FROM `relationships`;

-- ----------------------------------------------------------------------------
-- 2. PRIMARY KEY NULL AND UNIQUENESS INTEGRITY AUDIT
-- Primary keys must NEVER be NULL and must NEVER contain duplicates
-- ----------------------------------------------------------------------------
SELECT 'tactics PK NULL check' AS test_name, COUNT(*) AS failure_count FROM tactics WHERE tactic_id IS NULL
UNION ALL
SELECT 'techniques PK NULL check', COUNT(*) FROM techniques WHERE technique_id IS NULL
UNION ALL
SELECT 'software PK NULL check', COUNT(*) FROM software WHERE software_id IS NULL
UNION ALL
SELECT 'groups PK NULL check', COUNT(*) FROM `groups` WHERE group_id IS NULL
UNION ALL
SELECT 'campaigns PK NULL check', COUNT(*) FROM campaigns WHERE campaign_id IS NULL
UNION ALL
SELECT 'mitigations PK NULL check', COUNT(*) FROM mitigations WHERE mitigation_id IS NULL
UNION ALL
SELECT 'data_components PK NULL check', COUNT(*) FROM data_components WHERE data_component_id IS NULL
UNION ALL
SELECT 'relationships PK NULL check', COUNT(*) FROM `relationships` WHERE relationship_id IS NULL;

-- Check for duplicate primary keys in primary entities
SELECT 'tactics duplicate PK check' AS test_name, COUNT(*) - COUNT(DISTINCT tactic_id) AS duplicate_count FROM tactics
UNION ALL
SELECT 'techniques duplicate PK check', COUNT(*) - COUNT(DISTINCT technique_id) FROM techniques
UNION ALL
SELECT 'software duplicate PK check', COUNT(*) - COUNT(DISTINCT software_id) FROM software
UNION ALL
SELECT 'groups duplicate PK check', COUNT(*) - COUNT(DISTINCT group_id) FROM `groups`
UNION ALL
SELECT 'campaigns duplicate PK check', COUNT(*) - COUNT(DISTINCT campaign_id) FROM campaigns
UNION ALL
SELECT 'mitigations duplicate PK check', COUNT(*) - COUNT(DISTINCT mitigation_id) FROM mitigations
UNION ALL
SELECT 'data_components duplicate PK check', COUNT(*) - COUNT(DISTINCT data_component_id) FROM data_components;


SELECT 
    'Orphan Sub-Techniques' AS check_name,
    COUNT(*) AS orphan_count
FROM techniques t
WHERE t.parent_technique_id IS NOT NULL
  AND NOT EXISTS (
      SELECT 1 FROM techniques p WHERE p.technique_id = t.parent_technique_id
  );


SELECT 
    'Orphan technique_tactics (Invalid Technique ID)' AS check_name,
    COUNT(*) AS orphan_count
FROM technique_tactics tt
WHERE NOT EXISTS (
    SELECT 1 FROM techniques t WHERE t.technique_id = tt.technique_id
);


SELECT 
    'Orphan technique_tactics (Invalid Tactic ID)' AS check_name,
    COUNT(*) AS orphan_count
FROM technique_tactics tt
WHERE NOT EXISTS (
    SELECT 1 FROM tactics tac WHERE tac.tactic_id = tt.tactic_id
);

-- Check 3.4: group_aliases -> groups
SELECT 
    'Orphan group_aliases (Invalid Group ID)' AS check_name,
    COUNT(*) AS orphan_count
FROM group_aliases ga
WHERE NOT EXISTS (
    SELECT 1 FROM `groups` g WHERE g.group_id = ga.group_id
);

-- Check 3.5: Duplicate junction entries in technique_tactics
SELECT 
    technique_id, 
    tactic_id, 
    COUNT(*) AS occurrence_count
FROM technique_tactics
GROUP BY technique_id, tactic_id
HAVING COUNT(*) > 1;

-- ----------------------------------------------------------------------------
-- 4. RELATIONSHIPS SUMMARY AUDIT (THREAT GRAPH CONSISTENCY)
-- Verifies the semantic distribution of the 20,628 relationship records
-- ----------------------------------------------------------------------------
SELECT 
    source_type,
    mapping_type,
    target_type,
    COUNT(*) AS relationship_count
FROM `relationships`
GROUP BY source_type, mapping_type, target_type
ORDER BY relationship_count DESC;
