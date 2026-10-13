
USE cybertrace;

CREATE OR REPLACE VIEW v_technique_details AS
SELECT 
    t.technique_id,
    t.name AS technique_name,
    t.is_subtechnique,
    t.parent_technique_id,
    p.name AS parent_technique_name,
    GROUP_CONCAT(DISTINCT tac.name ORDER BY tac.name SEPARATOR ', ') AS tactics_list,
    t.url,
    t.version
FROM techniques t
LEFT JOIN techniques p ON t.parent_technique_id = p.technique_id
LEFT JOIN technique_tactics tt ON t.technique_id = tt.technique_id
LEFT JOIN tactics tac ON tt.tactic_id = tac.tactic_id
GROUP BY t.technique_id, t.name, t.is_subtechnique, t.parent_technique_id, p.name, t.url, t.version;

CREATE OR REPLACE VIEW v_matrix_overview AS
SELECT 
    tac.tactic_id,
    tac.name AS tactic_name,
    t.technique_id,
    t.name AS technique_name,
    t.is_subtechnique,
    t.parent_technique_id
FROM tactics tac
INNER JOIN technique_tactics tt ON tac.tactic_id = tt.tactic_id
INNER JOIN techniques t ON tt.technique_id = t.technique_id
ORDER BY tac.tactic_id, t.is_subtechnique, t.technique_id;

CREATE OR REPLACE VIEW v_threat_actor_profiles AS
SELECT 
    g.group_id,
    g.name AS group_name,
    GROUP_CONCAT(DISTINCT ga.alias_name ORDER BY ga.alias_name SEPARATOR ', ') AS known_aliases,
    COUNT(DISTINCT r_tech.target_id) AS techniques_used_count,
    COUNT(DISTINCT r_soft.target_id) AS software_used_count,
    g.url
FROM `groups` g
LEFT JOIN group_aliases ga ON g.group_id = ga.group_id
LEFT JOIN `relationships` r_tech 
    ON g.group_id = r_tech.source_id 
   AND r_tech.mapping_type = 'uses' 
   AND r_tech.target_type = 'technique'
LEFT JOIN `relationships` r_soft 
    ON g.group_id = r_soft.source_id 
   AND r_soft.mapping_type = 'uses' 
   AND r_soft.target_type = 'software'
GROUP BY g.group_id, g.name, g.url;

CREATE OR REPLACE VIEW v_software_usage AS
SELECT 
    s.software_id,
    s.name AS software_name,
    s.type AS software_type,
    r.target_id AS technique_id,
    t.name AS technique_name,
    r.mapping_description
FROM software s
INNER JOIN `relationships` r 
    ON s.software_id = r.source_id 
   AND r.mapping_type = 'uses' 
   AND r.target_type = 'technique'
INNER JOIN techniques t 
    ON r.target_id = t.technique_id;

CREATE OR REPLACE VIEW v_campaign_attribution AS
SELECT 
    c.campaign_id,
    c.name AS campaign_name,
    c.first_seen,
    c.last_seen,
    r.target_id AS attributed_group_id,
    g.name AS attributed_group_name,
    r.mapping_description AS attribution_notes
FROM campaigns c
LEFT JOIN `relationships` r 
    ON c.campaign_id = r.source_id 
   AND r.mapping_type = 'attributed-to' 
   AND r.target_type = 'group'
LEFT JOIN `groups` g 
    ON r.target_id = g.group_id;

CREATE OR REPLACE VIEW v_technique_connectivity AS
SELECT 
    t.technique_id,
    t.name AS technique_name,
    COUNT(DISTINCT CASE WHEN r.source_type = 'software' THEN r.source_id END) AS associated_software_count,
    COUNT(DISTINCT CASE WHEN r.source_type = 'group' THEN r.source_id END) AS associated_groups_count,
    COUNT(DISTINCT CASE WHEN r.source_type = 'campaign' THEN r.source_id END) AS associated_campaigns_count,
    COUNT(DISTINCT CASE WHEN r.source_type = 'mitigation' THEN r.source_id END) AS associated_mitigations_count,
    COUNT(DISTINCT r.relationship_id) AS total_relationships_count
FROM techniques t
LEFT JOIN `relationships` r ON t.technique_id = r.target_id
GROUP BY t.technique_id, t.name;
