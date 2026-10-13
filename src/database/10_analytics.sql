

USE cybertrace;
SELECT 
    (SELECT COUNT(*) FROM tactics) AS total_tactics,
    (SELECT COUNT(*) FROM techniques) AS total_techniques,
    (SELECT COUNT(*) FROM techniques WHERE is_subtechnique = 0) AS core_techniques,
    (SELECT COUNT(*) FROM techniques WHERE is_subtechnique = 1) AS sub_techniques,
    (SELECT COUNT(*) FROM software) AS total_software,
    (SELECT COUNT(*) FROM software WHERE type = 'malware') AS total_malware,
    (SELECT COUNT(*) FROM software WHERE type = 'tool') AS total_tools,
    (SELECT COUNT(*) FROM `groups`) AS total_threat_groups,
    (SELECT COUNT(*) FROM campaigns) AS total_campaigns,
    (SELECT COUNT(*) FROM mitigations) AS total_mitigations,
    (SELECT COUNT(*) FROM data_components) AS total_data_components,
    (SELECT COUNT(*) FROM `relationships`) AS total_threat_graph_relationships;

SELECT 
    tac.tactic_id,
    tac.name AS tactical_phase,
    COUNT(tt.technique_id) AS technique_count,
    ROUND(COUNT(tt.technique_id) * 100.0 / (SELECT COUNT(*) FROM technique_tactics), 2) AS percentage_of_matrix,
    COUNT(DISTINCT t.parent_technique_id) AS parent_clusters
FROM tactics tac
INNER JOIN technique_tactics tt ON tac.tactic_id = tt.tactic_id
INNER JOIN techniques t ON tt.technique_id = t.technique_id
GROUP BY tac.tactic_id, tac.name
ORDER BY technique_count DESC;
SELECT 
    t.technique_id,
    t.name AS technique_name,
    COUNT(DISTINCT r.source_id) AS distinct_software_using_count,
    SUM(CASE WHEN s.type = 'malware' THEN 1 ELSE 0 END) AS malware_count,
    SUM(CASE WHEN s.type = 'tool' THEN 1 ELSE 0 END) AS tool_count
FROM techniques t
INNER JOIN `relationships` r 
    ON t.technique_id = r.target_id 
   AND r.source_type = 'software' 
   AND r.mapping_type = 'uses'
INNER JOIN software s 
    ON r.source_id = s.software_id
GROUP BY t.technique_id, t.name
ORDER BY distinct_software_using_count DESC
LIMIT 10;
SELECT 
    g.group_id,
    g.name AS threat_group,
    COUNT(DISTINCT r_tech.target_id) AS distinct_techniques_employed,
    COUNT(DISTINCT r_soft.target_id) AS distinct_software_operated,
    (SELECT COUNT(*) FROM campaigns c 
     INNER JOIN `relationships` r_camp ON c.campaign_id = r_camp.source_id 
     WHERE r_camp.target_id = g.group_id AND r_camp.mapping_type = 'attributed-to') AS attributed_campaigns_count
FROM `groups` g
LEFT JOIN `relationships` r_tech 
    ON g.group_id = r_tech.source_id 
   AND r_tech.mapping_type = 'uses' 
   AND r_tech.target_type = 'technique'
LEFT JOIN `relationships` r_soft 
    ON g.group_id = r_soft.source_id 
   AND r_soft.mapping_type = 'uses' 
   AND r_soft.target_type = 'software'
GROUP BY g.group_id, g.name
ORDER BY distinct_techniques_employed DESC
LIMIT 10;
SELECT 
    t.technique_id,
    t.name AS technique_name,
    COUNT(DISTINCT CASE WHEN r.source_type = 'group' THEN r.source_id END) AS group_usage_count,
    COUNT(DISTINCT CASE WHEN r.source_type = 'software' THEN r.source_id END) AS software_usage_count,
    COUNT(DISTINCT CASE WHEN r.source_type = 'mitigation' THEN r.source_id END) AS available_mitigations_count
FROM techniques t
LEFT JOIN `relationships` r ON t.technique_id = r.target_id
GROUP BY t.technique_id, t.name
HAVING available_mitigations_count = 0 
   AND (group_usage_count > 0 OR software_usage_count > 0)
ORDER BY (group_usage_count + software_usage_count) DESC
LIMIT 10;

-- SELECT 
    s.software_id,
    s.name AS tool_name,
    COUNT(DISTINCT r_group.source_id) AS adversary_groups_operating,
    COUNT(DISTINCT r_tech.target_id) AS techniques_facilitated
FROM software s
INNER JOIN `relationships` r_group 
    ON s.software_id = r_group.target_id 
   AND r_group.source_type = 'group' 
   AND r_group.mapping_type = 'uses'
LEFT JOIN `relationships` r_tech 
    ON s.software_id = r_tech.source_id 
   AND r_tech.mapping_type = 'uses' 
   AND r_tech.target_type = 'technique'
WHERE s.type = 'tool'
GROUP BY s.software_id, s.name
ORDER BY adversary_groups_operating DESC
LIMIT 10;

SELECT 
    c.campaign_id,
    c.name AS campaign_name,
    COALESCE(c.first_seen, 'Unknown') AS start_timeline,
    COALESCE(c.last_seen, 'Ongoing / Unspecified') AS end_timeline,
    COUNT(DISTINCT r.target_id) AS techniques_utilized_in_campaign
FROM campaigns c
LEFT JOIN `relationships` r 
    ON c.campaign_id = r.source_id 
   AND r.mapping_type = 'uses' 
   AND r.target_type = 'technique'
GROUP BY c.campaign_id, c.name, c.first_seen, c.last_seen
ORDER BY techniques_utilized_in_campaign DESC
LIMIT 10;
