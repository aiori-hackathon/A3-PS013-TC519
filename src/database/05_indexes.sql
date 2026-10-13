

USE cybertrace;

CREATE INDEX idx_techniques_parent 
    ON techniques (parent_technique_id);

CREATE INDEX idx_techniques_name 
    ON techniques (name);

CREATE INDEX idx_techniques_is_sub 
    ON techniques (is_subtechnique);

CREATE INDEX idx_tactics_name 
    ON tactics (name);


CREATE INDEX idx_tt_tactic 
    ON technique_tactics (tactic_id);


CREATE INDEX idx_software_name 
    ON software (name);

CREATE INDEX idx_software_type 
    ON software (type);

CREATE INDEX idx_groups_name 
    ON `groups` (name);

CREATE INDEX idx_aliases_group_id 
    ON group_aliases (group_id);

CREATE INDEX idx_aliases_name 
    ON group_aliases (alias_name);

CREATE INDEX idx_campaigns_name 
    ON campaigns (name);

CREATE INDEX idx_campaigns_first_seen 
    ON campaigns (first_seen);

-- ----------------------------------------------------------------------------
-- 7. UNIVERSAL RELATIONSHIPS INDEXES (HIGH-IMPACT OPTIMIZATION)
-- Purpose: Accelerate threat graph traversals across 20,628 mapping edges

CREATE INDEX idx_rel_source_mapping 
    ON `relationships` (source_id, mapping_type);

CREATE INDEX idx_rel_target_mapping 
    ON `relationships` (target_id, mapping_type);

CREATE INDEX idx_rel_types 
    ON `relationships` (source_type, mapping_type, target_type);


CREATE INDEX idx_dm_strategy 
    ON defensive_mappings (strategy_id);

CREATE INDEX idx_dm_data_component 
    ON defensive_mappings (data_component_id);
