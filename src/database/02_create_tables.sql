
USE cybertrace;

CREATE TABLE IF NOT EXISTS tactics (
    tactic_id VARCHAR(20) NOT NULL,
    stix_id VARCHAR(100) NOT NULL,
    name VARCHAR(100) NOT NULL,
    description TEXT NULL,
    url VARCHAR(255) NULL,
    created_date VARCHAR(50) NULL,
    last_modified_date VARCHAR(50) NULL,
    version VARCHAR(20) NULL,
    CONSTRAINT pk_tactics PRIMARY KEY (tactic_id),
    CONSTRAINT uk_tactics_stix_id UNIQUE (stix_id),
    CONSTRAINT uk_tactics_name UNIQUE (name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS techniques (
    technique_id VARCHAR(20) NOT NULL,
    stix_id VARCHAR(100) NOT NULL,
    name VARCHAR(200) NOT NULL,
    description MEDIUMTEXT NULL,
    url VARCHAR(255) NULL,
    created_date VARCHAR(50) NULL,
    last_modified_date VARCHAR(50) NULL,
    version VARCHAR(20) NULL,
    is_subtechnique TINYINT(1) NOT NULL DEFAULT 0,
    parent_technique_id VARCHAR(20) NULL,
    supports_remote VARCHAR(50) NULL,
    impact_type VARCHAR(100) NULL,
    CONSTRAINT pk_techniques PRIMARY KEY (technique_id),
    CONSTRAINT uk_techniques_stix_id UNIQUE (stix_id),
    CONSTRAINT fk_techniques_parent FOREIGN KEY (parent_technique_id)
        REFERENCES techniques (technique_id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS technique_tactics (
    technique_id VARCHAR(20) NOT NULL,
    tactic_id VARCHAR(20) NOT NULL,
    CONSTRAINT pk_technique_tactics PRIMARY KEY (technique_id, tactic_id),
    CONSTRAINT fk_tt_technique FOREIGN KEY (technique_id)
        REFERENCES techniques (technique_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    CONSTRAINT fk_tt_tactic FOREIGN KEY (tactic_id)
        REFERENCES tactics (tactic_id)
        ON DELETE RESTRICT
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS software (
    software_id VARCHAR(20) NOT NULL,
    stix_id VARCHAR(100) NOT NULL,
    name VARCHAR(200) NOT NULL,
    type VARCHAR(20) NOT NULL,
    description MEDIUMTEXT NULL,
    url VARCHAR(255) NULL,
    created_date VARCHAR(50) NULL,
    last_modified_date VARCHAR(50) NULL,
    version VARCHAR(20) NULL,
    CONSTRAINT pk_software PRIMARY KEY (software_id),
    CONSTRAINT uk_software_stix_id UNIQUE (stix_id),
    CONSTRAINT chk_software_type CHECK (type IN ('malware', 'tool'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS `groups` (
    group_id VARCHAR(20) NOT NULL,
    stix_id VARCHAR(100) NOT NULL,
    name VARCHAR(200) NOT NULL,
    description MEDIUMTEXT NULL,
    url VARCHAR(255) NULL,
    created_date VARCHAR(50) NULL,
    last_modified_date VARCHAR(50) NULL,
    version VARCHAR(20) NULL,
    CONSTRAINT pk_groups PRIMARY KEY (group_id),
    CONSTRAINT uk_groups_stix_id UNIQUE (stix_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS group_aliases (
    alias_id INT AUTO_INCREMENT NOT NULL,
    group_id VARCHAR(20) NOT NULL,
    alias_name VARCHAR(150) NOT NULL,
    CONSTRAINT pk_group_aliases PRIMARY KEY (alias_id),
    CONSTRAINT uk_group_alias UNIQUE (group_id, alias_name),
    CONSTRAINT fk_group_aliases_group FOREIGN KEY (group_id)
        REFERENCES `groups` (group_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS campaigns (
    campaign_id VARCHAR(20) NOT NULL,
    stix_id VARCHAR(100) NOT NULL,
    name VARCHAR(200) NOT NULL,
    description MEDIUMTEXT NULL,
    first_seen VARCHAR(50) NULL,
    last_seen VARCHAR(50) NULL,
    url VARCHAR(255) NULL,
    created_date VARCHAR(50) NULL,
    last_modified_date VARCHAR(50) NULL,
    version VARCHAR(20) NULL,
    CONSTRAINT pk_campaigns PRIMARY KEY (campaign_id),
    CONSTRAINT uk_campaigns_stix_id UNIQUE (stix_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS mitigations (
    mitigation_id VARCHAR(20) NOT NULL,
    stix_id VARCHAR(100) NOT NULL,
    name VARCHAR(200) NOT NULL,
    description MEDIUMTEXT NULL,
    url VARCHAR(255) NULL,
    created_date VARCHAR(50) NULL,
    last_modified_date VARCHAR(50) NULL,
    version VARCHAR(20) NULL,
    CONSTRAINT pk_mitigations PRIMARY KEY (mitigation_id),
    CONSTRAINT uk_mitigations_stix_id UNIQUE (stix_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS data_components (
    data_component_id VARCHAR(20) NOT NULL,
    stix_id VARCHAR(100) NOT NULL,
    name VARCHAR(200) NOT NULL,
    description MEDIUMTEXT NULL,
    url VARCHAR(255) NULL,
    version VARCHAR(20) NULL,
    CONSTRAINT pk_data_components PRIMARY KEY (data_component_id),
    CONSTRAINT uk_data_components_stix_id UNIQUE (stix_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS analytics (
    analytic_id VARCHAR(20) NOT NULL,
    stix_id VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description MEDIUMTEXT NULL,
    url VARCHAR(255) NULL,
    version VARCHAR(20) NULL,
    CONSTRAINT pk_analytics PRIMARY KEY (analytic_id),
    CONSTRAINT uk_analytics_stix_id UNIQUE (stix_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS detection_strategies (
    strategy_id VARCHAR(20) NOT NULL,
    stix_id VARCHAR(100) NOT NULL,
    name VARCHAR(255) NOT NULL,
    url VARCHAR(255) NULL,
    version VARCHAR(20) NULL,
    CONSTRAINT pk_detection_strategies PRIMARY KEY (strategy_id),
    CONSTRAINT uk_detection_strategies_stix_id UNIQUE (stix_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS `relationships` (
    relationship_id INT AUTO_INCREMENT NOT NULL,
    source_id VARCHAR(20) NOT NULL,
    source_type VARCHAR(30) NOT NULL,
    mapping_type VARCHAR(30) NOT NULL,
    target_id VARCHAR(20) NOT NULL,
    target_type VARCHAR(30) NOT NULL,
    mapping_description MEDIUMTEXT NULL,
    stix_id VARCHAR(100) NOT NULL,
    created_date VARCHAR(50) NULL,
    last_modified_date VARCHAR(50) NULL,
    CONSTRAINT pk_relationships PRIMARY KEY (relationship_id),
    CONSTRAINT uk_relationships_stix_id UNIQUE (stix_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS defensive_mappings (
    mapping_id INT AUTO_INCREMENT NOT NULL,
    strategy_id VARCHAR(20) NOT NULL,
    analytic_id VARCHAR(100) NULL,
    data_component_id VARCHAR(20) NULL,
    platform VARCHAR(100) NULL,
    log_source_name VARCHAR(150) NULL,
    channel VARCHAR(150) NULL,
    CONSTRAINT pk_defensive_mappings PRIMARY KEY (mapping_id),
    CONSTRAINT fk_dm_strategy FOREIGN KEY (strategy_id)
        REFERENCES detection_strategies (strategy_id)
        ON DELETE CASCADE
        ON UPDATE CASCADE,
    CONSTRAINT fk_dm_data_component FOREIGN KEY (data_component_id)
        REFERENCES data_components (data_component_id)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS citations (
    citation_id INT AUTO_INCREMENT NOT NULL,
    reference_tag VARCHAR(150) NOT NULL,
    citation_text MEDIUMTEXT NULL,
    url VARCHAR(500) NULL,
    CONSTRAINT pk_citations PRIMARY KEY (citation_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS technique_audit_log (
    audit_id INT AUTO_INCREMENT NOT NULL,
    technique_id VARCHAR(20) NOT NULL,
    action_type VARCHAR(10) NOT NULL,
    old_name VARCHAR(200) NULL,
    new_name VARCHAR(200) NULL,
    changed_by VARCHAR(50) NOT NULL DEFAULT 'SYSTEM_USER',
    changed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_technique_audit_log PRIMARY KEY (audit_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
