# CyberTrace: Cyber Threat Intelligence Platform
## Step 6 – Final Relational Schema
**Document**: `RELATIONAL_SCHEMA.md`  
**Level**: Second-Year Undergraduate DBMS Project  
**Author**: CyberTrace Project Team  
**Target RDBMS**: MySQL Server 8.0  

---

## 1. Schema Overview

The CyberTrace relational database schema is the final, normalized design derived from the MITRE ATT&CK Enterprise dataset. It encompasses:
1. **Primary Entity Tables**: `tactics`, `techniques`, `software`, `groups`, `campaigns`, `mitigations`, `data_components`, `analytics`, `detection_strategies`, `citations`.
2. **Associative / Junction Tables**: `technique_tactics`, `relationships`, `defensive_mappings`.
3. **Dependent Entity Tables**: `group_aliases`.

All tables are in Boyce-Codd Normal Form (BCNF), enforce entity and referential integrity constraints, and optimize query performance through targeted indexing.

---

## 2. Formal Relational Notation

- $\text{tactics}(\underline{\text{tactic\_id}}, \text{stix\_id}, \text{name}, \text{description}, \text{url}, \text{created\_date}, \text{last\_modified\_date}, \text{version})$
- $\text{techniques}(\underline{\text{technique\_id}}, \text{stix\_id}, \text{name}, \text{description}, \text{url}, \text{created\_date}, \text{last\_modified\_date}, \text{version}, \text{is\_subtechnique}, \text{parent\_technique\_id}^*, \text{supports\_remote}, \text{impact\_type})$
- $\text{technique\_tactics}(\underline{\text{technique\_id}}^*, \underline{\text{tactic\_id}}^*)$
- $\text{software}(\underline{\text{software\_id}}, \text{stix\_id}, \text{name}, \text{type}, \text{description}, \text{url}, \text{created\_date}, \text{last\_modified\_date}, \text{version})$
- $\text{groups}(\underline{\text{group\_id}}, \text{stix\_id}, \text{name}, \text{description}, \text{url}, \text{created\_date}, \text{last\_modified\_date}, \text{version})$
- $\text{group\_aliases}(\underline{\text{alias\_id}}, \text{group\_id}^*, \text{alias\_name})$
- $\text{campaigns}(\underline{\text{campaign\_id}}, \text{stix\_id}, \text{name}, \text{description}, \text{first\_seen}, \text{last\_seen}, \text{url}, \text{created\_date}, \text{last\_modified\_date}, \text{version})$
- $\text{mitigations}(\underline{\text{mitigation\_id}}, \text{stix\_id}, \text{name}, \text{description}, \text{url}, \text{created\_date}, \text{last\_modified\_date}, \text{version})$
- $\text{data\_components}(\underline{\text{data\_component\_id}}, \text{stix\_id}, \text{name}, \text{description}, \text{url}, \text{version})$
- $\text{analytics}(\underline{\text{analytic\_id}}, \text{stix\_id}, \text{name}, \text{description}, \text{url}, \text{version})$
- $\text{detection\_strategies}(\underline{\text{strategy\_id}}, \text{stix\_id}, \text{name}, \text{url}, \text{version})$
- $\text{relationships}(\underline{\text{relationship\_id}}, \text{source\_id}, \text{source\_type}, \text{mapping\_type}, \text{target\_id}, \text{target\_type}, \text{mapping\_description}, \text{stix\_id}, \text{created\_date}, \text{last\_modified\_date})$
- $\text{defensive\_mappings}(\underline{\text{mapping\_id}}, \text{strategy\_id}^*, \text{analytic\_id}, \text{data\_component\_id}^*, \text{platform}, \text{log\_source\_name}, \text{channel})$
- $\text{citations}(\underline{\text{citation\_id}}, \text{reference\_tag}, \text{citation\_text}, \text{url})$

*(Underlined attributes denote Primary Keys; asterisks $^*$ denote Foreign Keys).*

---

## 3. Comprehensive Table DDL Specifications

### 3.1 Table: `tactics`
- **Purpose**: High-level adversarial objectives across the attack lifecycle.
- **Columns**:
  - `tactic_id` VARCHAR(10) NOT NULL PRIMARY KEY
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `name` VARCHAR(100) NOT NULL UNIQUE
  - `description` TEXT NULL
  - `url` VARCHAR(255) NULL
  - `created_date` VARCHAR(50) NULL
  - `last_modified_date` VARCHAR(50) NULL
  - `version` VARCHAR(20) NULL

---

### 3.2 Table: `techniques`
- **Purpose**: Specific technical actions taken by adversaries.
- **Columns**:
  - `technique_id` VARCHAR(20) NOT NULL PRIMARY KEY
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `name` VARCHAR(200) NOT NULL
  - `description` MEDIUMTEXT NULL
  - `url` VARCHAR(255) NULL
  - `created_date` VARCHAR(50) NULL
  - `last_modified_date` VARCHAR(50) NULL
  - `version` VARCHAR(20) NULL
  - `is_subtechnique` TINYINT(1) NOT NULL DEFAULT 0
  - `parent_technique_id` VARCHAR(20) NULL
  - `supports_remote` VARCHAR(50) NULL
  - `impact_type` VARCHAR(100) NULL
- **Foreign Keys**:
  - `parent_technique_id` REFERENCES `techniques(technique_id)` ON DELETE RESTRICT ON UPDATE CASCADE

---

### 3.3 Table: `technique_tactics`
- **Purpose**: Many-to-Many association mapping techniques to tactics.
- **Columns**:
  - `technique_id` VARCHAR(20) NOT NULL
  - `tactic_id` VARCHAR(10) NOT NULL
- **Primary Key**: `(technique_id, tactic_id)`
- **Foreign Keys**:
  - `technique_id` REFERENCES `techniques(technique_id)` ON DELETE CASCADE ON UPDATE CASCADE
  - `tactic_id` REFERENCES `tactics(tactic_id)` ON DELETE RESTRICT ON UPDATE CASCADE

---

### 3.4 Table: `software`
- **Purpose**: Malware families and tools leveraged by adversaries.
- **Columns**:
  - `software_id` VARCHAR(20) NOT NULL PRIMARY KEY
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `name` VARCHAR(200) NOT NULL
  - `type` VARCHAR(20) NOT NULL
  - `description` MEDIUMTEXT NULL
  - `url` VARCHAR(255) NULL
  - `created_date` VARCHAR(50) NULL
  - `last_modified_date` VARCHAR(50) NULL
  - `version` VARCHAR(20) NULL
- **Constraints**:
  - `CHECK (type IN ('malware', 'tool'))`

---

### 3.5 Table: `groups`
- **Purpose**: Adversary threat actor groups and APT intrusion sets.
- **Columns**:
  - `group_id` VARCHAR(20) NOT NULL PRIMARY KEY
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `name` VARCHAR(200) NOT NULL
  - `description` MEDIUMTEXT NULL
  - `url` VARCHAR(255) NULL
  - `created_date` VARCHAR(50) NULL
  - `last_modified_date` VARCHAR(50) NULL
  - `version` VARCHAR(20) NULL

---

### 3.6 Table: `group_aliases`
- **Purpose**: Dependent entity storing alternate industry names for threat groups.
- **Columns**:
  - `alias_id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY
  - `group_id` VARCHAR(20) NOT NULL
  - `alias_name` VARCHAR(150) NOT NULL
- **Foreign Keys**:
  - `group_id` REFERENCES `groups(group_id)` ON DELETE CASCADE ON UPDATE CASCADE
- **Constraints**:
  - `UNIQUE (group_id, alias_name)`

---

### 3.7 Table: `campaigns`
- **Purpose**: Specific clusters of malicious activity with defined start/end dates.
- **Columns**:
  - `campaign_id` VARCHAR(20) NOT NULL PRIMARY KEY
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `name` VARCHAR(200) NOT NULL
  - `description` MEDIUMTEXT NULL
  - `first_seen` VARCHAR(50) NULL
  - `last_seen` VARCHAR(50) NULL
  - `url` VARCHAR(255) NULL
  - `created_date` VARCHAR(50) NULL
  - `last_modified_date` VARCHAR(50) NULL
  - `version` VARCHAR(20) NULL

---

### 3.8 Table: `mitigations`
- **Purpose**: Defensive controls and architectural security hardening measures.
- **Columns**:
  - `mitigation_id` VARCHAR(20) NOT NULL PRIMARY KEY
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `name` VARCHAR(200) NOT NULL
  - `description` MEDIUMTEXT NULL
  - `url` VARCHAR(255) NULL
  - `created_date` VARCHAR(50) NULL
  - `last_modified_date` VARCHAR(50) NULL
  - `version` VARCHAR(20) NULL

---

### 3.9 Table: `data_components`
- **Purpose**: Operating system and network telemetry logging sources.
- **Columns**:
  - `data_component_id` VARCHAR(20) NOT NULL PRIMARY KEY
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `name` VARCHAR(200) NOT NULL
  - `description` MEDIUMTEXT NULL
  - `url` VARCHAR(255) NULL
  - `version` VARCHAR(20) NULL

---

### 3.10 Table: `analytics`
- **Purpose**: Formal detection queries and behavioral detection rules.
- **Columns**:
  - `analytic_id` VARCHAR(20) NOT NULL PRIMARY KEY
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `name` VARCHAR(255) NOT NULL
  - `description` MEDIUMTEXT NULL
  - `url` VARCHAR(255) NULL
  - `version` VARCHAR(20) NULL

---

### 3.11 Table: `detection_strategies`
- **Purpose**: Strategic blueprints that correlate techniques to telemetry.
- **Columns**:
  - `strategy_id` VARCHAR(20) NOT NULL PRIMARY KEY
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `name` VARCHAR(255) NOT NULL
  - `url` VARCHAR(255) NULL
  - `version` VARCHAR(20) NULL

---

### 3.12 Table: `relationships`
- **Purpose**: Universal M:N threat intelligence mapping catalog (20,628 edges).
- **Columns**:
  - `relationship_id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY
  - `source_id` VARCHAR(20) NOT NULL
  - `source_type` VARCHAR(30) NOT NULL
  - `mapping_type` VARCHAR(30) NOT NULL
  - `target_id` VARCHAR(20) NOT NULL
  - `target_type` VARCHAR(30) NOT NULL
  - `mapping_description` MEDIUMTEXT NULL
  - `stix_id` VARCHAR(100) NOT NULL UNIQUE
  - `created_date` VARCHAR(50) NULL
  - `last_modified_date` VARCHAR(50) NULL

---

### 3.13 Table: `defensive_mappings`
- **Purpose**: Associative mapping linking detection strategies, analytics, and data components.
- **Columns**:
  - `mapping_id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY
  - `strategy_id` VARCHAR(20) NOT NULL
  - `analytic_id` VARCHAR(100) NULL
  - `data_component_id` VARCHAR(20) NULL
  - `platform` VARCHAR(100) NULL
  - `log_source_name` VARCHAR(150) NULL
  - `channel` VARCHAR(150) NULL
- **Foreign Keys**:
  - `strategy_id` REFERENCES `detection_strategies(strategy_id)` ON DELETE CASCADE ON UPDATE CASCADE
  - `data_component_id` REFERENCES `data_components(data_component_id)` ON DELETE SET NULL ON UPDATE CASCADE

---

### 3.14 Table: `citations`
- **Purpose**: Bibliographic citations and evidence links.
- **Columns**:
  - `citation_id` INT AUTO_INCREMENT NOT NULL PRIMARY KEY
  - `reference_tag` VARCHAR(150) NOT NULL UNIQUE
  - `citation_text` MEDIUMTEXT NULL
  - `url` VARCHAR(500) NULL

---

## 4. Referential Action Justification

- `ON DELETE CASCADE`:
  - Used in associative junction tables (`technique_tactics`, `group_aliases`, `defensive_mappings`) where a child mapping has no semantic meaning if the parent entity is removed.
- `ON DELETE RESTRICT`:
  - Used on primary entity foreign keys (such as `parent_technique_id` in `techniques` and `tactic_id` in `technique_tactics`) to prevent accidental deletion of a tactic or parent technique that still has dependent sub-techniques or techniques.
- `ON UPDATE CASCADE`:
  - Enforced across all foreign keys to ensure that any legitimate update to an identifier cascades automatically without violating referential integrity.
