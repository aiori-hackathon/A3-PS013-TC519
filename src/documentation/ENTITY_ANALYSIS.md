# CyberTrace: Cyber Threat Intelligence Platform
## Step 2 – Entity Analysis
**Document**: `ENTITY_ANALYSIS.md`  
**Level**: Second-Year Undergraduate DBMS Project  
**Author**: CyberTrace Project Team  
**Primary Dataset**: MITRE ATT&CK Enterprise Matrix v19.2  

---

## 1. Introduction to Entity Modeling in CyberTrace

In database design, an **entity** is a distinct, identifiable object, event, concept, or relationship in the real-world domain about which information is stored. 

Based on our analysis of the MITRE ATT&CK Enterprise dataset, we distinguish between:
1. **Strong (Kernel) Entities**: Entities that have an independent existence and possess their own natural primary keys (e.g., `tactics`, `techniques`, `software`, `groups`, `campaigns`, `mitigations`, `data_components`, `analytics`, `detection_strategies`, `citations`).
2. **Weak / Dependent Entities**: Entities that depend on the existence of a parent entity (e.g., `group_aliases`).
3. **Associative / Junction Entities**: Entities that model Many-to-Many (M:N) relationships between primary entities, containing foreign keys and relationship-specific descriptive attributes (e.g., `technique_tactics`, `relationships`, `defensive_mappings`).

---

## 2. Comprehensive Entity Catalog

### 2.1 Entity: `tactics` (Adversary Objectives)
- **Purpose**: Represents the high-level phases and tactical goals of an adversary during an intrusion (e.g., Initial Access, Persistence, Privilege Escalation, Command and Control).
- **Source Sheet**: `tactics` (15 rows).
- **Entity Type**: Strong Entity.
- **Attributes**:
  - `tactic_id` (VARCHAR(10)) – Primary Key (e.g., `TA0001` to `TA0043`).
  - `stix_id` (VARCHAR(100)) – Candidate Key (Unique STIX UUID).
  - `name` (VARCHAR(100)) – Tactical phase title (NOT NULL, UNIQUE).
  - `description` (TEXT) – Comprehensive explanation of the adversarial goal.
  - `url` (VARCHAR(255)) – Official MITRE documentation link.
  - `created_date` (VARCHAR(50)) – Creation timestamp.
  - `last_modified_date` (VARCHAR(50)) – Last updated timestamp.
  - `version` (VARCHAR(20)) – Version string.
- **Relationships**:
  - Categorizes Techniques: M:N relationship with `techniques` via associative entity `technique_tactics`.

---

### 2.2 Entity: `techniques` (Adversary Methods)
- **Purpose**: Concrete actions and technical mechanisms employed by adversaries to achieve tactical goals (e.g., Command and Scripting Interpreter, Token Impersonation).
- **Source Sheet**: `techniques` (697 rows).
- **Entity Type**: Strong Entity with Recursive Hierarchy.
- **Attributes**:
  - `technique_id` (VARCHAR(20)) – Primary Key (e.g., `T1059`, `T1059.001`).
  - `stix_id` (VARCHAR(100)) – Candidate Key (Unique STIX UUID).
  - `name` (VARCHAR(200)) – Technique name (NOT NULL).
  - `description` (TEXT) – Detailed technical breakdown of execution.
  - `url` (VARCHAR(255)) – Official ATT&CK URL.
  - `created_date` (VARCHAR(50)) – Creation date.
  - `last_modified_date` (VARCHAR(50)) – Last modification date.
  - `version` (VARCHAR(20)) – Version string.
  - `is_subtechnique` (BOOLEAN / TINYINT(1)) – 1 if sub-technique, 0 if top-level (NOT NULL).
  - `parent_technique_id` (VARCHAR(20)) – Foreign Key referencing `techniques(technique_id)`. NULL for top-level techniques.
  - `supports_remote` (VARCHAR(50)) – Remote execution capability indicator.
  - `impact_type` (VARCHAR(100)) – Impact categorization.
- **Relationships**:
  - Belongs to Tactics: M:N with `tactics` via `technique_tactics`.
  - Recursive Hierarchy: 1:M self-reference (Parent Technique $\to$ Sub-techniques).
  - Target of Software: M:N with `software` via `relationships`.
  - Target of Groups: M:N with `groups` via `relationships`.
  - Target of Campaigns: M:N with `campaigns` via `relationships`.
  - Mitigated by: M:N with `mitigations` via `relationships`.
  - Detected by: M:N with `detection_strategies` via `relationships`.

---

### 2.3 Entity: `technique_tactics` (Technique-Tactic Association)
- **Purpose**: Associative entity establishing the Many-to-Many mapping between techniques and the tactics they serve. Resolves the 1NF violation of multi-valued tactics in `techniques`.
- **Source**: Decomposed from `techniques.tactics` and cross-referenced with `tactics.ID`.
- **Entity Type**: Associative Entity.
- **Attributes**:
  - `technique_id` (VARCHAR(20)) – Foreign Key referencing `techniques(technique_id)`.
  - `tactic_id` (VARCHAR(10)) – Foreign Key referencing `tactics(tactic_id)`.
- **Primary Key**: Composite Key `(technique_id, tactic_id)`.

---

### 2.4 Entity: `software` (Tools & Malware)
- **Purpose**: Commercial utilities, open-source penetration tools, and custom malicious binaries observed in adversary campaigns (e.g., Mimikatz, Cobalt Strike, 3PARA RAT).
- **Source Sheet**: `software` (825 rows).
- **Entity Type**: Strong Entity.
- **Attributes**:
  - `software_id` (VARCHAR(20)) – Primary Key (e.g., `S0001` - `S1185`).
  - `stix_id` (VARCHAR(100)) – Candidate Key (Unique STIX UUID).
  - `name` (VARCHAR(200)) – Software name (NOT NULL).
  - `type` (VARCHAR(20)) – Categorical indicator: `malware` or `tool` (NOT NULL).
  - `description` (TEXT) – Technical summary of software capabilities.
  - `url` (VARCHAR(255)) – Documentation link.
  - `created_date` (VARCHAR(50)) – Creation timestamp.
  - `last_modified_date` (VARCHAR(50)) – Last modified timestamp.
  - `version` (VARCHAR(20)) – Version string.
- **Relationships**:
  - Executes Techniques: M:N with `techniques` via `relationships` (`mapping_type = 'uses'`).
  - Operated by Groups: M:N with `groups` via `relationships`.
  - Leveraged in Campaigns: M:N with `campaigns` via `relationships`.

---

### 2.5 Entity: `groups` (Adversary Threat Groups)
- **Purpose**: Known clusters of adversary activity, nation-state Advanced Persistent Threat (APT) groups, and cybercrime syndicates (e.g., APT28, Sandworm Team, Lazarus Group).
- **Source Sheet**: `groups` (176 rows).
- **Entity Type**: Strong Entity.
- **Attributes**:
  - `group_id` (VARCHAR(20)) – Primary Key (e.g., `G0001` - `G1049`).
  - `stix_id` (VARCHAR(100)) – Candidate Key (Unique STIX UUID).
  - `name` (VARCHAR(200)) – Primary threat actor group name (NOT NULL).
  - `description` (TEXT) – Operational history, known targeting profile, origin.
  - `url` (VARCHAR(255)) – Link to ATT&CK profile.
  - `created_date` (VARCHAR(50)) – Profile creation timestamp.
  - `last_modified_date` (VARCHAR(50)) – Last updated timestamp.
  - `version` (VARCHAR(20)) – Version string.
- **Relationships**:
  - Uses Techniques: M:N with `techniques` via `relationships`.
  - Uses Software: M:N with `software` via `relationships`.
  - Conducts Campaigns: 1:M with `campaigns` via `relationships` (`mapping_type = 'attributed-to'`).
  - Known Aliases: 1:M with `group_aliases`.

---

### 2.6 Entity: `group_aliases` (Threat Actor Synonyms)
- **Purpose**: Dependent entity storing alternate industry naming conventions for threat groups (e.g., APT28 is also known as Fancy Bear, Sofacy, Sednit, STRONTIUM). Resolves 1NF multi-valued cell violation.
- **Source**: Decomposed from `groups.associated groups`.
- **Entity Type**: Weak / Dependent Entity.
- **Attributes**:
  - `alias_id` (INT AUTO_INCREMENT) – Primary Key.
  - `group_id` (VARCHAR(20)) – Foreign Key referencing `groups(group_id)`.
  - `alias_name` (VARCHAR(150)) – Alternate moniker / industry name (NOT NULL).
- **Constraints**: UNIQUE `(group_id, alias_name)`.

---

### 2.7 Entity: `campaigns` (Adversary Operations)
- **Purpose**: Specific clusters of malicious activity with common objectives and defined execution timeframes (e.g., 2015 Ukraine Electric Power Attack, SolarWinds Compromise).
- **Source Sheet**: `campaigns` (56 rows).
- **Entity Type**: Strong Entity.
- **Attributes**:
  - `campaign_id` (VARCHAR(20)) – Primary Key (e.g., `C0001` - `C0057`).
  - `stix_id` (VARCHAR(100)) – Candidate Key (STIX UUID).
  - `name` (VARCHAR(200)) – Campaign title (NOT NULL).
  - `description` (TEXT) – Detailed operational narrative.
  - `first_seen` (VARCHAR(50)) – Approximate start date of malicious campaign (NULL allowed).
  - `last_seen` (VARCHAR(50)) – Approximate conclusion date of campaign (NULL allowed).
  - `url` (VARCHAR(255)) – Documentation URL.
  - `created_date` (VARCHAR(50)) – Timestamp.
  - `last_modified_date` (VARCHAR(50)) – Timestamp.
  - `version` (VARCHAR(20)) – Version string.
- **Relationships**:
  - Attributed to Group: M:1 with `groups` via `relationships`.
  - Uses Techniques: M:N with `techniques` via `relationships`.
  - Deploys Software: M:N with `software` via `relationships`.

---

### 2.8 Entity: `mitigations` (Defensive Controls)
- **Purpose**: Configuration guidelines, administrative controls, and security architectural changes that prevent or limit technique execution (e.g., Multi-factor Authentication, Restrict File and Directory Permissions).
- **Source Sheet**: `mitigations` (44 rows).
- **Entity Type**: Strong Entity.
- **Attributes**:
  - `mitigation_id` (VARCHAR(20)) – Primary Key (e.g., `M1015` - `M1056`).
  - `stix_id` (VARCHAR(100)) – Candidate Key (STIX UUID).
  - `name` (VARCHAR(200)) – Control name (NOT NULL).
  - `description` (TEXT) – Implementation guidelines and defensive theory.
  - `url` (VARCHAR(255)) – URL link.
  - `created_date` (VARCHAR(50)) – Creation timestamp.
  - `last_modified_date` (VARCHAR(50)) – Last updated timestamp.
  - `version` (VARCHAR(20)) – Version string.
- **Relationships**:
  - Mitigates Techniques: M:N with `techniques` via `relationships` (`mapping_type = 'mitigates'`).

---

### 2.9 Entity: `relationships` (Universal Threat Graph Mappings)
- **Purpose**: Associative entity storing the 20,628 threat intelligence relationships connecting software, groups, campaigns, mitigations, and detection strategies to techniques.
- **Source Sheet**: `relationships` (20,628 rows).
- **Entity Type**: Associative Entity.
- **Attributes**:
  - `relationship_id` (INT AUTO_INCREMENT) – Primary Key.
  - `source_id` (VARCHAR(20)) – ID of the initiating entity (NOT NULL).
  - `source_type` (VARCHAR(30)) – Type of source entity (`software`, `group`, `mitigation`, `campaign`, `detectionstrategy`).
  - `mapping_type` (VARCHAR(30)) – Nature of relation (`uses`, `mitigates`, `detects`, `attributed-to`).
  - `target_id` (VARCHAR(20)) – ID of the target entity (NOT NULL).
  - `target_type` (VARCHAR(30)) – Type of target entity (`technique`, `software`, `group`).
  - `mapping_description` (TEXT) – Specific contextual intelligence explaining the mapping.
  - `stix_id` (VARCHAR(100)) – Candidate Key (Unique STIX relationship UUID).
  - `created_date` (VARCHAR(50)) – Creation timestamp.
  - `last_modified_date` (VARCHAR(50)) – Modification timestamp.
- **Constraints**:
  - `UNIQUE (source_id, target_id, mapping_type)` (or uniquely identified by `stix_id`).

---

### 2.10 Entity: `data_components` (Telemetry & Log Sources)
- **Purpose**: Specific pieces of telemetry collected from operating systems, networks, or cloud environments (e.g., Active DNS, Process Creation, Command Execution).
- **Source Sheet**: `datacomponents` (106 rows).
- **Entity Type**: Strong Entity.
- **Attributes**:
  - `data_component_id` (VARCHAR(20)) – Primary Key (e.g., `DC0001` - `DC0103`).
  - `stix_id` (VARCHAR(100)) – Candidate Key (STIX UUID).
  - `name` (VARCHAR(200)) – Data component title (NOT NULL).
  - `description` (TEXT) – Telemetry semantics, event IDs, and collection methods.
  - `url` (VARCHAR(255)) – URL link.
  - `version` (VARCHAR(20)) – Version string.

---

### 2.11 Entity: `analytics` (Detection Logic & Queries)
- **Purpose**: Formal detection queries, rules, and analytical logic designed to uncover specific adversary behaviors.
- **Source Sheet**: `analytics` (1,758 rows).
- **Entity Type**: Strong Entity.
- **Attributes**:
  - `analytic_id` (VARCHAR(20)) – Primary Key (e.g., `AN0001` - `AN1758`).
  - `stix_id` (VARCHAR(100)) – Candidate Key (STIX UUID).
  - `name` (VARCHAR(255)) – Query title (NOT NULL).
  - `description` (TEXT) – Logic implementation details.
  - `url` (VARCHAR(255)) – URL.
  - `version` (VARCHAR(20)) – Version string.

---

### 2.12 Entity: `detection_strategies` (Strategic Detection Blueprints)
- **Purpose**: High-level strategic detection approaches aligning techniques with underlying analytics.
- **Source Sheet**: `detectionstrategies` (697 rows).
- **Entity Type**: Strong Entity.
- **Attributes**:
  - `strategy_id` (VARCHAR(20)) – Primary Key (e.g., `DET0001` - `DET0697`).
  - `stix_id` (VARCHAR(100)) – Candidate Key (STIX UUID).
  - `name` (VARCHAR(255)) – Detection strategy title (NOT NULL).
  - `url` (VARCHAR(255)) – URL.
  - `version` (VARCHAR(20)) – Version string.

---

### 2.13 Entity: `defensive_mappings` (Defensive Engineering Associations)
- **Purpose**: Associative entity linking detection strategies to specific analytics, data components, platforms, and Windows Event Log channels.
- **Source Sheet**: `defensive mappings` (4,160 rows).
- **Entity Type**: Associative Entity.
- **Attributes**:
  - `mapping_id` (INT AUTO_INCREMENT) – Primary Key.
  - `strategy_id` (VARCHAR(20)) – Foreign Key referencing `detection_strategies(strategy_id)`.
  - `analytic_id` (VARCHAR(100)) – Foreign Key referencing `analytics(stix_id)` or analytic identifier.
  - `data_component_id` (VARCHAR(20)) – Foreign Key referencing `data_components(data_component_id)`.
  - `platform` (VARCHAR(100)) – Operating system platform (e.g., `Windows`, `Linux`).
  - `log_source_name` (VARCHAR(150)) – Log provider (e.g., `WinEventLog:Security`).
  - `channel` (VARCHAR(150)) – Specific Event IDs / Channels.

---

### 2.14 Entity: `citations` (Bibliographic References)
- **Purpose**: Authoritative reference catalog providing source verification, research reports, and court indictments for all MITRE claims.
- **Source Sheet**: `citations` (4,305 rows).
- **Entity Type**: Supporting Reference Entity.
- **Attributes**:
  - `citation_id` (INT AUTO_INCREMENT) – Primary Key.
  - `reference_tag` (VARCHAR(150)) – Citation tag (e.g., `(Citation: Mandiant APT1)`) (NOT NULL).
  - `citation_text` (TEXT) – Full bibliographic citation, publication date, authors.
  - `url` (VARCHAR(500)) – Direct external URL link (NULL allowed).

---

## 3. Summary of Entities

| Entity Name | Classification | Primary Key | Key Foreign Keys | Total Raw Records |
|---|---|---|---|---|
| `tactics` | Strong | `tactic_id` | *None* | 15 |
| `techniques` | Strong / Recursive | `technique_id` | `parent_technique_id` | 697 |
| `technique_tactics` | Associative | `(technique_id, tactic_id)` | `technique_id`, `tactic_id` | Decomposed (1NF) |
| `software` | Strong | `software_id` | *None* | 825 |
| `groups` | Strong | `group_id` | *None* | 176 |
| `group_aliases` | Weak / Dependent | `alias_id` | `group_id` | Decomposed (1NF) |
| `campaigns` | Strong | `campaign_id` | *None* | 56 |
| `mitigations` | Strong | `mitigation_id` | *None* | 44 |
| `relationships` | Associative | `relationship_id` | `source_id`, `target_id` | 20,628 |
| `data_components` | Strong | `data_component_id` | *None* | 106 |
| `analytics` | Strong | `analytic_id` | *None* | 1,758 |
| `detection_strategies` | Strong | `strategy_id` | *None* | 697 |
| `defensive_mappings` | Associative | `mapping_id` | `strategy_id`, `data_component_id` | 4,160 |
| `citations` | Reference | `citation_id` | *None* | 4,305 |

All entities have been derived directly from the provided workbook without fabricating concepts or relationships.
