# CyberTrace: Entity-Relationship (ER) Diagram
## Level: Second-Year Undergraduate DBMS Project
**Directory**: `/diagrams/`  
**Tool**: Mermaid ER Specification + MySQL Workbench EER Model Instructions  

---

## 1. Visual Conceptual ER Diagram (Crow's Foot Notation)

```mermaid
erDiagram
    TACTICS ||--o{ TECHNIQUE_TACTICS : "categorizes (1:N)"
    TECHNIQUES ||--o{ TECHNIQUE_TACTICS : "implements (1:N)"
    
    TECHNIQUES ||--o{ TECHNIQUES : "has sub-technique (1:N recursive)"

    GROUPS ||--o{ GROUP_ALIASES : "known as (1:N)"

    SOFTWARE ||--o{ RELATIONSHIPS : "source (1:N)"
    GROUPS ||--o{ RELATIONSHIPS : "source (1:N)"
    CAMPAIGNS ||--o{ RELATIONSHIPS : "source (1:N)"
    MITIGATIONS ||--o{ RELATIONSHIPS : "source (1:N)"
    DETECTION_STRATEGIES ||--o{ RELATIONSHIPS : "source (1:N)"

    RELATIONSHIPS }o--|| TECHNIQUES : "targets technique (N:1)"
    RELATIONSHIPS }o--|| SOFTWARE : "targets software (N:1)"
    RELATIONSHIPS }o--|| GROUPS : "targets group (N:1)"

    DETECTION_STRATEGIES ||--o{ DEFENSIVE_MAPPINGS : "defines (1:N)"
    DATA_COMPONENTS ||--o{ DEFENSIVE_MAPPINGS : "provides telemetry (1:N)"

    TACTICS {
        VARCHAR tactic_id PK "TA0001 - TA0043"
        VARCHAR stix_id UK "STIX UUID"
        VARCHAR name UK "Initial Access, Execution..."
        TEXT description "Tactical purpose"
    }

    TECHNIQUES {
        VARCHAR technique_id PK "T1059, T1059.001..."
        VARCHAR stix_id UK "STIX UUID"
        VARCHAR name "Command and Scripting Interpreter"
        BOOLEAN is_subtechnique "1 if sub-technique"
        VARCHAR parent_technique_id FK "Recursive self-reference"
        TEXT description "Technical execution"
    }

    TECHNIQUE_TACTICS {
        VARCHAR technique_id PK,FK "References techniques"
        VARCHAR tactic_id PK,FK "References tactics"
    }

    SOFTWARE {
        VARCHAR software_id PK "S0001 - S1185"
        VARCHAR stix_id UK "STIX UUID"
        VARCHAR name "Mimikatz, Cobalt Strike..."
        VARCHAR type "malware or tool"
    }

    GROUPS {
        VARCHAR group_id PK "G0001 - G1049"
        VARCHAR stix_id UK "STIX UUID"
        VARCHAR name "APT28, Lazarus Group..."
    }

    GROUP_ALIASES {
        INT alias_id PK "Auto-increment"
        VARCHAR group_id FK "References groups"
        VARCHAR alias_name "Fancy Bear, STRONTIUM..."
    }

    CAMPAIGNS {
        VARCHAR campaign_id PK "C0001 - C0057"
        VARCHAR stix_id UK "STIX UUID"
        VARCHAR name "2015 Ukraine Attack..."
        VARCHAR first_seen "Start date"
        VARCHAR last_seen "End date"
    }

    MITIGATIONS {
        VARCHAR mitigation_id PK "M1015 - M1056"
        VARCHAR stix_id UK "STIX UUID"
        VARCHAR name "Account Use Policies..."
    }

    DATA_COMPONENTS {
        VARCHAR data_component_id PK "DC0001 - DC0103"
        VARCHAR name "Active DNS, Process Creation..."
    }

    DETECTION_STRATEGIES {
        VARCHAR strategy_id PK "DET0001 - DET0697"
        VARCHAR name "Detection title"
    }

    RELATIONSHIPS {
        INT relationship_id PK "Auto-increment"
        VARCHAR source_id "Sxxxx, Gxxxx, Cxxxx, Mxxxx, DETxxxx"
        VARCHAR source_type "software, group, campaign..."
        VARCHAR mapping_type "uses, mitigates, detects, attributed-to"
        VARCHAR target_id "Txxxx, Sxxxx, Gxxxx"
        VARCHAR target_type "technique, software, group"
        TEXT mapping_description "Contextual narrative"
    }

    DEFENSIVE_MAPPINGS {
        INT mapping_id PK "Auto-increment"
        VARCHAR strategy_id FK "References detection_strategies"
        VARCHAR data_component_id FK "References data_components"
        VARCHAR log_source_name "WinEventLog:Security"
        VARCHAR channel "EventCode=4624"
    }

    CITATIONS {
        INT citation_id PK "Auto-increment"
        VARCHAR reference_tag UK "Citation tag"
        TEXT citation_text "Full bibliographic reference"
    }
```

---

## 2. Cardinality & Relationship Explanations

1. **`tactics` to `technique_tactics` to `techniques` ($M:N$)**:
   - One tactic associates with many techniques ($1:N$).
   - One technique belongs to one or more tactics ($1:N$).
   - Resolved using composite associative entity `technique_tactics`.
2. **`techniques` to `techniques` ($1:M$ Recursive)**:
   - A top-level technique has zero, one, or many sub-techniques.
   - A sub-technique has exactly one parent technique (`parent_technique_id`).
3. **`groups` to `group_aliases` ($1:M$)**:
   - One threat group has zero, one, or multiple alias names.
   - Each alias belongs to exactly one threat group.
4. **Universal M:N Associative Graph via `relationships`**:
   - Captures the 20,628 threat intelligence edges connecting Software, Groups, Campaigns, Mitigations, and Detection Strategies to Techniques without creating 8 separate redundant tables.

---

## 3. How to Open and View in MySQL Workbench

To generate the visual EER diagram in MySQL Workbench:
1. Open **MySQL Workbench**.
2. Connect to the local MySQL instance (`localhost:3306`).
3. Execute the database creation and table creation scripts (`01_create_database.sql` and `02_create_tables.sql`).
4. In the MySQL Workbench top menu, navigate to:  
   `Database` $\longrightarrow$ `Reverse Engineer...`
5. Select the `cybertrace` database.
6. Click **Next** through the wizard steps and click **Finish**.
7. MySQL Workbench will automatically lay out the visual EER Diagram displaying all tables, primary keys, foreign key connectors, and cardinalities!
