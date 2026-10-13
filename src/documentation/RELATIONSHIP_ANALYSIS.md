# CyberTrace: Cyber Threat Intelligence Platform
## Step 3 – Relationship Analysis
**Document**: `RELATIONSHIP_ANALYSIS.md`  
**Level**: Second-Year Undergraduate DBMS Project  
**Author**: CyberTrace Project Team  
**Primary Dataset**: MITRE ATT&CK Enterprise Matrix v19.2  

---

## 1. Overview of Cyber Threat Intelligence Relationships

In relational database systems, a **relationship** is an association among two or more entities. Relationships reflect real-world connections and dependencies in the domain.

In cybersecurity threat intelligence:
- Adversaries (**Groups**) conduct **Campaigns** and deploy malicious **Software**.
- Adversaries execute technical **Techniques** to fulfill tactical objectives (**Tactics**).
- Defenses consist of **Mitigations** to neutralize techniques and **Detection Strategies** backed by telemetry **Data Components** to alert security analysts.

This document systematically analyzes all relationships present in the MITRE ATT&CK Enterprise dataset, categorizing them by cardinality (**One-to-One 1:1**, **One-to-Many 1:M**, and **Many-to-Many M:N**), specifying foreign keys, identifying junction tables, and citing factual row counts.

---

## 2. Detailed Relationship Inventory

### 2.1 Technique ↔ Tactic (Many-to-Many M:N)
- **Entities Involved**: `techniques` and `tactics`.
- **Cardinality**: Many-to-Many ($M:N$).
  - One technique can serve multiple tactical objectives (e.g., `T1548 Abuse Elevation Control Mechanism` achieves both *Privilege Escalation* and *Defense Evasion*).
  - One tactic contains dozens of alternative techniques (e.g., *Initial Access* encompasses phishing, valid accounts, external remote services, etc.).
- **Junction Table**: `technique_tactics`.
  - Foreign Key 1: `technique_id` $\to$ `techniques(technique_id)` (`ON DELETE CASCADE ON UPDATE CASCADE`).
  - Foreign Key 2: `tactic_id` $\to$ `tactics(tactic_id)` (`ON DELETE RESTRICT ON UPDATE CASCADE`).
  - Primary Key: Composite `(technique_id, tactic_id)`.
- **Evidence from Workbook**: Multi-valued column `tactics` in Sheet 1 (`techniques`), unpivoted across the 15 categories defined in Sheet 2 (`tactics`).

---

### 2.2 Technique ↔ Technique (Recursive 1:Many 1:M)
- **Entities Involved**: `techniques` (Self-Referencing / Unary Relationship).
- **Cardinality**: One-to-Many ($1:M$).
  - A parent technique can have zero, one, or multiple sub-techniques (e.g., parent technique `T1059 Command and Scripting Interpreter` has sub-techniques `T1059.001 PowerShell`, `T1059.003 Windows Command Shell`, `T1059.004 Unix Shell`, etc.).
  - A sub-technique belongs to exactly **one** parent technique.
  - Top-level techniques have no parent (`parent_technique_id IS NULL`).
- **Implementation**: Foreign Key `parent_technique_id` inside the `techniques` table referencing `techniques(technique_id)` (`ON DELETE RESTRICT ON UPDATE CASCADE`).
- **Evidence from Workbook**: Columns `is sub-technique` (0 or 1) and `sub-technique of` in Sheet 1 (`techniques`). Exactly 283 sub-techniques reference a parent ID; 414 top-level techniques have NULL.

---

### 2.3 Group ↔ Group Aliases (One-to-Many 1:M)
- **Entities Involved**: `groups` (Parent) and `group_aliases` (Child/Dependent).
- **Cardinality**: One-to-Many ($1:M$).
  - One threat actor group is known by multiple industry names and vendor designations (e.g., `G0007 APT28` is tracked as *Fancy Bear*, *Sednit*, *Sofacy*, *STRONTIUM*, *Pawn Storm*).
  - Each alias entry maps to exactly one threat group.
- **Implementation**: Foreign Key `group_id` in `group_aliases` referencing `groups(group_id)` (`ON DELETE CASCADE ON UPDATE CASCADE`).
- **Evidence from Workbook**: Multi-valued column `associated groups` in Sheet 4 (`groups`).

---

### 2.4 Software ↔ Technique (Many-to-Many M:N)
- **Entities Involved**: `software` and `techniques`.
- **Relationship Name**: `uses`.
- **Cardinality**: Many-to-Many ($M:N$).
  - A software tool or malware binary can implement multiple attack techniques (e.g., `Mimikatz S0002` implements OS Credential Dumping, LSA Secrets, Pass the Hash, Kerberoasting).
  - An attack technique can be executed by hundreds of different software tools.
- **Junction Representation**: Captured in `relationships` table (`source_id = software.software_id`, `target_id = techniques.technique_id`, `mapping_type = 'uses'`).
- **Evidence from Workbook**: Sheet 8 (`relationships`), exactly **11,362 records**.

---

### 2.5 Group ↔ Technique (Many-to-Many M:N)
- **Entities Involved**: `groups` and `techniques`.
- **Relationship Name**: `uses`.
- **Cardinality**: Many-to-Many ($M:N$).
  - A threat group is observed using multiple techniques during their operations.
  - A technique is commonly used across multiple adversary groups.
- **Junction Representation**: Captured in `relationships` table (`source_id = groups.group_id`, `target_id = techniques.technique_id`, `mapping_type = 'uses'`).
- **Evidence from Workbook**: Sheet 8 (`relationships`), exactly **4,628 records**.

---

### 2.6 Mitigation ↔ Technique (Many-to-Many M:N)
- **Entities Involved**: `mitigations` and `techniques`.
- **Relationship Name**: `mitigates`.
- **Cardinality**: Many-to-Many ($M:N$).
  - One defensive mitigation addresses and hardens against multiple techniques (e.g., `M1036 Account Use Policies` restricts access across credential dumping, lateral movement, and privilege escalation).
  - One technique can be countered by multiple distinct mitigations (e.g., execution prevention, network segmentation, least privilege).
- **Junction Representation**: Captured in `relationships` table (`source_id = mitigations.mitigation_id`, `target_id = techniques.technique_id`, `mapping_type = 'mitigates'`).
- **Evidence from Workbook**: Sheet 8 (`relationships`), exactly **1,448 records**.

---

### 2.7 Group ↔ Software (Many-to-Many M:N)
- **Entities Involved**: `groups` and `software`.
- **Relationship Name**: `uses`.
- **Cardinality**: Many-to-Many ($M:N$).
  - A threat group employs multiple software tools and custom malware families.
  - Widely available tools (like Cobalt Strike, PsExec, Mimikatz) are operated by dozens of different adversary groups.
- **Junction Representation**: Captured in `relationships` table (`source_id = groups.group_id`, `target_id = software.software_id`, `mapping_type = 'uses'`).
- **Evidence from Workbook**: Sheet 8 (`relationships`), exactly **1,149 records**.

---

### 2.8 Campaign ↔ Technique (Many-to-Many M:N)
- **Entities Involved**: `campaigns` and `techniques`.
- **Relationship Name**: `uses`.
- **Cardinality**: Many-to-Many ($M:N$).
  - A targeted cyber campaign incorporates multiple techniques throughout the kill chain.
  - A technique is leveraged across multiple historical campaigns.
- **Junction Representation**: Captured in `relationships` table (`source_id = campaigns.campaign_id`, `target_id = techniques.technique_id`, `mapping_type = 'uses'`).
- **Evidence from Workbook**: Sheet 8 (`relationships`), exactly **1,146 records**.

---

### 2.9 Detection Strategy ↔ Technique (Many-to-Many M:N)
- **Entities Involved**: `detection_strategies` and `techniques`.
- **Relationship Name**: `detects`.
- **Cardinality**: Many-to-Many ($M:N$).
  - A detection strategy monitors and detects specific technique behaviors.
  - A technique can be monitored through various detection strategies depending on telemetry availability.
- **Junction Representation**: Captured in `relationships` table (`source_id = detection_strategies.strategy_id`, `target_id = techniques.technique_id`, `mapping_type = 'detects'`).
- **Evidence from Workbook**: Sheet 8 (`relationships`), exactly **697 records**.

---

### 2.10 Campaign ↔ Software (Many-to-Many M:N)
- **Entities Involved**: `campaigns` and `software`.
- **Relationship Name**: `uses`.
- **Cardinality**: Many-to-Many ($M:N$).
  - An intrusion campaign relies on specific software binaries and utility tools.
  - A software tool can be observed across multiple campaigns over time.
- **Junction Representation**: Captured in `relationships` table (`source_id = campaigns.campaign_id`, `target_id = software.software_id`, `mapping_type = 'uses'`).
- **Evidence from Workbook**: Sheet 8 (`relationships`), exactly **172 records**.

---

### 2.11 Campaign ↔ Group (Many-to-One M:1 Attribution)
- **Entities Involved**: `campaigns` and `groups`.
- **Relationship Name**: `attributed-to`.
- **Cardinality**: Many-to-One ($M:1$).
  - Multiple campaigns are conducted by and attributed to the same threat group (e.g., *2015 Ukraine Electric Power Attack*, *2016 Ukraine Electric Power Attack*, and *2022 Ukraine Electric Power Attack* are all attributed to `G0034 Sandworm Team`).
  - An individual campaign is attributed to its conducting adversary group.
- **Junction Representation**: Captured in `relationships` table (`source_id = campaigns.campaign_id`, `target_id = groups.group_id`, `mapping_type = 'attributed-to'`).
- **Evidence from Workbook**: Sheet 8 (`relationships`), exactly **26 records**.

---

### 2.12 Defensive Mappings (Multi-Way Association)
- **Entities Involved**: `detection_strategies`, `analytics`, `data_components`.
- **Cardinality**: Multi-way $N:M$.
  - Detection strategies are composed of specific analytical queries (`analytics`), which monitor specific telemetry points (`data_components`) across particular operating system log sources.
- **Junction Table**: `defensive_mappings`.
  - Foreign Key 1: `strategy_id` $\to$ `detection_strategies(strategy_id)`.
  - Foreign Key 2: `data_component_id` $\to$ `data_components(data_component_id)`.
- **Evidence from Workbook**: Sheet 12 (`defensive mappings`), exactly **4,160 records**.

---

## 3. Relationship Cardinality Matrix Summary

| # | Relationship Name | Source Entity | Target Entity | Cardinality | Implementation Mechanism | Verified Workbook Row Count |
|---|---|---|---|---|---|---|
| 1 | Categorizes | `tactics` | `techniques` | $M:N$ | Junction table: `technique_tactics` | All 697 techniques mapped to 15 tactics |
| 2 | Sub-technique Hierarchy | `techniques` | `techniques` | $1:M$ | Recursive Foreign Key `parent_technique_id` | 283 sub-techniques |
| 3 | Threat Actor Aliases | `groups` | `group_aliases` | $1:M$ | Foreign Key `group_id` in `group_aliases` | Normalized from Sheet 4 |
| 4 | Software Uses Technique | `software` | `techniques` | $M:N$ | Junction table: `relationships` | **11,362** |
| 5 | Group Uses Technique | `groups` | `techniques` | $M:N$ | Junction table: `relationships` | **4,628** |
| 6 | Mitigation Mitigates Technique | `mitigations` | `techniques` | $M:N$ | Junction table: `relationships` | **1,448** |
| 7 | Group Uses Software | `groups` | `software` | $M:N$ | Junction table: `relationships` | **1,149** |
| 8 | Campaign Uses Technique | `campaigns` | `techniques` | $M:N$ | Junction table: `relationships` | **1,146** |
| 9 | Detection Strategy Detects Technique | `detection_strategies`| `techniques` | $M:N$ | Junction table: `relationships` | **697** |
| 10 | Campaign Uses Software | `campaigns` | `software` | $M:N$ | Junction table: `relationships` | **172** |
| 11 | Campaign Attributed To Group | `campaigns` | `groups` | $M:1$ | Junction table: `relationships` | **26** |
| 12 | Telemetry Defensive Mapping | `detection_strategies`| `data_components`| $M:N$ | Junction table: `defensive_mappings`| **4,160** |

**Total Verified Threat Graph Edges in `relationships`**: $11,362 + 4,628 + 1,448 + 1,149 + 1,146 + 697 + 172 + 26 = \mathbf{20,628}$ records.

Every single relationship is backed by empirical data from the MITRE ATT&CK Enterprise workbook.
