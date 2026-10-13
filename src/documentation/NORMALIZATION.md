# CyberTrace: Cyber Threat Intelligence Platform
## Step 5 – Database Normalization
**Document**: `NORMALIZATION.md`  
**Level**: Second-Year Undergraduate DBMS Project  
**Author**: CyberTrace Project Team  
**Primary Dataset**: MITRE ATT&CK Enterprise Matrix v19.2  

---

## 1. Overview and Objectives of Normalization

**Database Normalization** is a formal, scientific process of organizing relational database schemas to minimize data redundancy, eliminate data anomalies (insertion, update, and deletion anomalies), and preserve data integrity without loss of information.

The canonical progression evaluated for CyberTrace is:
$$\text{Unnormalized Form (UNF)} \longrightarrow \text{1NF} \longrightarrow \text{2NF} \longrightarrow \text{3NF} \longrightarrow \text{BCNF (Evaluated)}$$

This document demonstrates the concrete relational transformation from the raw MITRE ATT&CK Excel sheets into a fully normalized, anomaly-free relational schema.

---

## 2. Unnormalized Form (UNF) Analysis

In the raw Excel distribution of the MITRE ATT&CK dataset:
1. **Multi-Valued Cells**: Attributes contain delimited lists of multiple values in single cells:
   - `techniques.tactics` contains comma-separated lists of tactic names (e.g., `"Privilege Escalation, Defense Evasion"`).
   - `techniques.platforms` contains comma-separated OS targets (e.g., `"Linux, macOS, Windows, Office Suite"`).
   - `groups.associated groups` contains comma-separated alias monikers (e.g., `"Fancy Bear, Sednit, Sofacy, STRONTIUM"`).
2. **Repeating Groups / Cross-Tabulation**:
   - Sheet 7 (`Enterprise ATT&CK matrix`) lays out techniques as columns under 15 distinct tactic headers across 30 alternating columns, forming a human-browsable spreadsheet matrix rather than an atomic relational table.
3. **Redundant Descriptive Names**:
   - `relationships` stores `source name` and `target name` alongside their IDs across 20,628 rows.
   - `defensive mappings` stores repeated `strategy_name`, `analytic_name`, and `data_component_name` across 4,160 rows.

---

## 3. First Normal Form (1NF)

### 3.1 Definition of 1NF
A relation $R$ is in **First Normal Form (1NF)** if and only if:
1. Every attribute domain contains only **atomic (indivisible)** values.
2. There are no **repeating groups** or multi-valued attributes in any tuple.
3. Each record is uniquely identifiable by a Primary Key.

### 3.2 1NF Violations Discovered in Dataset
1. **Violation 1 (`techniques.tactics`)**:
   - *Raw State*: A tuple for technique `T1548` has `tactics = "Privilege Escalation, Defense Evasion"`.
   - *Why it fails*: An analyst cannot execute `WHERE tactic = 'Privilege Escalation'` with an exact index match; string wildcards (`LIKE '%Privilege Escalation%'`) are slow, prone to false matches, and violate relational calculus.
   - *Decomposition*: Extract the multi-valued attribute into a dedicated associative table `technique_tactics(technique_id, tactic_id)` where each tuple contains exactly one atomic technique ID and one atomic tactic ID:
     $$\langle \text{'T1548'}, \text{'TA0004'} \rangle, \quad \langle \text{'T1548'}, \text{'TA0005'} \rangle$$
2. **Violation 2 (`groups.associated groups`)**:
   - *Raw State*: `G0007` contains `"Fancy Bear, Sednit, Sofacy, STRONTIUM"`.
   - *Decomposition*: Decomposed into dependent entity `group_aliases(alias_id, group_id, alias_name)` with each alias in an individual atomic row.
3. **Violation 3 (`Enterprise ATT&CK matrix`)**:
   - *Raw State*: 30-column unpivoted spreadsheet layout.
   - *Resolution*: Rejected as a physical base table. Represented relationally by `techniques`, `tactics`, and `technique_tactics`.

### 3.3 Verification of 1NF
After decomposition:
- All attribute domains contain scalar, indivisible values (`VARCHAR`, `INT`, `TEXT`, `BOOLEAN`).
- No cell contains lists, arrays, or delimited sub-records.
- **The schema is strictly in 1NF.**

---

## 4. Second Normal Form (2NF)

### 4.1 Definition of 2NF
A relation $R$ is in **Second Normal Form (2NF)** if and only if:
1. It is in **1NF**.
2. No non-prime attribute is **partially functionally dependent** on any candidate key of $R$.
*(In other words, every non-prime attribute must be fully functionally dependent on the entire primary key, not a proper subset of it).*

> [!NOTE]
> If a table has a **single-attribute primary key**, it is **automatically in 2NF** because a proper subset of a single attribute cannot exist.

### 4.2 2NF Analysis on CyberTrace Tables
1. **Single-Key Tables (Automatically in 2NF)**:
   - `tactics` (PK: `tactic_id`)
   - `techniques` (PK: `technique_id`)
   - `software` (PK: `software_id`)
   - `groups` (PK: `group_id`)
   - `campaigns` (PK: `campaign_id`)
   - `mitigations` (PK: `mitigation_id`)
   - `data_components` (PK: `data_component_id`)
   - `analytics` (PK: `analytic_id`)
   - `detection_strategies` (PK: `strategy_id`)
   - `citations` (PK: `citation_id`)
   - `group_aliases` (PK: `alias_id`)

2. **Associative Table with Composite Key: `technique_tactics`**:
   - Candidate Key / Primary Key: `(technique_id, tactic_id)`.
   - Non-prime attributes: None.
   - *Verification*: Because there are no non-prime attributes, partial dependencies cannot exist. Hence, `technique_tactics` is strictly in 2NF.

3. **Multi-Way Mapping Table: `defensive_mappings`**:
   - *Raw Candidate Key*: `(strategy_id, analytic_id, data_component_id, log_source_name)`.
   - *Raw Attributes*: `detection_strategy_name`, `analytic_name`, `data_component_name`, `platform`, `channel`.
   - *Partial Dependencies Discovered*:
     $$\text{strategy\_id} \longrightarrow \text{detection\_strategy\_name} \quad (\text{subset of composite key})$$
     $$\text{data\_component\_id} \longrightarrow \text{data\_component\_name} \quad (\text{subset of composite key})$$
     $$\text{analytic\_id} \longrightarrow \text{analytic\_name} \quad (\text{subset of composite key})$$
   - *Decomposition Performed*:
     - Removed `detection_strategy_name` $\to$ maintained in `detection_strategies`.
     - Removed `data_component_name` $\to$ maintained in `data_components`.
     - Removed `analytic_name` $\to$ maintained in `analytics`.
     - Retained in `defensive_mappings`: `mapping_id` (Surrogate PK), `strategy_id` (FK), `analytic_id` (FK), `data_component_id` (FK), `platform`, `log_source_name`, `channel`.
   - *Result*: Every non-key attribute is dependent on the whole key.

### 4.3 Verification of 2NF
All partial dependencies on composite keys have been eliminated. **The schema is strictly in 2NF.**

---

## 5. Third Normal Form (3NF)

### 5.1 Definition of 3NF
A relation $R$ is in **Third Normal Form (3NF)** if and only if:
1. It is in **2NF**.
2. No non-prime attribute is **transitively dependent** on any candidate key of $R$.
*(Formally, for every non-trivial functional dependency $X \to A$, either $X$ is a superkey of $R$, or $A$ is a prime attribute).*

### 5.2 3NF Violations Discovered in Dataset
1. **Violation in `relationships` Table**:
   - *Raw Structure*:
     $$\text{relationship\_id} \longrightarrow \{\text{source\_id, source\_name, target\_id, target\_name, mapping\_type, \dots}\}$$
   - *Transitive Dependencies*:
     $$\text{relationship\_id} \longrightarrow \text{source\_id} \quad \text{and} \quad \text{source\_id} \longrightarrow \text{source\_name} \implies \text{relationship\_id} \longrightarrow \text{source\_name}$$
     $$\text{relationship\_id} \longrightarrow \text{target\_id} \quad \text{and} \quad \text{target\_id} \longrightarrow \text{target\_name} \implies \text{relationship\_id} \longrightarrow \text{target\_name}$$
   - *Anomalies Caused*:
     - **Update Anomaly**: If a software tool name (e.g. `Mimikatz`) is modified, all 100+ relationship rows referencing `S0002` must be updated. If any row is missed, data becomes inconsistent.
     - **Insertion Anomaly**: Cannot record a relationship with a source whose name is not yet confirmed without creating a conflicting name string.
     - **Deletion Anomaly**: Deleting relationship records might delete the only recorded instance of an entity name if not recorded elsewhere.
   - *3NF Decomposition*:
     - Remove `source_name` and `target_name` from `relationships`.
     - In the normalized schema, `relationships` stores:
       `relationship_id`, `source_id`, `source_type`, `mapping_type`, `target_id`, `target_type`, `mapping_description`, `stix_id`, `created_date`, `last_modified_date`.
     - Descriptive names are resolved dynamically at query time using SQL `INNER JOIN` or relational views.

### 5.3 Verification of 3NF
Every non-prime attribute in every table is directly dependent upon the primary key and nothing else ($\text{Key} \to \text{Attribute}$). **The schema is strictly in 3NF.**

---

## 6. Boyce-Codd Normal Form (BCNF) Evaluation

### 6.1 Definition of BCNF
A relation $R$ is in **Boyce-Codd Normal Form (BCNF)** if and only if:
- For every non-trivial functional dependency $X \to Y$, **$X$ is a superkey** of $R$.

*(BCNF is a stricter form of 3NF that eliminates anomalies when a table has multiple overlapping candidate keys).*

### 6.2 Evaluation on CyberTrace Schema
- In `tactics`: Determinants are `tactic_id` and `stix_id`. Both are candidate superkeys. $\implies$ **In BCNF**.
- In `techniques`: Determinants are `technique_id` and `stix_id`. Both are candidate superkeys. $\implies$ **In BCNF**.
- In `software`: Determinants are `software_id` and `stix_id`. Both are candidate superkeys. $\implies$ **In BCNF**.
- In `groups`: Determinants are `group_id` and `stix_id`. Both are candidate superkeys. $\implies$ **In BCNF**.
- In `campaigns`: Determinants are `campaign_id` and `stix_id`. Both are candidate superkeys. $\implies$ **In BCNF**.
- In `technique_tactics`: Only functional dependency is the trivial composite key dependency. $\implies$ **In BCNF**.
- In `relationships`: Determinant is `relationship_id` (or `stix_id`), both of which are superkeys. $\implies$ **In BCNF**.

**Conclusion**: Since every determinant in our normalized schema is a candidate superkey, **the schema satisfies BCNF**. No further decomposition is required, and no functional dependencies were lost during decomposition (dependency-preserving and lossless join decomposition).

---

## 7. Normalization Summary Map

```
[Raw Excel Sheets (UNF)]
   ├── Multi-valued tactics, platforms, aliases
   ├── 30-column pivot Matrix
   └── Redundant entity names in 20,628 mapping rows
             │
             ▼ 1NF Decomposition
[First Normal Form (1NF)]
   ├── Created `technique_tactics` junction table (atomic mapping)
   ├── Created `group_aliases` table (atomic names)
   └── Excluded presentation Matrix from physical storage
             │
             ▼ 2NF Decomposition
[Second Normal Form (2NF)]
   └── Decomposed `defensive_mappings` to remove partial dependencies
             │
             ▼ 3NF Decomposition
[Third Normal Form (3NF)]
   └── Removed transitive `source_name` and `target_name` from `relationships`
             │
             ▼ BCNF Evaluation
[Boyce-Codd Normal Form (BCNF)]
   └── Verified all determinants are candidate superkeys (Lossless & Dependency-Preserving)
```

The resulting normalized database schema is scientifically robust, free of anomalies, and optimized for MySQL implementation.
