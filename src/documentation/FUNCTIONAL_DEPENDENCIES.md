# CyberTrace: Cyber Threat Intelligence Platform
## Step 4 – Functional Dependencies Analysis
**Document**: `FUNCTIONAL_DEPENDENCIES.md`  
**Level**: Second-Year Undergraduate DBMS Project  
**Author**: CyberTrace Project Team  
**Primary Dataset**: MITRE ATT&CK Enterprise Matrix v19.2  

---

## 1. Theoretical Foundation of Functional Dependencies

In Relational Database Management Systems (DBMS), a **Functional Dependency (FD)** is a formal constraint between two sets of attributes in a relational schema $R$.

### Formal Definition:
Given a relation $R$, a set of attributes $Y$ is functionally dependent on another set of attributes $X$ (denoted as $X \to Y$, read *"X functionally determines Y"* or *"Y is functionally dependent on X"*), if and only if, whenever two tuples $t_1$ and $t_2$ in any legal relational state of $R$ have $t_1[X] = t_2[X]$, they must also have $t_1[Y] = t_2[Y]$.

- **Determinant**: The left-hand side attribute set $X$.
- **Dependent**: The right-hand side attribute set $Y$.
- **Full Functional Dependency**: An attribute $Y$ is fully functionally dependent on $X$ if $X \to Y$ and $Y$ is not functionally dependent on any proper subset of $X$.
- **Partial Dependency**: An attribute $Y$ is partially dependent on a composite key $X$ if there exists some proper subset $A \subset X$ such that $A \to Y$.
- **Transitive Dependency**: A dependency of the form $X \to Y$ and $Y \to Z$ where $Y \not\to X$ and $Z$ is a non-prime attribute not belonging to any candidate key, implying $X \to Z$ indirectly through $Y$.

---

## 2. Table-by-Table Functional Dependency Audit

### 2.1 Table: `tactics`
- **Candidate Keys**: `tactic_id`, `stix_id`, `name`.
- **Selected Primary Key**: `tactic_id`.
- **Functional Dependencies**:
  - $\text{tactic\_id} \to \{\text{stix\_id, name, description, url, created\_date, last\_modified\_date, version}\}$
  - $\text{stix\_id} \to \{\text{tactic\_id, name, description, url, created\_date, last\_modified\_date, version}\}$
  - $\text{name} \to \{\text{tactic\_id, stix\_id, description, url, created\_date, last\_modified\_date, version}\}$
- **Analysis**:
  - All non-prime attributes are fully functionally dependent on the single-attribute primary key `tactic_id`.
  - There are no partial dependencies (primary key is not composite).
  - There are no transitive dependencies among non-prime attributes.
  - **Verdict**: Satisfies full functional dependency.

---

### 2.2 Table: `techniques`
- **Candidate Keys**: `technique_id`, `stix_id`.
- **Selected Primary Key**: `technique_id`.
- **Functional Dependencies**:
  - $\text{technique\_id} \to \{\text{stix\_id, name, description, url, created\_date, last\_modified\_date, version, is\_subtechnique, parent\_technique\_id, supports\_remote, impact\_type}\}$
  - $\text{stix\_id} \to \{\text{technique\_id, name, description, url, created\_date, last\_modified\_date, version, is\_subtechnique, parent\_technique\_id, supports\_remote, impact\_type}\}$
- **Analysis**:
  - Given any `technique_id` (e.g., `T1059`), the technique's name, technical description, and parent identifier are uniquely and deterministically identified.
  - In the unnormalized sheet, `techniques.tactics` was multi-valued ($1 \to \text{many}$), which violated the definition of a single-valued functional dependency. Removing `tactics` to the junction table `technique_tactics` restores functional dependency integrity.

---

### 2.3 Table: `technique_tactics` (Associative Table)
- **Candidate Key / Primary Key**: Composite Key `(technique_id, tactic_id)`.
- **Functional Dependencies**:
  - Neither $\text{technique\_id} \to \text{tactic\_id}$ nor $\text{tactic\_id} \to \text{technique\_id}$ holds individually because the relationship is $M:N$.
  - Trivially, $\{\text{technique\_id, tactic\_id}\} \to \{\text{technique\_id, tactic\_id}\}$.
- **Analysis**:
  - The table contains only prime attributes (attributes forming the primary key).
  - There are no non-prime attributes, eliminating any possibility of partial or transitive dependencies.

---

### 2.4 Table: `software`
- **Candidate Keys**: `software_id`, `stix_id`.
- **Selected Primary Key**: `software_id`.
- **Functional Dependencies**:
  - $\text{software\_id} \to \{\text{stix\_id, name, type, description, url, created\_date, last\_modified\_date, version}\}$
  - $\text{stix\_id} \to \{\text{software\_id, name, type, description, url, created\_date, last\_modified\_date, version}\}$
- **Analysis**:
  - `software_id` uniquely identifies the software's classification (`malware` vs `tool`), documentation link, and description.
  - No transitive dependencies exist between non-key attributes.

---

### 2.5 Table: `groups`
- **Candidate Keys**: `group_id`, `stix_id`.
- **Selected Primary Key**: `group_id`.
- **Functional Dependencies**:
  - $\text{group\_id} \to \{\text{stix\_id, name, description, url, created\_date, last\_modified\_date, version}\}$
  - $\text{stix\_id} \to \{\text{group\_id, name, description, url, created\_date, last\_modified\_date, version}\}$
- **Analysis**:
  - In the raw sheet, `associated groups` contained multi-valued aliases (e.g., `Fancy Bear, Sednit, STRONTIUM`), which could not be modeled by an FD without violating 1NF. Decomposing aliases into `group_aliases(alias_id, group_id, alias_name)` resolves this problem.

---

### 2.6 Table: `campaigns`
- **Candidate Keys**: `campaign_id`, `stix_id`.
- **Selected Primary Key**: `campaign_id`.
- **Functional Dependencies**:
  - $\text{campaign\_id} \to \{\text{stix\_id, name, description, first\_seen, last\_seen, url, created\_date, last\_modified\_date, version}\}$
- **Analysis**:
  - The campaign start (`first_seen`) and end (`last_seen`) timeline points and narrative descriptions are determined solely by `campaign_id`.

---

### 2.7 Table: `mitigations`
- **Candidate Keys**: `mitigation_id`, `stix_id`.
- **Selected Primary Key**: `mitigation_id`.
- **Functional Dependencies**:
  - $\text{mitigation\_id} \to \{\text{stix\_id, name, description, url, created\_date, last\_modified\_date, version}\}$
- **Analysis**:
  - Every non-key defensive attribute is fully dependent on `mitigation_id`.

---

### 2.8 Table: `relationships` (Raw vs Normalized)
- **Raw Excel FDs (With Anomalies)**:
  - $\text{relationship\_id} \to \{\text{source\_id, source\_name, source\_type, mapping\_type, target\_id, target\_name, target\_type, mapping\_description, stix\_id}\}$
  - $\text{source\_id} \to \text{source\_name}$  *(Transitive dependency on non-key source)*
  - $\text{target\_id} \to \text{target\_name}$  *(Transitive dependency on non-key target)*
- **Problem Statement**:
  - Because `source_name` is determined by `source_id`, storing `source_name` in every relationship row creates update anomalies. If `Sandworm Team` were renamed, 2,000+ relationship rows would have to be updated individually.
- **Normalized Schema FDs (Cleaned)**:
  - $\text{relationship\_id} \to \{\text{source\_id, source\_type, mapping\_type, target\_id, target\_type, mapping\_description, stix\_id, created\_date, last\_modified\_date}\}$
  - Redundant name dependencies ($\text{source\_id} \to \text{source\_name}$ and $\text{target\_id} \to \text{target\_name}$) are removed from this relation and relegated strictly to their parent entity tables.

---

### 2.9 Table: `defensive_mappings` (Raw vs Normalized)
- **Raw Excel FDs (With Anomalies)**:
  - Composite Key: $\{\text{strategy\_id, analytic\_id, data\_component\_id, log\_source\_name}\}$
  - $\text{strategy\_id} \to \text{detection\_strategy\_name}$  *(Partial dependency)*
  - $\text{data\_component\_id} \to \text{data\_component\_name}$  *(Partial dependency)*
  - $\text{analytic\_id} \to \text{analytic\_name}$  *(Partial dependency)*
- **Problem Statement**:
  - A non-prime attribute depends on a proper subset of the composite key, directly violating Second Normal Form (2NF).
- **Normalized Schema FDs**:
  - $\text{mapping\_id} \to \{\text{strategy\_id, analytic\_id, data\_component\_id, platform, log\_source\_name, channel}\}$
  - All non-key attributes depend on the whole primary key.

---

## 3. Summary of Functional Dependencies

| Table | Candidate Key(s) | Primary Key | Dependency Classification | Status |
|---|---|---|---|---|
| `tactics` | `tactic_id`, `stix_id`, `name` | `tactic_id` | Full Functional Dependency | Optimal |
| `techniques` | `technique_id`, `stix_id` | `technique_id` | Full Functional Dependency | Optimal (after 1NF split) |
| `technique_tactics` | `(technique_id, tactic_id)` | Composite | Key Attributes Only | Optimal |
| `software` | `software_id`, `stix_id` | `software_id` | Full Functional Dependency | Optimal |
| `groups` | `group_id`, `stix_id` | `group_id` | Full Functional Dependency | Optimal (after alias split) |
| `group_aliases` | `alias_id` | `alias_id` | Full Functional Dependency | Optimal |
| `campaigns` | `campaign_id`, `stix_id` | `campaign_id` | Full Functional Dependency | Optimal |
| `mitigations` | `mitigation_id`, `stix_id` | `mitigation_id` | Full Functional Dependency | Optimal |
| `relationships` | `relationship_id`, `stix_id` | `relationship_id` | Full Functional Dependency | Redundant names removed |
| `data_components` | `data_component_id`, `stix_id` | `data_component_id`| Full Functional Dependency | Optimal |
| `analytics` | `analytic_id`, `stix_id` | `analytic_id` | Full Functional Dependency | Optimal |
| `detection_strategies` | `strategy_id`, `stix_id` | `strategy_id` | Full Functional Dependency | Optimal |
| `defensive_mappings` | `mapping_id` | `mapping_id` | Full Functional Dependency | Partial deps removed |
| `citations` | `citation_id`, `reference_tag` | `citation_id` | Full Functional Dependency | Optimal |

All functional dependencies in the finalized relational schema are mathematically valid and conform to relational design principles.
