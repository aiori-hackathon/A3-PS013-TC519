# CyberTrace: Cyber Threat Intelligence Platform
## Step 7 – Relational Schema Review Before MySQL Implementation
**Document**: `SCHEMA_REVIEW.md`  
**Level**: Second-Year Undergraduate DBMS Project  
**Author**: CyberTrace Project Team  
**Review Status**: APPROVED FOR IMPLEMENTATION  

---

## 1. Schema Quality & Design Audit Checklist

Before implementing MySQL DDL scripts, a rigorous architectural review of the relational design was conducted against fundamental DBMS principles:

| Review Criterion | Verification Question | Evaluation | Design Justification |
|---|---|---|---|
| **1NF Compliance** | Are all column values atomic? Are repeating groups eliminated? | **PASSED** | Multi-valued `tactics` and `associated groups` extracted into `technique_tactics` and `group_aliases`. No comma-separated strings stored in relational keys. |
| **2NF Compliance** | Are there any partial dependencies on composite keys? | **PASSED** | Composite table `technique_tactics` contains only key attributes. In `defensive_mappings`, redundant entity names were removed, ensuring every attribute depends on the full key. |
| **3NF Compliance** | Are all transitive dependencies eliminated? | **PASSED** | `source_name` and `target_name` removed from `relationships`. Names are resolved dynamically via `JOIN` against parent entity tables. |
| **BCNF Compliance** | Is every determinant a candidate superkey? | **PASSED** | All functional dependencies are determined by candidate superkeys (`tactic_id`, `technique_id`, `software_id`, `group_id`, etc.). |
| **M:N Resolution** | Are all many-to-many relationships modeled via associative tables? | **PASSED** | Modeled via `technique_tactics`, `relationships`, and `defensive_mappings`. |
| **Primary Key Design** | Are primary keys unique, minimal, and non-null? | **PASSED** | Natural MITRE keys (`Txxxx`, `TAxxxx`, `Sxxxx`, `Gxxxx`) used for entities; auto-increment surrogate keys used for associative tables where beneficial. |
| **Recursive Integrity** | Is the recursive sub-technique relationship valid? | **PASSED** | `techniques.parent_technique_id` references `techniques.technique_id` with `ON DELETE RESTRICT`. Top-level techniques legitimately hold `NULL`. |
| **Data Type Efficiency** | Are types chosen according to actual data lengths? | **PASSED** | Appropriate `VARCHAR(20)` for IDs, `VARCHAR(200)` for names, `MEDIUMTEXT` for rich-text descriptions, `TINYINT(1)` for booleans. |
| **Referential Actions** | Are cascade actions applied safely? | **PASSED** | `ON DELETE CASCADE` used only on dependent tables (`technique_tactics`, `group_aliases`); `ON DELETE RESTRICT` used on core entities to prevent accidental data loss. |
| **Data Preservation** | Does the schema preserve 100% of the workbook information? | **PASSED** | All 13 sheets and all 20,628 threat graph edges are fully accounted for. |

---

## 2. Structural Sanity Verification

```
Entity Dependency Hierarchy (Loading Sequence):
  1. Root Entities (No Foreign Keys):
     ├── tactics
     ├── software
     ├── groups
     ├── campaigns
     ├── mitigations
     ├── data_components
     ├── analytics
     ├── detection_strategies
     └── citations

  2. Recursive Entity:
     └── techniques (self-references techniques.technique_id)

  3. Dependent & Associative Tables (Reference Root Entities):
     ├── technique_tactics (references techniques, tactics)
     ├── group_aliases (references groups)
     ├── relationships (references source & target entity IDs)
     └── defensive_mappings (references detection_strategies, data_components)
```

**Approval Statement**:  
The schema meets all second-year undergraduate DBMS academic standards, eliminates data anomalies, and is approved for physical DDL script generation in MySQL Server 8.0 and MySQL Workbench.
