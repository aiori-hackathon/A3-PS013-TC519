# CyberTrace: Cyber Threat Intelligence Platform
## Step 8 – Database Validation Report
**Document**: `DATA_VALIDATION_REPORT.md`  
**Level**: Second-Year Undergraduate DBMS Project  
**Author**: CyberTrace Project Team  
**Validation Script**: `database/04_validation.sql`  

---

## 1. Executive Summary & Verification Methodology

Following the physical schema creation and dataset import into MySQL Server 8.0, systematic validation was conducted to verify that:
1. All table row counts match the cleaned source Excel dataset exactly.
2. Primary keys satisfy strict non-null and uniqueness constraints (Entity Integrity).
3. Foreign key constraints maintain referential integrity without broken references or orphan records (Referential Integrity).
4. Junction tables contain no duplicate association tuples.
5. All 20,628 threat graph edges are accurately classified by source type, target type, and mapping predicate.

---

## 2. Table-by-Table Row Count Audit

| Relational Table | Expected Source Rows | Validated Imported Rows | Status | Verification Query |
|---|---|---|---|---|
| `tactics` | 15 | 15 | **PASSED** | `SELECT COUNT(*) FROM tactics;` |
| `techniques` | 697 | 697 | **PASSED** | `SELECT COUNT(*) FROM techniques;` |
| `technique_tactics` | 668 | 668 | **PASSED** | `SELECT COUNT(*) FROM technique_tactics;` |
| `software` | 825 | 825 | **PASSED** | `SELECT COUNT(*) FROM software;` |
| `groups` | 176 | 176 | **PASSED** | `SELECT COUNT(*) FROM groups;` |
| `group_aliases` | 185 | 185 | **PASSED** | `SELECT COUNT(*) FROM group_aliases;` |
| `campaigns` | 56 | 56 | **PASSED** | `SELECT COUNT(*) FROM campaigns;` |
| `mitigations` | 44 | 44 | **PASSED** | `SELECT COUNT(*) FROM mitigations;` |
| `data_components` | 106 | 106 | **PASSED** | `SELECT COUNT(*) FROM data_components;` |
| `relationships` | 20,628 | 20,628 | **PASSED** | `SELECT COUNT(*) FROM relationships;` |

*Discrepancies Found*: **0**. Complete 100% preservation of dataset rows.

---

## 3. Entity Integrity Audit (Primary Key Non-Null & Uniqueness)

The SQL validation suite checked all candidate and primary keys for `NULL` values or duplicate occurrences:

```sql
SELECT 'tactics PK NULL check', COUNT(*) FROM tactics WHERE tactic_id IS NULL;
-- Result: 0 (PASSED)

SELECT 'techniques PK NULL check', COUNT(*) FROM techniques WHERE technique_id IS NULL;
-- Result: 0 (PASSED)

SELECT 'software PK NULL check', COUNT(*) FROM software WHERE software_id IS NULL;
-- Result: 0 (PASSED)

SELECT 'groups PK NULL check', COUNT(*) FROM groups WHERE group_id IS NULL;
-- Result: 0 (PASSED)
```

- **NULL Keys Discovered**: 0 across all tables.
- **Duplicate Keys Discovered**: 0 across all tables.

---

## 4. Referential Integrity Audit (Foreign Key Constraints)

### 4.1 Recursive Technique Self-Reference
- **Rule**: Every `sub-technique` with a non-null `parent_technique_id` must reference a valid existing `technique_id` in `techniques`.
- **Result**:
  - Total Sub-techniques: 283
  - Orphan Sub-techniques: **0**
  - Status: **PASSED**

### 4.2 Technique-Tactic Junction Table
- **Rule**: Every `(technique_id, tactic_id)` tuple in `technique_tactics` must reference an existing technique in `techniques` and an existing tactic in `tactics`.
- **Result**:
  - Orphan Technique References: **0**
  - Orphan Tactic References: **0**
  - Duplicate Junction Tuples: **0**
  - Status: **PASSED**

### 4.3 Threat Actor Aliases
- **Rule**: Every `alias_name` in `group_aliases` must point to an active, valid `group_id` in `groups`.
- **Result**:
  - Orphan Alias References: **0**
  - Status: **PASSED**

---

## 5. Universal Threat Graph Relationship Verification

The 20,628 relationship records imported into `relationships` were grouped by source, target, and mapping predicate to confirm semantic integrity:

| Source Type | Mapping Type | Target Type | Validated Row Count | Status |
|---|---|---|---|---|
| `software` | `uses` | `technique` | 11,362 | **PASSED** |
| `group` | `uses` | `technique` | 4,628 | **PASSED** |
| `mitigation` | `mitigates` | `technique` | 1,448 | **PASSED** |
| `group` | `uses` | `software` | 1,149 | **PASSED** |
| `campaign` | `uses` | `technique` | 1,146 | **PASSED** |
| `detectionstrategy` | `detects` | `technique` | 697 | **PASSED** |
| `campaign` | `uses` | `software` | 172 | **PASSED** |
| `campaign` | `attributed-to` | `group` | 26 | **PASSED** |
| **Total** | | | **20,628** | **PASSED** |

---

## 6. Conclusion

The database validation confirms that the physical MySQL schema correctly preserves the structure and integrity of the MITRE ATT&CK Enterprise dataset. Entity integrity, domain constraints, and foreign key relationships are strictly maintained without loss of information or orphaned data.
