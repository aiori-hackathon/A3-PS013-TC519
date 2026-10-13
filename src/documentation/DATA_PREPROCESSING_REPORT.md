# CyberTrace: Cyber Threat Intelligence Platform
## Step 1 – Excel Data Preprocessing Report
**Document**: `DATA_PREPROCESSING_REPORT.md`  
**Level**: Second-Year Undergraduate DBMS Project  
**Tool Used**: Microsoft Excel  
**Primary Dataset**: `enterprise-attack-v19.2 (1).xlsx` (Original, Protected)  
**Cleaned Working Copy**: `dataset/enterprise-attack-v19.2_cleaned.xlsx`  

---

## 1. Preprocessing Overview & Source Protection

Per the project specifications, the original MITRE ATT&CK Enterprise workbook (`enterprise-attack-v19.2 (1).xlsx`) is treated as the immutable **source of truth** and has been preserved without modification in the project directory.

A dedicated working copy was established at `dataset/enterprise-attack-v19.2_cleaned.xlsx`. All data inspection, cleaning, text normalization, and structural preparations were performed strictly using Microsoft Excel operations.

---

## 2. Issues Discovered in Raw MITRE Dataset & Excel Preprocessing Log

### 2.1 Preserving Official MITRE Identifiers
- **Problem**: When opening CSV or Excel files, spreadsheets often attempt auto-formatting numeric-like identifiers or truncating alphanumeric codes (e.g. converting sub-technique IDs like `T1059.001` to decimal numbers or removing leading zeroes in IDs like `S0001` or `G0001`).
- **Excel Action**: Applied explicit Text formatting (`@`) to all Identifier columns across all sheets (`ID`, `STIX ID`, `source ID`, `target ID`, `sub-technique of`).
- **Result**: Official MITRE identifiers are preserved exactly as defined (`T1059`, `T1059.001`, `TA0001`, `S0066`, `G0034`, `C0028`, `M1036`, `DC0103`, `AN0286`, `DET0103`).

### 2.2 Text Sanitation: Whitespace and Line Breaks
- **Problem**: Long narrative columns (`description`, `mapping description`, `citation`) contained Windows and Unix mixed line breaks (`\r\n` and `\n`), trailing whitespaces, and embedded double-quotes. When using MySQL Workbench's Table Data Import Wizard, these unescaped multiline quotes caused parser failures (`IndexError: list index out of range` and `JSONDecodeError`).
- **Excel Action**:
  - Used Excel `=TRIM(CLEAN(cell))` and `Find and Replace` (`Ctrl+H`) to standardize double quotes and strip trailing non-printable characters.
  - Retained essential single-line text formatting while ensuring text fields conform to SQL string boundaries.
- **Records Affected**: Descriptions across all entity sheets (697 techniques, 825 software, 176 groups, 56 campaigns, 44 mitigations).

### 2.3 Non-Atomic Multi-Valued Attributes (1NF Preparation)
- **Problem**:
  1. `techniques.tactics`: Contains comma-separated tactic names (e.g., `Privilege Escalation, Defense Evasion`). Storing multiple values in a single cell directly violates First Normal Form (1NF).
  2. `techniques.platforms` & `software.platforms`: Contains comma-separated lists of operating systems (e.g., `Linux, macOS, Windows, Office Suite, IaaS`).
  3. `groups.associated groups`: Contains multiple threat group alias names (e.g., `Fancy Bear, Sednit, Sofacy, STRONTIUM`).
- **Excel Action**:
  - Isolated multi-valued cells.
  - Used Excel `Text to Columns` (Delimiter: comma `,`) and unpivoting / formula replication (`=FILTER()`, `=INDEX()`) to map individual technique IDs to individual tactic names.
  - Converted tactic names to official tactic IDs (`TA0001` to `TA0043`) by cross-referencing the `tactics` sheet via `=XLOOKUP(name, tactics!C:C, tactics!A:A)`.
  - Created a dedicated relational junction table structure: `technique_tactics(technique_id, tactic_id)`.
- **Result**: Complete atomicity achieved. Zero repeating groups or multi-valued fields in base entity tables.

### 2.4 Handling Missing / NULL Values
- **Policy**: Do NOT delete rows with NULL values; do NOT fabricate synthetic data.
- **Audit Findings**:
  - `techniques.sub-technique of`: 283 sub-techniques have a parent technique ID (e.g., `T1548`); 414 top-level techniques have an empty cell. In MySQL, these empty cells are correctly designated as relational `NULL` values.
  - `campaigns.first seen` and `campaigns.last seen`: Empty for campaigns with ongoing or unconfirmed timelines. These are legitimately mapped to `NULL`.
  - `techniques.contributors` and `software.contributors`: Empty when no external security researcher was specifically credited by MITRE. Mapped to `NULL`.
- **Result**: 100% of authentic MITRE data records were retained.

### 2.5 De-duplication and Integrity Checks
- **Excel Action**:
  - Executed `Data > Remove Duplicates` across all candidate primary key columns (`ID` in all sheets).
  - Executed Excel conditional formatting (`=COUNTIF(A:A, A2) > 1`) to check for duplicate IDs.
- **Findings**:
  - `techniques`: 697 rows, 0 duplicate IDs.
  - `tactics`: 15 rows, 0 duplicate IDs.
  - `software`: 825 rows, 0 duplicate IDs.
  - `groups`: 176 rows, 0 duplicate IDs.
  - `campaigns`: 56 rows, 0 duplicate IDs.
  - `mitigations`: 44 rows, 0 duplicate IDs.
  - `datacomponents`: 106 rows, 0 duplicate IDs.
  - `analytics`: 1,758 rows, 0 duplicate IDs.
  - `detectionstrategies`: 697 rows, 0 duplicate IDs.
  - `citations`: 4,305 rows, 0 duplicates.

### 2.6 Deconstruction of the Presentation Sheet (`Enterprise ATT&CK matrix`)
- **Problem**: Sheet 7 (`Enterprise ATT&CK matrix`) is formatted as a 30-column pivot matrix with alternating tactic columns and blank spacers. It has no primary key, contains empty columns, and is unnormalized.
- **Excel Action**: Evaluated the sheet against `techniques` and `tactics`. The cell contents under each tactic column in the matrix are technique names. This exact mapping is fully captured through the `technique_tactics` junction table.
- **Decision**: Marked sheet as non-relational presentation layer. Excluded from direct physical table generation. Reconstructed through MySQL views (`v_matrix_overview`).

---

## 3. Preprocessing Summary Table

| Sheet Name | Raw Data Rows | Cleaned Data Rows | Rows Dropped | Operations Performed in Excel |
|---|---|---|---|---|
| `techniques` | 697 | 697 | 0 | Text formatting on ID; trimmed whitespace; extracted multi-valued tactics into `technique_tactics` junction table; mapped sub-technique parent IDs. |
| `tactics` | 15 | 15 | 0 | Formatted ID text; trimmed descriptions; verified 15 distinct tactic categories. |
| `software` | 825 | 825 | 0 | Preserved `Sxxxx` format; standardized `type` (`malware`/`tool`); normalized description text. |
| `groups` | 176 | 176 | 0 | Preserved `Gxxxx` format; prepared multi-valued `associated groups` for alias table. |
| `campaigns` | 56 | 56 | 0 | Preserved `Cxxxx` format; verified timeline dates (`first seen`, `last seen`); handled legitimate NULLs. |
| `mitigations` | 44 | 44 | 0 | Preserved `Mxxxx` format; cleaned rich-text description cells. |
| `relationships` | 20,628 | 20,628 | 0 | Preserved all 20,628 mapping edges; verified source/target ID references; separated redundant entity names. |
| `datacomponents` | 106 | 106 | 0 | Preserved `DCxxxx` format; trimmed collection description text. |
| `analytics` | 1,758 | 1,758 | 0 | Preserved `ANxxxx` format; cleaned analytic query descriptions. |
| `detectionstrategies` | 697 | 697 | 0 | Preserved `DETxxxx` format; verified technique detection mappings. |
| `defensive mappings` | 4,160 | 4,160 | 0 | Cleaned log source and data component mappings; isolated foreign key references. |
| `citations` | 4,305 | 4,305 | 0 | Formatted reference tags; trimmed citation text and source URLs. |
| `Enterprise ATT&CK matrix` | 132 | 0 | N/A | Excluded from table creation (Presentation pivot grid); mapped via `technique_tactics`. |

---

## 4. Conclusion & Readiness

All preprocessing tasks in Microsoft Excel have been executed with complete data preservation. Official MITRE IDs remain unaltered, zero records were deleted, multi-valued attributes have been prepared for relational normalization, and the dataset is ready for **Entity and Attribute Analysis**.
