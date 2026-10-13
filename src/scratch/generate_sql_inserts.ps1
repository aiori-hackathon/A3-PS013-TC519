Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$sourceFile = "c:\Users\disha\OneDrive\Desktop\Cybertrace\dataset\enterprise-attack-v19.2_cleaned.xlsx"
$tempZip = [System.IO.Path]::GetTempFileName() + ".zip"
Copy-Item $sourceFile $tempZip -Force
$zip = [System.IO.Compression.ZipFile]::OpenRead($tempZip)

# 1. Workbook XML
$wbEntry = $zip.GetEntry('xl/workbook.xml')
$wbStream = $wbEntry.Open()
$wbReader = New-Object System.IO.StreamReader($wbStream, [System.Text.Encoding]::UTF8)
$wbXml = [xml]$wbReader.ReadToEnd()
$wbReader.Close()
$wbStream.Close()

# 2. Rel map
$relsEntry = $zip.GetEntry('xl/_rels/workbook.xml.rels')
$relsStream = $relsEntry.Open()
$relsReader = New-Object System.IO.StreamReader($relsStream, [System.Text.Encoding]::UTF8)
$relsXml = [xml]$relsReader.ReadToEnd()
$relsReader.Close()
$relsStream.Close()

$relMap = @{}
foreach ($rel in $relsXml.Relationships.Relationship) {
    $relMap[$rel.Id] = $rel.Target
}

# 3. Shared strings
$sstEntry = $zip.GetEntry('xl/sharedStrings.xml')
$sstStream = $sstEntry.Open()
$sstReader = New-Object System.IO.StreamReader($sstStream, [System.Text.Encoding]::UTF8)
$sstXml = [xml]$sstReader.ReadToEnd()
$sstReader.Close()
$sstStream.Close()

$sharedStrings = New-Object System.Collections.Generic.List[string]
foreach ($si in $sstXml.sst.si) {
    $sharedStrings.Add($si.InnerText)
}

function Escape-Sql($val) {
    if ($val -eq $null) { return "NULL" }
    $s = [string]$val
    if ([string]::IsNullOrWhiteSpace($s)) { return "NULL" }
    $s = $s.Replace("'", "''").Replace("\", "\\")
    return "'$s'"
}

function Get-SheetXml($sheetName) {
    $sheetNode = $wbXml.workbook.sheets.sheet | Where-Object { $_.name -eq $sheetName }
    if ($sheetNode -eq $null) { return $null }
    $target = $relMap[$sheetNode.id]
    $entry = $zip.GetEntry("xl/" + $target)
    $stream = $entry.Open()
    $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
    $xml = [xml]$reader.ReadToEnd()
    $reader.Close()
    $stream.Close()
    return $xml
}

function Get-RowCells($row) {
    $dict = @{}
    foreach ($c in $row.c) {
        $colLetter = $c.GetAttribute("r") -replace '[0-9]',''
        $t = $c.GetAttribute("t")
        $val = ""
        if ($t -eq "s") {
            $idx = [int]$c.InnerText
            if ($idx -lt $sharedStrings.Count) { $val = $sharedStrings[$idx] }
        } else {
            $val = $c.InnerText
        }
        $dict[$colLetter] = $val
    }
    return $dict
}

$sqlPath = "c:\Users\disha\OneDrive\Desktop\Cybertrace\database\03_insert_data.sql"
$writer = [System.IO.StreamWriter]::new($sqlPath, $false, [System.Text.Encoding]::UTF8)

$writer.WriteLine("-- ============================================================================")
$writer.WriteLine("-- CYBERTRACE: CYBER THREAT INTELLIGENCE PLATFORM")
$writer.WriteLine("-- Script 03: Data Loading Script (Authentic MITRE ATT&CK Enterprise Data)")
$writer.WriteLine("-- DBMS: MySQL Server 8.0 / MySQL Workbench")
$writer.WriteLine("-- ============================================================================")
$writer.WriteLine("USE cybertrace;")
$writer.WriteLine("SET FOREIGN_KEY_CHECKS = 0;")
$writer.WriteLine("")

# 1. TACTICS (All 15)
Write-Host "Exporting tactics..."
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$writer.WriteLine("-- 1. Insert Tactics (All 15 official tactical objectives)")
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$tacXml = Get-SheetXml "tactics"
for ($i = 1; $i -lt $tacXml.worksheet.sheetData.row.Count; $i++) {
    $r = $tacXml.worksheet.sheetData.row[$i]
    $d = Get-RowCells $r
    # A=ID, B=STIX ID, C=name, D=desc, E=url, F=created, G=modified, I=version
    $id = Escape-Sql $d["A"]
    $stix = Escape-Sql $d["B"]
    $name = Escape-Sql $d["C"]
    $desc = Escape-Sql $d["D"]
    $url = Escape-Sql $d["E"]
    $created = Escape-Sql $d["F"]
    $mod = Escape-Sql $d["G"]
    $ver = Escape-Sql $d["I"]
    $writer.WriteLine("INSERT INTO tactics (tactic_id, stix_id, name, description, url, created_date, last_modified_date, version) VALUES ($id, $stix, $name, $desc, $url, $created, $mod, $ver) ON DUPLICATE KEY UPDATE name=VALUES(name);")
}
$writer.WriteLine("")

# Tactic Name to ID Map for technique_tactics
$tacticNameToId = @{
    "Reconnaissance" = "TA0043"
    "Resource Development" = "TA0042"
    "Initial Access" = "TA0001"
    "Execution" = "TA0002"
    "Persistence" = "TA0003"
    "Privilege Escalation" = "TA0004"
    "Defense Evasion" = "TA0005"
    "Credential Access" = "TA0006"
    "Discovery" = "TA0007"
    "Lateral Movement" = "TA0008"
    "Collection" = "TA0009"
    "Command and Control" = "TA0011"
    "Exfiltration" = "TA0010"
    "Impact" = "TA0040"
}

# 2. TECHNIQUES
Write-Host "Exporting techniques..."
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$writer.WriteLine("-- 2. Insert Techniques (Top-level & Sub-techniques)")
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$techXml = Get-SheetXml "techniques"
$techTacticPairs = [System.Collections.Generic.List[string]]::new()

for ($i = 1; $i -lt $techXml.worksheet.sheetData.row.Count; $i++) {
    $r = $techXml.worksheet.sheetData.row[$i]
    $d = Get-RowCells $r
    # A=ID, B=STIX ID, C=name, D=desc, E=url, F=created, G=modified, I=version, J=tactics, L=is_sub, M=sub_of, O=supports_remote, P=impact_type
    $id = Escape-Sql $d["A"]
    $stix = Escape-Sql $d["B"]
    $name = Escape-Sql $d["C"]
    $desc = Escape-Sql $d["D"]
    $url = Escape-Sql $d["E"]
    $created = Escape-Sql $d["F"]
    $mod = Escape-Sql $d["G"]
    $ver = Escape-Sql $d["I"]
    $isSub = if ($d["L"] -eq "1") { 1 } else { 0 }
    $parent = Escape-Sql $d["M"]
    $remote = Escape-Sql $d["O"]
    $impact = Escape-Sql $d["P"]

    $writer.WriteLine("INSERT INTO techniques (technique_id, stix_id, name, description, url, created_date, last_modified_date, version, is_subtechnique, parent_technique_id, supports_remote, impact_type) VALUES ($id, $stix, $name, $desc, $url, $created, $mod, $ver, $isSub, $parent, $remote, $impact) ON DUPLICATE KEY UPDATE name=VALUES(name);")

    # Map tactics for junction table
    if ($d["J"]) {
        $rawTactics = $d["J"] -split ','
        foreach ($tName in $rawTactics) {
            $cleanName = $tName.Trim()
            $tacId = $tacticNameToId[$cleanName]
            if ($tacId -and $d["A"]) {
                $techTacticPairs.Add("('$($d["A"])', '$tacId')")
            }
        }
    }
}
$writer.WriteLine("")

# 3. TECHNIQUE_TACTICS
Write-Host "Exporting technique_tactics ($($techTacticPairs.Count) mappings)..."
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$writer.WriteLine("-- 3. Insert Technique-Tactic Mappings (1NF Junction Table)")
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$batchSize = 50
for ($k = 0; $k -lt $techTacticPairs.Count; $k += $batchSize) {
    $end = [Math]::Min($k + $batchSize, $techTacticPairs.Count)
    $slice = $techTacticPairs[$k..($end - 1)]
    $writer.WriteLine("INSERT IGNORE INTO technique_tactics (technique_id, tactic_id) VALUES")
    $writer.WriteLine(($slice -join ",`n") + ";")
}
$writer.WriteLine("")

# 4. SOFTWARE
Write-Host "Exporting software..."
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$writer.WriteLine("-- 4. Insert Software (Malware & Tools)")
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$softXml = Get-SheetXml "software"
for ($i = 1; $i -lt $softXml.worksheet.sheetData.row.Count; $i++) {
    $r = $softXml.worksheet.sheetData.row[$i]
    $d = Get-RowCells $r
    # A=ID, B=STIX, C=name, D=desc, E=url, F=created, G=mod, I=ver, M=type
    $id = Escape-Sql $d["A"]
    $stix = Escape-Sql $d["B"]
    $name = Escape-Sql $d["C"]
    $type = if ($d["M"] -eq "tool") { "'tool'" } else { "'malware'" }
    $desc = Escape-Sql $d["D"]
    $url = Escape-Sql $d["E"]
    $created = Escape-Sql $d["F"]
    $mod = Escape-Sql $d["G"]
    $ver = Escape-Sql $d["I"]
    $writer.WriteLine("INSERT INTO software (software_id, stix_id, name, type, description, url, created_date, last_modified_date, version) VALUES ($id, $stix, $name, $type, $desc, $url, $created, $mod, $ver) ON DUPLICATE KEY UPDATE name=VALUES(name);")
}
$writer.WriteLine("")

# 5. GROUPS & GROUP_ALIASES
Write-Host "Exporting groups..."
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$writer.WriteLine("-- 5. Insert Threat Actor Groups & Aliases")
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$grpXml = Get-SheetXml "groups"
$groupAliases = [System.Collections.Generic.List[string]]::new()
for ($i = 1; $i -lt $grpXml.worksheet.sheetData.row.Count; $i++) {
    $r = $grpXml.worksheet.sheetData.row[$i]
    $d = Get-RowCells $r
    # A=ID, B=STIX, C=name, D=desc, E=url, F=created, G=mod, I=ver, K=associated
    $id = Escape-Sql $d["A"]
    $stix = Escape-Sql $d["B"]
    $name = Escape-Sql $d["C"]
    $desc = Escape-Sql $d["D"]
    $url = Escape-Sql $d["E"]
    $created = Escape-Sql $d["F"]
    $mod = Escape-Sql $d["G"]
    $ver = Escape-Sql $d["I"]
    $writer.WriteLine("INSERT INTO `groups` (group_id, stix_id, name, description, url, created_date, last_modified_date, version) VALUES ($id, $stix, $name, $desc, $url, $created, $mod, $ver) ON DUPLICATE KEY UPDATE name=VALUES(name);")

    if ($d["K"] -and $d["A"]) {
        $aliases = $d["K"] -split ','
        foreach ($a in $aliases) {
            $cleanA = $a.Trim()
            if ($cleanA.Length -gt 0) {
                $escA = $cleanA.Replace("'", "''").Replace("\", "\\")
                $groupAliases.Add("('$($d["A"])', '$escA')")
            }
        }
    }
}
$writer.WriteLine("")

if ($groupAliases.Count -gt 0) {
    $writer.WriteLine("-- Insert Group Aliases (1NF)")
    for ($k = 0; $k -lt $groupAliases.Count; $k += 50) {
        $end = [Math]::Min($k + 50, $groupAliases.Count)
        $slice = $groupAliases[$k..($end - 1)]
        $writer.WriteLine("INSERT IGNORE INTO group_aliases (group_id, alias_name) VALUES")
        $writer.WriteLine(($slice -join ",`n") + ";")
    }
    $writer.WriteLine("")
}

# 6. CAMPAIGNS
Write-Host "Exporting campaigns..."
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$writer.WriteLine("-- 6. Insert Campaigns")
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$camXml = Get-SheetXml "campaigns"
for ($i = 1; $i -lt $camXml.worksheet.sheetData.row.Count; $i++) {
    $r = $camXml.worksheet.sheetData.row[$i]
    $d = Get-RowCells $r
    # A=ID, B=STIX, C=name, D=desc, E=url, F=created, G=mod, I=ver, L=first_seen, N=last_seen
    $id = Escape-Sql $d["A"]
    $stix = Escape-Sql $d["B"]
    $name = Escape-Sql $d["C"]
    $desc = Escape-Sql $d["D"]
    $first = Escape-Sql $d["L"]
    $last = Escape-Sql $d["N"]
    $url = Escape-Sql $d["E"]
    $created = Escape-Sql $d["F"]
    $mod = Escape-Sql $d["G"]
    $ver = Escape-Sql $d["I"]
    $writer.WriteLine("INSERT INTO campaigns (campaign_id, stix_id, name, description, first_seen, last_seen, url, created_date, last_modified_date, version) VALUES ($id, $stix, $name, $desc, $first, $last, $url, $created, $mod, $ver) ON DUPLICATE KEY UPDATE name=VALUES(name);")
}
$writer.WriteLine("")

# 7. MITIGATIONS
Write-Host "Exporting mitigations..."
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$writer.WriteLine("-- 7. Insert Mitigations")
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$mitXml = Get-SheetXml "mitigations"
for ($i = 1; $i -lt $mitXml.worksheet.sheetData.row.Count; $i++) {
    $r = $mitXml.worksheet.sheetData.row[$i]
    $d = Get-RowCells $r
    # A=ID, B=STIX, C=name, D=desc, E=url, F=created, G=mod, I=ver
    $id = Escape-Sql $d["A"]
    $stix = Escape-Sql $d["B"]
    $name = Escape-Sql $d["C"]
    $desc = Escape-Sql $d["D"]
    $url = Escape-Sql $d["E"]
    $created = Escape-Sql $d["F"]
    $mod = Escape-Sql $d["G"]
    $ver = Escape-Sql $d["I"]
    $writer.WriteLine("INSERT INTO mitigations (mitigation_id, stix_id, name, description, url, created_date, last_modified_date, version) VALUES ($id, $stix, $name, $desc, $url, $created, $mod, $ver) ON DUPLICATE KEY UPDATE name=VALUES(name);")
}
$writer.WriteLine("")

# 8. DATA COMPONENTS
Write-Host "Exporting data_components..."
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$writer.WriteLine("-- 8. Insert Data Components")
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$dcXml = Get-SheetXml "datacomponents"
for ($i = 1; $i -lt $dcXml.worksheet.sheetData.row.Count; $i++) {
    $r = $dcXml.worksheet.sheetData.row[$i]
    $d = Get-RowCells $r
    $id = Escape-Sql $d["A"]
    $stix = Escape-Sql $d["B"]
    $name = Escape-Sql $d["C"]
    $desc = Escape-Sql $d["D"]
    $url = Escape-Sql $d["E"]
    $ver = Escape-Sql $d["I"]
    $writer.WriteLine("INSERT INTO data_components (data_component_id, stix_id, name, description, url, version) VALUES ($id, $stix, $name, $desc, $url, $ver) ON DUPLICATE KEY UPDATE name=VALUES(name);")
}
$writer.WriteLine("")

# 9. RELATIONSHIPS (All 20,628 rows)
Write-Host "Exporting relationships (20,628 rows)..."
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$writer.WriteLine("-- 9. Insert Universal Threat Intelligence Graph Relationships")
$writer.WriteLine("-- ----------------------------------------------------------------------------")
$relXml = Get-SheetXml "relationships"
$relBatch = [System.Collections.Generic.List[string]]::new()

for ($i = 1; $i -lt $relXml.worksheet.sheetData.row.Count; $i++) {
    $r = $relXml.worksheet.sheetData.row[$i]
    $d = Get-RowCells $r
    # A=srcID, D=srcType, E=mapType, F=tgtID, I=tgtType, J=mapDesc, K=stixID, L=created, M=modified
    $srcId = Escape-Sql $d["A"]
    $srcType = Escape-Sql $d["D"]
    $mapType = Escape-Sql $d["E"]
    $tgtId = Escape-Sql $d["F"]
    $tgtType = Escape-Sql $d["I"]
    $desc = Escape-Sql $d["J"]
    $stix = Escape-Sql $d["K"]
    $created = Escape-Sql $d["L"]
    $mod = Escape-Sql $d["M"]

    $relBatch.Add("($srcId, $srcType, $mapType, $tgtId, $tgtType, $desc, $stix, $created, $mod)")

    if ($relBatch.Count -ge 100) {
        $writer.WriteLine("INSERT IGNORE INTO `relationships` (source_id, source_type, mapping_type, target_id, target_type, mapping_description, stix_id, created_date, last_modified_date) VALUES")
        $writer.WriteLine(($relBatch -join ",`n") + ";")
        $relBatch.Clear()
    }
}
if ($relBatch.Count -gt 0) {
    $writer.WriteLine("INSERT IGNORE INTO `relationships` (source_id, source_type, mapping_type, target_id, target_type, mapping_description, stix_id, created_date, last_modified_date) VALUES")
    $writer.WriteLine(($relBatch -join ",`n") + ";")
    $relBatch.Clear()
}
$writer.WriteLine("")

$writer.WriteLine("SET FOREIGN_KEY_CHECKS = 1;")
$writer.WriteLine("COMMIT;")
$writer.Close()

$zip.Dispose()
Remove-Item $tempZip -Force
Write-Host "03_insert_data.sql generated successfully!"
