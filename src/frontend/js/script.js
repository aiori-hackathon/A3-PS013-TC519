/**
 * ==============================================================================
 * CYBERTRACE - Cyber Threat Intelligence and Incident Correlation Platform
 * Master Frontend Controller & Data Store
 * Academic Level: Second-Year Undergraduate DBMS Academic Project
 * ==============================================================================
 */

// ==============================================================================
// 1. DATA STORE (Matches MySQL 8.0 `cybertrace` Database Schema)
// ==============================================================================

const CyberTraceData = {
    metrics: {
        totalTactics: 15,
        totalTechniques: 697,
        coreTechniques: 414,
        subTechniques: 283,
        totalSoftware: 825,
        malwareCount: 680,
        toolCount: 145,
        totalGroups: 176,
        totalCampaigns: 56,
        totalMitigations: 44,
        totalDataComponents: 106,
        totalRelationships: 20628
    },

    tactics: [
        { tactic_id: "TA0043", name: "Reconnaissance", description: "The adversary is trying to gather information they can use to plan future operations.", url: "https://attack.mitre.org/tactics/TA0043", technique_count: 86 },
        { tactic_id: "TA0042", name: "Resource Development", description: "The adversary is trying to establish resources they can use to support operations.", url: "https://attack.mitre.org/tactics/TA0042", technique_count: 42 },
        { tactic_id: "TA0001", name: "Initial Access", description: "The adversary is trying to get into your network through various entry vectors.", url: "https://attack.mitre.org/tactics/TA0001", technique_count: 53 },
        { tactic_id: "TA0002", name: "Execution", description: "The adversary is trying to run malicious code on compromised systems.", url: "https://attack.mitre.org/tactics/TA0002", technique_count: 78 },
        { tactic_id: "TA0003", name: "Persistence", description: "The adversary is trying to maintain their foothold across restarts and credential resets.", url: "https://attack.mitre.org/tactics/TA0003", technique_count: 105 },
        { tactic_id: "TA0004", name: "Privilege Escalation", description: "The adversary is trying to gain higher-level permissions like SYSTEM or root.", url: "https://attack.mitre.org/tactics/TA0004", technique_count: 89 },
        { tactic_id: "TA0005", name: "Defense Evasion", description: "The adversary is trying to avoid detection from security controls and antivirus.", url: "https://attack.mitre.org/tactics/TA0005", technique_count: 145 },
        { tactic_id: "TA0006", name: "Credential Access", description: "The adversary is trying to steal account names and passwords or hashes.", url: "https://attack.mitre.org/tactics/TA0006", technique_count: 67 },
        { tactic_id: "TA0007", name: "Discovery", description: "The adversary is trying to observe and explore the environment and network.", url: "https://attack.mitre.org/tactics/TA0007", technique_count: 72 },
        { tactic_id: "TA0008", name: "Lateral Movement", description: "The adversary is trying to move through your environment to access other systems.", url: "https://attack.mitre.org/tactics/TA0008", technique_count: 41 },
        { tactic_id: "TA0009", name: "Collection", description: "The adversary is trying to gather data of interest to their operational goal.", url: "https://attack.mitre.org/tactics/TA0009", technique_count: 58 },
        { tactic_id: "TA0011", name: "Command and Control", description: "The adversary is trying to communicate with compromised systems to control them.", url: "https://attack.mitre.org/tactics/TA0011", technique_count: 74 },
        { tactic_id: "TA0010", name: "Exfiltration", description: "The adversary is trying to steal data from your corporate or cloud network.", url: "https://attack.mitre.org/tactics/TA0010", technique_count: 39 },
        { tactic_id: "TA0040", name: "Impact", description: "The adversary is trying to manipulate, interrupt, or destroy your systems and data.", url: "https://attack.mitre.org/tactics/TA0040", technique_count: 48 }
    ],

    techniques: [
        { technique_id: "T1059", name: "Command and Scripting Interpreter", is_subtechnique: 0, parent_technique_id: null, tactics: ["Execution"], description: "Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries.", supports_remote: "Yes", version: "3.0", url: "https://attack.mitre.org/techniques/T1059" },
        { technique_id: "T1059.001", name: "PowerShell", is_subtechnique: 1, parent_technique_id: "T1059", tactics: ["Execution"], description: "Adversaries may abuse PowerShell commands and scripts for execution across Windows networks.", supports_remote: "Yes", version: "2.1", url: "https://attack.mitre.org/techniques/T1059/001" },
        { technique_id: "T1059.003", name: "Windows Command Shell", is_subtechnique: 1, parent_technique_id: "T1059", tactics: ["Execution"], description: "Adversaries may abuse the Windows command shell (cmd.exe) for execution.", supports_remote: "Yes", version: "1.3", url: "https://attack.mitre.org/techniques/T1059/003" },
        { technique_id: "T1003", name: "OS Credential Dumping", is_subtechnique: 0, parent_technique_id: null, tactics: ["Credential Access"], description: "Adversaries may dump credentials from the operating system to obtain account login secrets.", supports_remote: "No", version: "4.0", url: "https://attack.mitre.org/techniques/T1003" },
        { technique_id: "T1003.001", name: "LSASS Memory", is_subtechnique: 1, parent_technique_id: "T1003", tactics: ["Credential Access"], description: "Adversaries may strip credential material from the Local Security Authority Subsystem Service (LSASS) process.", supports_remote: "No", version: "2.2", url: "https://attack.mitre.org/techniques/T1003/001" },
        { technique_id: "T1548", name: "Abuse Elevation Control Mechanism", is_subtechnique: 0, parent_technique_id: null, tactics: ["Privilege Escalation", "Defense Evasion"], description: "Adversaries may circumvent mechanisms designed to control privilege elevation to gain higher permissions.", supports_remote: "No", version: "2.0", url: "https://attack.mitre.org/techniques/T1548" },
        { technique_id: "T1548.002", name: "Bypass User Account Control", is_subtechnique: 1, parent_technique_id: "T1548", tactics: ["Privilege Escalation", "Defense Evasion"], description: "Adversaries may bypass UAC mechanisms to elevate process privileges on system.", supports_remote: "No", version: "3.0", url: "https://attack.mitre.org/techniques/T1548/002" },
        { technique_id: "T1566", name: "Phishing", is_subtechnique: 0, parent_technique_id: null, tactics: ["Initial Access"], description: "Adversaries may send phishing messages to gain access to victim systems via spearphishing attachments or links.", supports_remote: "Yes", version: "2.5", url: "https://attack.mitre.org/techniques/T1566" },
        { technique_id: "T1078", name: "Valid Accounts", is_subtechnique: 0, parent_technique_id: null, tactics: ["Initial Access", "Persistence", "Privilege Escalation", "Defense Evasion"], description: "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access or Persistence.", supports_remote: "Yes", version: "3.1", url: "https://attack.mitre.org/techniques/T1078" },
        { technique_id: "T1021", name: "Remote Services", is_subtechnique: 0, parent_technique_id: null, tactics: ["Lateral Movement"], description: "Adversaries may use Valid Accounts to log into remote services such as RDP, SSH, or SMB.", supports_remote: "Yes", version: "2.0", url: "https://attack.mitre.org/techniques/T1021" },
        { technique_id: "T1047", name: "Windows Management Instrumentation", is_subtechnique: 0, parent_technique_id: null, tactics: ["Execution"], description: "Adversaries may abuse Windows Management Instrumentation (WMI) to execute malicious commands and payloads.", supports_remote: "Yes", version: "1.4", url: "https://attack.mitre.org/techniques/T1047" },
        { technique_id: "T1486", name: "Data Encrypted for Impact", is_subtechnique: 0, parent_technique_id: null, tactics: ["Impact"], description: "Adversaries may encrypt data on target systems or network file shares to interrupt availability as ransomware.", supports_remote: "No", version: "2.0", url: "https://attack.mitre.org/techniques/T1486" }
    ],

    software: [
        { software_id: "S0002", name: "Mimikatz", type: "tool", description: "Mimikatz is an open-source credential dumper capable of extracting plaintext passwords, hash values, and Kerberos tickets.", version: "3.2", url: "https://attack.mitre.org/software/S0002", techniques_count: 24 },
        { software_id: "S0154", name: "Cobalt Strike", type: "tool", description: "Cobalt Strike is a commercial penetration testing tool widely abused by adversaries for interactive post-exploitation beacons.", version: "4.1", url: "https://attack.mitre.org/software/S0154", techniques_count: 58 },
        { software_id: "S0066", name: "3PARA RAT", type: "malware", description: "3PARA RAT is a remote access tool used by adversary groups for persistence and remote command execution.", version: "1.1", url: "https://attack.mitre.org/software/S0066", techniques_count: 12 },
        { software_id: "S0065", name: "4H RAT", type: "malware", description: "4H RAT is malware used by threat actors to perform system discovery and stage lateral movement.", version: "1.1", url: "https://attack.mitre.org/software/S0065", techniques_count: 9 },
        { software_id: "S0029", name: "PsExec", type: "tool", description: "PsExec is a legitimate Sysinternals utility used for executing processes on other systems.", version: "1.2", url: "https://attack.mitre.org/software/S0029", techniques_count: 15 },
        { software_id: "S0484", name: "Carbanak", type: "malware", description: "Carbanak is malware used primarily for financial fraud targeting banks and retail networks.", version: "2.0", url: "https://attack.mitre.org/software/S0484", techniques_count: 36 }
    ],

    groups: [
        { group_id: "G0007", name: "APT28", aliases: ["Fancy Bear", "Sednit", "Sofacy", "STRONTIUM"], description: "APT28 is a threat group attributed to Russia's GRU Main Directorate. Active since at least 2004 targeting government, military, and corporate networks.", version: "3.0", url: "https://attack.mitre.org/groups/G0007", techniques_count: 78 },
        { group_id: "G0034", name: "Sandworm Team", aliases: ["TeleBots", "BlackEnergy", "Voodoo Bear", "IRON VIKING"], description: "Sandworm Team is a Russian state-sponsored cyber espionage group linked to destructive attacks against Ukrainian energy infrastructure.", version: "2.4", url: "https://attack.mitre.org/groups/G0034", techniques_count: 92 },
        { group_id: "G0032", name: "Lazarus Group", aliases: ["HIDDEN COBRA", "Guardians of Peace", "ZINC"], description: "Lazarus Group is a North Korean state-sponsored threat group active since at least 2009 responsible for major cyber heists and ransomware operations.", version: "3.1", url: "https://attack.mitre.org/groups/G0032", techniques_count: 114 },
        { group_id: "G0099", name: "APT-C-36", aliases: ["Blind Eagle", "AguilaCiega"], description: "APT-C-36 is a suspected South American espionage group operating against Colombian government and financial institutions.", version: "2.0", url: "https://attack.mitre.org/groups/G0099", techniques_count: 34 },
        { group_id: "G0046", name: "FIN7", aliases: ["Carbanak Group"], description: "FIN7 is a financially motivated threat group that has engaged in point-of-sale malware campaigns and enterprise ransomware.", version: "2.2", url: "https://attack.mitre.org/groups/G0046", techniques_count: 51 }
    ],

    campaigns: [
        { campaign_id: "C0028", name: "2015 Ukraine Electric Power Attack", attributed_group: "Sandworm Team (G0034)", first_seen: "01 December 2015", last_seen: "01 January 2016", description: "Destructive cyber attack targeting multiple Ukrainian regional electricity distribution companies, causing power outages for over 225,000 customers.", version: "1.0", url: "https://attack.mitre.org/campaigns/C0028" },
        { campaign_id: "C0025", name: "2016 Ukraine Electric Power Attack", attributed_group: "Sandworm Team (G0034)", first_seen: "01 December 2016", last_seen: "01 December 2016", description: "Attack on the Pivnichna electrical substation in Ukraine deploying the Industroyer/Crashoverride malware.", version: "1.0", url: "https://attack.mitre.org/campaigns/C0025" },
        { campaign_id: "C0024", name: "SolarWinds Compromise", attributed_group: "APT29 (G0016)", first_seen: "01 March 2020", last_seen: "01 December 2020", description: "Supply chain attack that inserted the SUNBURST backdoor into updates for SolarWinds Orion IT monitoring software.", version: "1.2", url: "https://attack.mitre.org/campaigns/C0024" },
        { campaign_id: "C0057", name: "3CX Supply Chain Attack", attributed_group: "AppleJeus (G1049)", first_seen: "01 March 2023", last_seen: "01 April 2023", description: "Supply chain attack that compromised the installation packages of the 3CX desktop voice and video client.", version: "1.0", url: "https://attack.mitre.org/campaigns/C0057" }
    ],

    mitigations: [
        { mitigation_id: "M1036", name: "Account Use Policies", description: "Configure policies and settings to restrict the use of certain types of accounts such as service or administrator accounts to authorized systems.", url: "https://attack.mitre.org/mitigations/M1036", version: "1.1" },
        { mitigation_id: "M1015", name: "Active Directory Configuration", description: "Implement robust Active Directory (AD) configurations using group policies to secure domain controllers and trusts.", url: "https://attack.mitre.org/mitigations/M1015", version: "1.2" },
        { mitigation_id: "M1032", name: "Multi-factor Authentication", description: "Require a two-factor or multi-factor authentication method for accessing sensitive systems, administrative interfaces, and external portals.", url: "https://attack.mitre.org/mitigations/M1032", version: "2.0" },
        { mitigation_id: "M1030", name: "Network Segmentation", description: "Architecturally divide networks into distinct security zones to restrict lateral movement between sensitive segments.", url: "https://attack.mitre.org/mitigations/M1030", version: "1.3" },
        { mitigation_id: "M1026", name: "Privileged Account Management", description: "Manage the creation, modification, use, and permissions associated with privileged accounts to enforce least privilege.", url: "https://attack.mitre.org/mitigations/M1026", version: "1.2" }
    ],

    detection_strategies: [
        { strategy_id: "DET0103", name: "Behavioral Detection of Network Share Connection Removal via CLI and SMB Disconnects", url: "https://attack.mitre.org", version: "1.0" },
        { strategy_id: "DET0001", name: "Process Creation Monitoring for Malicious Scripting Interpreters", url: "https://attack.mitre.org", version: "1.0" },
        { strategy_id: "DET0015", name: "Anomalous LSASS Memory Read and Handle Requests", url: "https://attack.mitre.org", version: "1.1" }
    ],

    data_components: [
        { data_component_id: "DC0067", name: "Logon Session Creation", description: "Telemetry detailing user logon session initialization events (Windows EventCode 4624, 4648).", version: "2.0" },
        { data_component_id: "DC0032", name: "Process Creation", description: "System logging capturing binary execution, parent-child process relationships, and command line arguments (Sysmon EventCode 1, 4688).", version: "2.0" },
        { data_component_id: "DC0064", name: "Command Execution", description: "PowerShell and script block logging capturing executed command syntax (Windows EventCode 4103, 4104).", version: "2.0" },
        { data_component_id: "DC0103", name: "Active DNS", description: "DNS query resolution logs monitoring requested domains and returned IP addresses.", version: "2.0" }
    ],

    relationships: [
        { source_id: "S0002", source_name: "Mimikatz", source_type: "software", mapping_type: "uses", target_id: "T1003", target_name: "OS Credential Dumping", target_type: "technique", description: "Mimikatz extracts plaintext passwords, hash values, and Kerberos tickets from memory." },
        { source_id: "S0002", source_name: "Mimikatz", source_type: "software", mapping_type: "uses", target_id: "T1003.001", target_name: "LSASS Memory", target_type: "technique", description: "Mimikatz dumps password hashes directly by reading LSASS process memory." },
        { source_id: "G0007", source_name: "APT28", source_type: "group", mapping_type: "uses", target_id: "T1059.001", target_name: "PowerShell", target_type: "technique", description: "APT28 has executed PowerShell scripts to download payloads and execute commands." },
        { source_id: "G0007", source_name: "APT28", source_type: "group", mapping_type: "uses", target_id: "S0002", target_name: "Mimikatz", target_type: "software", description: "APT28 has deployed Mimikatz to harvest credentials on compromised victim endpoints." },
        { source_id: "G0034", source_name: "Sandworm Team", source_type: "group", mapping_type: "uses", target_id: "T1486", target_name: "Data Encrypted for Impact", target_type: "technique", description: "Sandworm Team utilized ransomware components during destructive attacks in Ukraine." },
        { source_id: "C0028", source_name: "2015 Ukraine Electric Power Attack", source_type: "campaign", mapping_type: "attributed-to", target_id: "G0034", target_name: "Sandworm Team", target_type: "group", description: "The 2015 Ukrainian electrical power outage campaign was formally attributed to Sandworm Team." },
        { source_id: "M1032", source_name: "Multi-factor Authentication", source_type: "mitigation", mapping_type: "mitigates", target_id: "T1078", target_name: "Valid Accounts", target_type: "technique", description: "MFA prevents adversaries from authenticating with compromised credentials alone." },
        { source_id: "DET0103", source_name: "Behavioral Detection of Share Removal", source_type: "detectionstrategy", mapping_type: "detects", target_id: "T1059", target_name: "Command and Scripting Interpreter", target_type: "technique", description: "Detects command interpreter execution used to disconnect network shares." }
    ]
};

// ==============================================================================
// 2. FUTURE BACKEND REST API PROVIDER (Architecture for Phase 3)
// ==============================================================================
/**
 * In Phase 3, each method below will execute real fetch() HTTP calls to Flask:
 *   const res = await fetch('/api/techniques');
 *   return await res.json();
 * For Phase 2, it delivers clean demonstration data conforming to the MySQL schema.
 */
const CyberTraceAPI = {
    async getMetrics() {
        return CyberTraceData.metrics;
    },
    async getTactics() {
        return CyberTraceData.tactics;
    },
    async getTechniques(filter = {}) {
        let items = CyberTraceData.techniques;
        if (filter.tactic) {
            items = items.filter(t => t.tactics && t.tactics.includes(filter.tactic));
        }
        if (filter.search) {
            const q = filter.search.toLowerCase();
            items = items.filter(t => t.technique_id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q));
        }
        if (filter.subtechnique !== undefined && filter.subtechnique !== "all") {
            const isSub = filter.subtechnique === "1" ? 1 : 0;
            items = items.filter(t => t.is_subtechnique === isSub);
        }
        return items;
    },
    async getSoftware(filter = {}) {
        let items = CyberTraceData.software;
        if (filter.type && filter.type !== "all") {
            items = items.filter(s => s.type === filter.type);
        }
        if (filter.search) {
            const q = filter.search.toLowerCase();
            items = items.filter(s => s.software_id.toLowerCase().includes(q) || s.name.toLowerCase().includes(q));
        }
        return items;
    },
    async getGroups(filter = {}) {
        let items = CyberTraceData.groups;
        if (filter.search) {
            const q = filter.search.toLowerCase();
            items = items.filter(g => g.group_id.toLowerCase().includes(q) || g.name.toLowerCase().includes(q) || (g.aliases && g.aliases.some(a => a.toLowerCase().includes(q))));
        }
        return items;
    },
    async getCampaigns(filter = {}) {
        let items = CyberTraceData.campaigns;
        if (filter.search) {
            const q = filter.search.toLowerCase();
            items = items.filter(c => c.campaign_id.toLowerCase().includes(q) || c.name.toLowerCase().includes(q));
        }
        return items;
    },
    async getMitigations(filter = {}) {
        let items = CyberTraceData.mitigations;
        if (filter.search) {
            const q = filter.search.toLowerCase();
            items = items.filter(m => m.mitigation_id.toLowerCase().includes(q) || m.name.toLowerCase().includes(q));
        }
        return items;
    },
    async getRelationships(filter = {}) {
        let items = CyberTraceData.relationships;
        if (filter.source_type && filter.source_type !== "all") {
            items = items.filter(r => r.source_type === filter.source_type);
        }
        if (filter.mapping_type && filter.mapping_type !== "all") {
            items = items.filter(r => r.mapping_type === filter.mapping_type);
        }
        if (filter.search) {
            const q = filter.search.toLowerCase();
            items = items.filter(r => r.source_name.toLowerCase().includes(q) || r.target_name.toLowerCase().includes(q) || r.source_id.toLowerCase().includes(q) || r.target_id.toLowerCase().includes(q));
        }
        return items;
    }
};

// ==============================================================================
// 3. PAGE INITIALIZATION ROUTERS
// ==============================================================================

document.addEventListener("DOMContentLoaded", () => {
    // Determine active page by checking body or elements
    const pageId = document.body.dataset.page;
    switch (pageId) {
        case "login":
            initLoginPage();
            break;
        case "dashboard":
            initDashboardPage();
            break;
        case "techniques":
            initTechniquesPage();
            break;
        case "tactics":
            initTacticsPage();
            break;
        case "software":
            initSoftwarePage();
            break;
        case "groups":
            initGroupsPage();
            break;
        case "campaigns":
            initCampaignsPage();
            break;
        case "mitigations":
            initMitigationsPage();
            break;
        case "detection-strategies":
            initDetectionStrategiesPage();
            break;
        case "data-components":
            initDataComponentsPage();
            break;
        case "relationships":
            initRelationshipsPage();
            break;
        case "analytics":
            initAnalyticsPage();
            break;
    }

    // Attach global quick search if present in navbar
    const globalSearchForm = document.getElementById("globalSearchForm");
    if (globalSearchForm) {
        globalSearchForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const q = document.getElementById("globalSearchInput")?.value.trim();
            if (q) {
                window.location.href = `techniques.html?search=${encodeURIComponent(q)}`;
            }
        });
    }
});

// ==============================================================================
// 4. MODULE CONTROLLERS
// ==============================================================================

// --- LOGIN PAGE ---
function initLoginPage() {
    const loginForm = document.getElementById("loginForm");
    const errorAlert = document.getElementById("loginAlert");

    if (!loginForm) return;

    loginForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const username = document.getElementById("username").value.trim();
        const password = document.getElementById("password").value.trim();

        if (!username || !password) {
            showError("Please enter both username and password.");
            return;
        }

        // Demonstration Login check: Accepts analyst/admin credentials
        if (username.length >= 3 && password.length >= 4) {
            sessionStorage.setItem("cybertrace_user", username);
            sessionStorage.setItem("cybertrace_role", "Cybersecurity Analyst");
            window.location.href = "dashboard.html";
        } else {
            showError("Invalid credentials. Try: admin / cybertrace");
        }
    });

    function showError(msg) {
        if (errorAlert) {
            errorAlert.textContent = msg;
            errorAlert.classList.remove("d-none");
        }
    }
}

// --- DASHBOARD PAGE ---
async function initDashboardPage() {
    const metrics = await CyberTraceAPI.getMetrics();
    
    // Populate cards
    setText("statTechniques", metrics.totalTechniques);
    setText("statTactics", metrics.totalTactics);
    setText("statSoftware", metrics.totalSoftware);
    setText("statGroups", metrics.totalGroups);
    setText("statCampaigns", metrics.totalCampaigns);
    setText("statMitigations", metrics.totalMitigations);
    setText("statRelationships", metrics.totalRelationships.toLocaleString());

    // Populate Top Groups Table
    const groupsTable = document.getElementById("dashboardGroupsTable");
    if (groupsTable) {
        const groups = await CyberTraceAPI.getGroups();
        groupsTable.innerHTML = groups.slice(0, 5).map(g => `
            <tr>
                <td><span class="badge badge-tech-id">${g.group_id}</span></td>
                <td><strong>${g.name}</strong></td>
                <td>${g.aliases ? g.aliases.slice(0, 2).join(', ') : 'None'}</td>
                <td><span class="badge bg-primary">${g.techniques_count} techniques</span></td>
                <td><a href="groups.html" class="btn btn-sm btn-outline-secondary">View</a></td>
            </tr>
        `).join('');
    }

    // Populate Top Techniques Table
    const techniquesTable = document.getElementById("dashboardTechniquesTable");
    if (techniquesTable) {
        const techniques = await CyberTraceAPI.getTechniques();
        techniquesTable.innerHTML = techniques.slice(0, 5).map(t => `
            <tr>
                <td><span class="badge badge-tech-id">${t.technique_id}</span></td>
                <td><strong>${t.name}</strong></td>
                <td>${t.tactics.join(', ')}</td>
                <td><span class="badge ${t.is_subtechnique ? 'badge-subtechnique' : 'bg-light text-dark'}">${t.is_subtechnique ? 'Sub-technique' : 'Core'}</span></td>
                <td><a href="techniques.html?search=${t.technique_id}" class="btn btn-sm btn-outline-secondary">Details</a></td>
            </tr>
        `).join('');
    }
}

// --- TECHNIQUES PAGE ---
async function initTechniquesPage() {
    const tableBody = document.getElementById("techniquesTableBody");
    const searchInput = document.getElementById("techSearch");
    const tacticFilter = document.getElementById("techTacticFilter");
    const subFilter = document.getElementById("techSubFilter");
    const resultCount = document.getElementById("techCount");

    // Populate tactic filter dropdown
    if (tacticFilter) {
        const tactics = await CyberTraceAPI.getTactics();
        tactics.forEach(tac => {
            const opt = document.createElement("option");
            opt.value = tac.name;
            opt.textContent = tac.name;
            tacticFilter.appendChild(opt);
        });
    }

    // Check URL parameters for direct search
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get("search") && searchInput) {
        searchInput.value = urlParams.get("search");
    }

    async function render() {
        const items = await CyberTraceAPI.getTechniques({
            search: searchInput?.value,
            tactic: tacticFilter?.value,
            subtechnique: subFilter?.value
        });

        if (resultCount) resultCount.textContent = `${items.length} techniques displayed`;

        if (!tableBody) return;

        if (items.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No techniques found matching your criteria.</td></tr>`;
            return;
        }

        tableBody.innerHTML = items.map(t => `
            <tr>
                <td><span class="badge badge-tech-id">${t.technique_id}</span></td>
                <td><strong>${t.name}</strong></td>
                <td>${t.tactics ? t.tactics.map(tac => `<span class="badge bg-secondary me-1">${tac}</span>`).join('') : ''}</td>
                <td>${t.is_subtechnique ? `<span class="badge badge-subtechnique">Sub-technique (${t.parent_technique_id})</span>` : '<span class="badge bg-light text-dark border">Core Technique</span>'}</td>
                <td>${t.supports_remote ? `<span class="badge bg-info text-dark">${t.supports_remote}</span>` : '<span class="text-muted">Local</span>'}</td>
                <td>
                    <button class="btn btn-sm btn-outline-primary" onclick="showTechniqueModal('${t.technique_id}')">
                        <i class="bi bi-eye"></i> Details
                    </button>
                </td>
            </tr>
        `).join('');
    }

    searchInput?.addEventListener("input", render);
    tacticFilter?.addEventListener("change", render);
    subFilter?.addEventListener("change", render);

    render();
}

// Modal helper for technique details
window.showTechniqueModal = function(techId) {
    const t = CyberTraceData.techniques.find(item => item.technique_id === techId);
    if (!t) return;

    setText("modalTechId", t.technique_id);
    setText("modalTechName", t.name);
    setText("modalTechDesc", t.description);
    setText("modalTechTactics", t.tactics.join(', '));
    setText("modalTechType", t.is_subtechnique ? `Sub-technique of ${t.parent_technique_id}` : "Core Primary Technique");
    setText("modalTechRemote", t.supports_remote || "Not specified");
    setText("modalTechVersion", t.version);
    
    const linkElem = document.getElementById("modalTechUrl");
    if (linkElem) linkElem.href = t.url;

    const modal = new bootstrap.Modal(document.getElementById("techniqueDetailModal"));
    modal.show();
};

// --- TACTICS PAGE ---
async function initTacticsPage() {
    const container = document.getElementById("tacticsContainer");
    const tactics = await CyberTraceAPI.getTactics();

    if (!container) return;

    container.innerHTML = tactics.map(tac => `
        <div class="col-md-6 col-lg-4 mb-4">
            <div class="card h-100 shadow-sm border">
                <div class="card-header bg-white d-flex justify-content-between align-items-center">
                    <span class="badge badge-tech-id">${tac.tactic_id}</span>
                    <span class="badge bg-primary">${tac.technique_count} Techniques</span>
                </div>
                <div class="card-body">
                    <h5 class="card-title text-primary">${tac.name}</h5>
                    <p class="card-text text-muted small">${tac.description}</p>
                </div>
                <div class="card-footer bg-white border-0 pt-0">
                    <a href="techniques.html?search=${encodeURIComponent(tac.name)}" class="btn btn-sm btn-outline-primary w-100">
                        View Associated Techniques
                    </a>
                </div>
            </div>
        </div>
    `).join('');
}

// --- SOFTWARE PAGE ---
async function initSoftwarePage() {
    const tableBody = document.getElementById("softwareTableBody");
    const searchInput = document.getElementById("softwareSearch");
    const typeFilter = document.getElementById("softwareTypeFilter");

    async function render() {
        const items = await CyberTraceAPI.getSoftware({
            search: searchInput?.value,
            type: typeFilter?.value
        });

        if (!tableBody) return;

        if (items.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-muted">No software found.</td></tr>`;
            return;
        }

        tableBody.innerHTML = items.map(s => `
            <tr>
                <td><span class="badge badge-tech-id">${s.software_id}</span></td>
                <td><strong>${s.name}</strong></td>
                <td><span class="badge ${s.type === 'malware' ? 'badge-malware' : 'badge-tool'}">${s.type.toUpperCase()}</span></td>
                <td><p class="text-muted small mb-0">${s.description}</p></td>
                <td><span class="badge bg-secondary">${s.techniques_count || 0} techniques</span></td>
            </tr>
        `).join('');
    }

    searchInput?.addEventListener("input", render);
    typeFilter?.addEventListener("change", render);
    render();
}

// --- GROUPS PAGE ---
async function initGroupsPage() {
    const tableBody = document.getElementById("groupsTableBody");
    const searchInput = document.getElementById("groupsSearch");

    async function render() {
        const items = await CyberTraceAPI.getGroups({ search: searchInput?.value });

        if (!tableBody) return;

        if (items.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-muted">No threat groups found.</td></tr>`;
            return;
        }

        tableBody.innerHTML = items.map(g => `
            <tr>
                <td><span class="badge badge-tech-id">${g.group_id}</span></td>
                <td><strong>${g.name}</strong></td>
                <td>${g.aliases ? g.aliases.map(a => `<span class="badge bg-light text-dark border me-1">${a}</span>`).join('') : '<span class="text-muted">None</span>'}</td>
                <td><p class="text-muted small mb-0">${g.description}</p></td>
                <td><span class="badge bg-primary">${g.techniques_count || 0} techniques</span></td>
            </tr>
        `).join('');
    }

    searchInput?.addEventListener("input", render);
    render();
}

// --- CAMPAIGNS PAGE ---
async function initCampaignsPage() {
    const tableBody = document.getElementById("campaignsTableBody");
    const searchInput = document.getElementById("campaignsSearch");

    async function render() {
        const items = await CyberTraceAPI.getCampaigns({ search: searchInput?.value });

        if (!tableBody) return;

        if (items.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No campaigns found.</td></tr>`;
            return;
        }

        tableBody.innerHTML = items.map(c => `
            <tr>
                <td><span class="badge badge-tech-id">${c.campaign_id}</span></td>
                <td><strong>${c.name}</strong></td>
                <td><span class="badge bg-dark">${c.attributed_group || 'Unattributed'}</span></td>
                <td>${c.first_seen || 'Unknown'}</td>
                <td>${c.last_seen || 'Ongoing'}</td>
                <td><p class="text-muted small mb-0">${c.description}</p></td>
            </tr>
        `).join('');
    }

    searchInput?.addEventListener("input", render);
    render();
}

// --- MITIGATIONS PAGE ---
async function initMitigationsPage() {
    const tableBody = document.getElementById("mitigationsTableBody");
    const searchInput = document.getElementById("mitigationsSearch");

    async function render() {
        const items = await CyberTraceAPI.getMitigations({ search: searchInput?.value });

        if (!tableBody) return;

        if (items.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-muted">No mitigations found.</td></tr>`;
            return;
        }

        tableBody.innerHTML = items.map(m => `
            <tr>
                <td><span class="badge badge-tech-id">${m.mitigation_id}</span></td>
                <td><strong>${m.name}</strong></td>
                <td><p class="text-muted small mb-0">${m.description}</p></td>
                <td><a href="${m.url}" target="_blank" class="btn btn-sm btn-outline-secondary"><i class="bi bi-box-arrow-up-right"></i> MITRE</a></td>
            </tr>
        `).join('');
    }

    searchInput?.addEventListener("input", render);
    render();
}

// --- DETECTION STRATEGIES PAGE ---
function initDetectionStrategiesPage() {
    const tableBody = document.getElementById("detectionStrategiesTableBody");
    if (!tableBody) return;

    tableBody.innerHTML = CyberTraceData.detection_strategies.map(d => `
        <tr>
            <td><span class="badge badge-tech-id">${d.strategy_id}</span></td>
            <td><strong>${d.name}</strong></td>
            <td>v${d.version}</td>
            <td><a href="${d.url}" target="_blank" class="btn btn-sm btn-outline-secondary">View Spec</a></td>
        </tr>
    `).join('');
}

// --- DATA COMPONENTS PAGE ---
function initDataComponentsPage() {
    const tableBody = document.getElementById("dataComponentsTableBody");
    if (!tableBody) return;

    tableBody.innerHTML = CyberTraceData.data_components.map(dc => `
        <tr>
            <td><span class="badge badge-tech-id">${dc.data_component_id}</span></td>
            <td><strong>${dc.name}</strong></td>
            <td><p class="text-muted small mb-0">${dc.description}</p></td>
            <td>v${dc.version}</td>
        </tr>
    `).join('');
}

// --- RELATIONSHIPS PAGE ---
async function initRelationshipsPage() {
    const tableBody = document.getElementById("relationshipsTableBody");
    const searchInput = document.getElementById("relSearch");
    const srcFilter = document.getElementById("relSourceFilter");
    const mapFilter = document.getElementById("relMappingFilter");

    async function render() {
        const items = await CyberTraceAPI.getRelationships({
            search: searchInput?.value,
            source_type: srcFilter?.value,
            mapping_type: mapFilter?.value
        });

        if (!tableBody) return;

        if (items.length === 0) {
            tableBody.innerHTML = `<tr><td colspan="6" class="text-center py-4 text-muted">No relationships found.</td></tr>`;
            return;
        }

        tableBody.innerHTML = items.map(r => `
            <tr>
                <td><strong>${r.source_name}</strong> <span class="badge badge-tech-id ms-1">${r.source_id}</span></td>
                <td><span class="badge bg-secondary">${r.source_type}</span></td>
                <td><span class="badge bg-primary font-monospace">${r.mapping_type.toUpperCase()}</span></td>
                <td><strong>${r.target_name}</strong> <span class="badge badge-tech-id ms-1">${r.target_id}</span></td>
                <td><span class="badge bg-info text-dark">${r.target_type}</span></td>
                <td><small class="text-muted">${r.description || 'Verified relationship'}</small></td>
            </tr>
        `).join('');
    }

    searchInput?.addEventListener("input", render);
    srcFilter?.addEventListener("change", render);
    mapFilter?.addEventListener("change", render);
    render();
}

// --- ANALYTICS PAGE ---
async function initAnalyticsPage() {
    const metrics = await CyberTraceAPI.getMetrics();
    
    setText("analyticsTechniques", metrics.totalTechniques);
    setText("analyticsSoftware", metrics.totalSoftware);
    setText("analyticsGroups", metrics.totalGroups);
    setText("analyticsRelationships", metrics.totalRelationships.toLocaleString());

    // Populate Tactic Distribution Table
    const tacticDistTable = document.getElementById("analyticsTacticTable");
    if (tacticDistTable) {
        const tactics = await CyberTraceAPI.getTactics();
        const maxCount = Math.max(...tactics.map(t => t.technique_count));
        
        tacticDistTable.innerHTML = tactics.map(tac => {
            const pct = Math.round((tac.technique_count / maxCount) * 100);
            return `
                <tr>
                    <td><strong>${tac.name}</strong></td>
                    <td class="text-end fw-bold">${tac.technique_count}</td>
                    <td style="width: 50%;">
                        <div class="progress" style="height: 14px;">
                            <div class="progress-bar bg-primary" role="progressbar" style="width: ${pct}%;" aria-valuenow="${pct}" aria-valuemin="0" aria-valuemax="100"></div>
                        </div>
                    </td>
                </tr>
            `;
        }).join('');
    }
}

// Utility function to safely set element text
function setText(id, text) {
    const elem = document.getElementById(id);
    if (elem) elem.textContent = text;
}
