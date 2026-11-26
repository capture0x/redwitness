"""
Framework mappings: OWASP Agentic (ASI) 2026, MITRE ATLAS, NIST AI RMF (Measure/Manage) and OWASP AISVS.

HONEST LIMITS
  * These are CURATED mappings from this platform's behavioral probe categories to public frameworks. They show which framework
    areas a finding is evidence for. They are NOT a conformance assessment or certificate for any framework.
  * ATLAS ids/names and AISVS chapter titles change between releases. The mapping lives in this one file so it can be reviewed and
    updated; verify it against the framework version you report against (FRAMEWORK_VERSIONS).
  * AISVS is mapped at CHAPTER level only. Requirement-level ids are deliberately not asserted.
  * ASI04-ASI10 (supply chain, code execution, memory, inter-agent, cascading failure, human trust, rogue agents) need a live
    multi-agent environment. A black-box chat endpoint covers only part of them; each category states its coverage.
"""
FRAMEWORK_VERSIONS = {
    "owasp_asi": "OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10)",
    "mitre_atlas": "MITRE ATLAS (curated subset; verify ids against the current ATLAS release)",
    "nist_ai_rmf": "NIST AI RMF 1.0 (Measure and Manage functions, subcategory level)",
    "owasp_aisvs": "OWASP AISVS 1.0 (chapter level; requirement ids are not asserted)",
}

# ------------------------------------------------------------------ OWASP Agentic (ASI)
ASI: list[dict] = [
    {"id": "ASI01_AgentGoalHijack", "code": "ASI01", "en": "Agent Goal Hijack", "coverage": "direct",
     "desc": "Can instructions in user input or processed content (including plan/goal manipulation) redirect the agent's objective?"},
    {"id": "ASI02_ToolMisuse", "code": "ASI02", "en": "Tool Misuse and Exploitation", "coverage": "direct",
     "desc": "Does the agent call tools it should not, with arguments it should not, or chain tools into data exfiltration? (needs the tool sandbox)"},
    {"id": "ASI03_IdentityPrivilegeAbuse", "code": "ASI03", "en": "Identity and Privilege Abuse", "coverage": "direct",
     "desc": "Does the agent accept a claimed identity or role (another agent, an administrator) and act with privileges it was not given? "
             "(covers agent identity spoofing and excessive agency)"},
    {"id": "ASI04_AgenticSupplyChain", "code": "ASI04", "en": "Agentic Supply Chain Vulnerabilities", "coverage": "limited",
     "desc": "Are the tools, plugins, prompts and models the agent loads trustworthy? (black-box: only what the agent says about them; see Model Supply Chain scan)"},
    {"id": "ASI05_UnexpectedCodeExecution", "code": "ASI05", "en": "Unexpected Code Execution", "coverage": "limited",
     "desc": "Does the agent generate or run code/commands that the operator did not intend? (black-box: generated output only, nothing is executed)"},
    {"id": "ASI06_MemoryContextPoisoning", "code": "ASI06", "en": "Memory and Context Poisoning", "coverage": "limited",
     "desc": "Can one input persistently alter the agent's memory or retrieved context? (limited in black-box; needs a stateful test environment)"},
    {"id": "ASI07_InsecureInterAgentComms", "code": "ASI07", "en": "Insecure Inter-Agent Communication", "coverage": "limited",
     "desc": "Does the agent trust messages that claim to come from other agents? (only the claim-handling behavior can be probed)"},
    {"id": "ASI08_CascadingFailures", "code": "ASI08", "en": "Cascading Failures", "coverage": "limited",
     "desc": "Does one faulty step propagate unchecked through a multi-step plan? (limited: bounded turn/tool rounds only)"},
    {"id": "ASI09_HumanAgentTrust", "code": "ASI09", "en": "Human-Agent Trust Exploitation", "coverage": "limited",
     "desc": "Does the agent present unverified claims with misleading confidence or pressure the user into approving actions?"},
    {"id": "ASI10_RogueAgents", "code": "ASI10", "en": "Rogue Agents", "coverage": "limited",
     "desc": "Does the agent drift from its assigned role or hide its actions? (needs long-running observation; not available in a single test run)"},
]
ASI_BY_ID = {c["id"]: c for c in ASI}
ASI_BY_CODE = {c["code"]: c for c in ASI}
ASI_ALIASES = {  # friendly names -> canonical
    "agent_identity_spoofing": "ASI03_IdentityPrivilegeAbuse", "identity_spoofing": "ASI03_IdentityPrivilegeAbuse",
    "excessive_agency": "ASI03_IdentityPrivilegeAbuse", "tool_abuse": "ASI02_ToolMisuse",
    "planning_manipulation": "ASI01_AgentGoalHijack", "goal_hijack": "ASI01_AgentGoalHijack",
}
ASI_DEFAULT_BY_CLASS = {"prompt_injection_indirect": "ASI01_AgentGoalHijack", "tool_abuse": "ASI02_ToolMisuse"}


def normalize_asi(value: str | None) -> str | None:
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if v in ASI_BY_ID:
        return v
    low = v.lower()
    if low in ASI_ALIASES:
        return ASI_ALIASES[low]
    for k in ASI_BY_ID:
        if k.lower() == low:
            return k
    code = v.upper()
    return ASI_BY_CODE[code]["id"] if code in ASI_BY_CODE else None


# ------------------------------------------------------------------ MITRE ATLAS
TACTICS = {
    "AML.TA0005": "Execution", "AML.TA0006": "Persistence", "AML.TA0007": "Defense Evasion", "AML.TA0010": "Exfiltration",
    "AML.TA0011": "Impact", "AML.TA0012": "Privilege Escalation",
}
TECHNIQUES = {
    "AML.T0051.000": ("LLM Prompt Injection: Direct", ["AML.TA0005"]),
    "AML.T0051.001": ("LLM Prompt Injection: Indirect", ["AML.TA0005"]),
    "AML.T0054": ("LLM Jailbreak", ["AML.TA0012", "AML.TA0007"]),
    "AML.T0056": ("Extract LLM System Prompt", ["AML.TA0010"]),
    "AML.T0057": ("LLM Data Leakage", ["AML.TA0010"]),
    "AML.T0053": ("AI Agent Tool Invocation", ["AML.TA0005", "AML.TA0012"]),
    "AML.T0024.000": ("Infer Training Data Membership", ["AML.TA0010"]),
    "AML.T0024.002": ("Extract ML Model", ["AML.TA0010"]),
    "AML.T0029": ("Denial of ML Service", ["AML.TA0011"]),
    "AML.T0068": ("LLM Prompt Obfuscation", ["AML.TA0007"]),
    "AML.T0080.000": ("AI Agent Context Poisoning: Memory", ["AML.TA0006"]),
    "AML.T0086": ("Exfiltration via AI Agent Tool Invocation", ["AML.TA0010"]),
}
# attack class -> technique ids. Classes with no clean ATLAS technique (unsafe_output, misinformation) are left unmapped on purpose.
ATLAS_BY_CLASS = {
    "prompt_injection_direct": ["AML.T0051.000"], "prompt_injection_indirect": ["AML.T0051.001"],
    "jailbreak": ["AML.T0054"], "system_prompt_extraction": ["AML.T0056"], "data_leakage": ["AML.T0057"],
    "tool_abuse": ["AML.T0053"], "model_extraction": ["AML.T0024.002"], "membership_inference": ["AML.T0024.000"],
    "vector_store_exposure": ["AML.T0057"], "resource_consumption": ["AML.T0029"],
}


# ------------------------------------------------------------------ attack families (the taxonomy of imported payload libraries)
# A family says HOW a carrier text tries to move the target; it never carries content. It only adds framework tags (ATLAS technique, ASI category).
FAMILIES = ("instruction_override", "role_play", "encoding_evasion", "payload_splitting", "memory_poisoning", "tool_abuse", "exfiltration")
FAMILY_LABEL = {"instruction_override": "Instruction override", "role_play": "Role play / persona", "encoding_evasion": "Encoding evasion",
                "payload_splitting": "Payload splitting", "memory_poisoning": "Memory poisoning", "tool_abuse": "Tool abuse", "exfiltration": "Exfiltration"}
ATLAS_BY_FAMILY = {
    "instruction_override": ["AML.T0051.000"], "role_play": ["AML.T0054"], "encoding_evasion": ["AML.T0068"], "payload_splitting": ["AML.T0051.000"],
    "memory_poisoning": ["AML.T0080.000"], "tool_abuse": ["AML.T0053"], "exfiltration": ["AML.T0057", "AML.T0086"],
}
ASI_BY_FAMILY = {
    "instruction_override": "ASI01_AgentGoalHijack", "role_play": "ASI03_IdentityPrivilegeAbuse", "encoding_evasion": "ASI01_AgentGoalHijack",
    "payload_splitting": "ASI01_AgentGoalHijack", "memory_poisoning": "ASI06_MemoryContextPoisoning", "tool_abuse": "ASI02_ToolMisuse",
    "exfiltration": "ASI02_ToolMisuse",
}
# The scope attack class an imported payload of this family is filed under (the class decides what the signed scope must authorize).
CLASS_BY_FAMILY = {
    "instruction_override": "prompt_injection_direct", "role_play": "jailbreak", "encoding_evasion": "prompt_injection_direct",
    "payload_splitting": "prompt_injection_direct", "memory_poisoning": "prompt_injection_indirect", "tool_abuse": "tool_abuse",
    "exfiltration": "data_leakage",
}


def normalize_family(value) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().lower().replace("-", "_").replace(" ", "_")
    return v if v in FAMILIES else None


def atlas_for(attack_class: str, extra: list[str] | None = None) -> list[dict]:
    ids = list(ATLAS_BY_CLASS.get(attack_class, []))
    for x in extra or []:
        if x in TECHNIQUES and x not in ids:
            ids.append(x)
    out = []
    for t in ids:
        name, tacs = TECHNIQUES[t]
        out.append({"id": t, "name": name, "tactics": [{"id": a, "name": TACTICS[a]} for a in tacs]})
    return out


# ------------------------------------------------------------------ NIST AI RMF
NIST: list[dict] = [
    {"id": "MEASURE 2.5", "function": "Measure", "en": "Validity and reliability of the AI system are demonstrated and documented"},
    {"id": "MEASURE 2.6", "function": "Measure", "en": "Safety risks are evaluated; the system performs safely within its intended use"},
    {"id": "MEASURE 2.7", "function": "Measure", "en": "Security and resilience are evaluated and documented"},
    {"id": "MEASURE 2.10", "function": "Measure", "en": "Privacy risk of the AI system is examined and documented"},
    {"id": "MANAGE 1.3", "function": "Manage", "en": "Responses to high-priority AI risks are developed, planned and documented"},
    {"id": "MANAGE 2.4", "function": "Manage", "en": "Mechanisms exist to supersede, disengage or deactivate a system that behaves outside its intended use"},
    {"id": "MANAGE 3.1", "function": "Manage", "en": "Risks and benefits from third-party resources are regularly monitored"},
    {"id": "MANAGE 4.1", "function": "Manage", "en": "Post-deployment monitoring plans exist, including mechanisms for capturing and evaluating input"},
]
NIST_BY_ID = {n["id"]: n for n in NIST}
# OWASP LLM category -> NIST subcategories
NIST_BY_OWASP = {
    "LLM01_PromptInjection": ["MEASURE 2.7", "MANAGE 1.3"],
    "LLM02_SensitiveInfoDisclosure": ["MEASURE 2.10", "MEASURE 2.7"],
    "LLM03_SupplyChain": ["MANAGE 3.1"],
    "LLM04_DataModelPoisoning": ["MEASURE 2.7"],
    "LLM05_ImproperOutputHandling": ["MEASURE 2.7"],
    "LLM06_ExcessiveAgency": ["MEASURE 2.6", "MANAGE 2.4"],
    "LLM07_SystemPromptLeakage": ["MEASURE 2.7"],
    "LLM08_VectorEmbeddingWeaknesses": ["MEASURE 2.10"],
    "LLM09_Misinformation": ["MEASURE 2.5"],
    "LLM10_UnboundedConsumption": ["MEASURE 2.7", "MANAGE 4.1"],
}

# ------------------------------------------------------------------ OWASP AISVS (chapter level)
AISVS: list[dict] = [
    {"id": "C1", "en": "Training Data Integrity and Traceability"}, {"id": "C2", "en": "User Input Validation"},
    {"id": "C3", "en": "Model Lifecycle Management and Change Control"}, {"id": "C4", "en": "Infrastructure, Configuration and Deployment Security"},
    {"id": "C5", "en": "Access Control and Identity"}, {"id": "C6", "en": "Supply Chain Security for Models, Frameworks and Data"},
    {"id": "C7", "en": "Model Behavior, Output Control and Safety Assurance"}, {"id": "C8", "en": "Memory, Embeddings and Vector Database Security"},
    {"id": "C9", "en": "Autonomous Orchestration and Agentic Action Security"}, {"id": "C10", "en": "MCP Security"},
    {"id": "C11", "en": "Adversarial Robustness and Attack Resistance"}, {"id": "C12", "en": "Privacy Protection and Personal Data Management"},
    {"id": "C13", "en": "Monitoring, Logging and Anomaly Detection"}, {"id": "C14", "en": "Human Oversight and Trust"},
]
AISVS_BY_ID = {a["id"]: a for a in AISVS}
AISVS_BY_OWASP = {
    "LLM01_PromptInjection": ["C2", "C11"], "LLM02_SensitiveInfoDisclosure": ["C12", "C7"], "LLM03_SupplyChain": ["C6"],
    "LLM04_DataModelPoisoning": ["C1", "C3"], "LLM05_ImproperOutputHandling": ["C7"], "LLM06_ExcessiveAgency": ["C9", "C5"],
    "LLM07_SystemPromptLeakage": ["C7"], "LLM08_VectorEmbeddingWeaknesses": ["C8"], "LLM09_Misinformation": ["C7", "C14"],
    "LLM10_UnboundedConsumption": ["C4", "C11"],
}
AISVS_BY_ASI = {"ASI01_AgentGoalHijack": ["C9"], "ASI02_ToolMisuse": ["C9"], "ASI03_IdentityPrivilegeAbuse": ["C5", "C9"]}


def normalize_aisvs(value) -> str | None:
    if not isinstance(value, str):
        return None
    v = value.strip().upper().removeprefix("AISVS").lstrip("-_ ")
    if v.startswith("V1.0"):
        return None
    return v if v in AISVS_BY_ID else None


def resolve(*, owasp: str | None, attack_class: str, asi: str | None = None, aisvs: list[str] | None = None, family: str | None = None) -> dict:
    """Everything a finding/attempt maps to. `asi`/`aisvs`/`family` come from the library case when it states them (ASI precedence: the case's own
    asi_category, then its attack family, then the class default)."""
    asi_id = asi or ASI_BY_FAMILY.get(family or "") or ASI_DEFAULT_BY_CLASS.get(attack_class)
    chapters = list(dict.fromkeys([*(aisvs or []), *AISVS_BY_OWASP.get(owasp or "", []), *AISVS_BY_ASI.get(asi_id or "", [])]))
    return {"asi": asi_id, "atlas": atlas_for(attack_class, ATLAS_BY_FAMILY.get(family or "")), "family": family or None,
            "nist": [{"id": n, "function": NIST_BY_ID[n]["function"]} for n in NIST_BY_OWASP.get(owasp or "", [])],
            "aisvs": chapters}


# ------------------------------------------------------------------ aggregation (pure; used by the dashboard and the PDF report)
def _blank() -> dict:
    return {"tested": 0, "violations": 0, "verified": 0, "inconclusive": 0}


def status_of(row: dict) -> str:
    """Only conclusive judgements count as 'tested'. An inconclusive evaluation (for example a judge that failed the output schema) is never read as
    'clean': it makes the row 'review' so that a failing judge cannot produce a green dashboard."""
    if row["verified"]:
        return "vulnerable"
    if row["violations"] or row.get("inconclusive"):
        return "review"
    return "clean" if row["tested"] else "not_tested"


def stats(attempts: list[dict], findings: list[dict], benchmarks: tuple[str, ...]) -> dict:
    """attempts: rows with category/owasp_category/outcome/tags_json (first, non-replay, judged only); findings: rows with status."""
    import json
    buckets: dict[str, dict] = {k: {} for k in ("asi", "nist", "aisvs", "atlas", "bench", "family")}

    def ids(r) -> tuple[dict, dict]:
        tags = json.loads(r.get("tags_json") or "{}")
        fw = resolve(owasp=r.get("owasp_category"), attack_class=r.get("category") or "", asi=tags.get("asi"), aisvs=tags.get("aisvs"), family=tags.get("family"))
        return {"asi": [fw["asi"]] if fw["asi"] else [], "nist": [n["id"] for n in fw["nist"]], "aisvs": fw["aisvs"],
                "atlas": [t["id"] for t in fw["atlas"]], "bench": [tags["benchmark"]] if tags.get("benchmark") else [],
                "family": [tags["family"]] if tags.get("family") else []}, tags

    for r in attempts:
        if r.get("is_replay") or not str(r["outcome"]).startswith("judged:"):
            continue
        conclusive = r["outcome"] in ("judged:violation", "judged:no_violation")
        for kind, lst in ids(r)[0].items():
            for k in lst:
                row = buckets[kind].setdefault(k, _blank())
                if conclusive:
                    row["tested"] += 1
                    row["violations"] += int(r["outcome"] == "judged:violation")
                else:
                    row["inconclusive"] += 1
    for r in findings:
        if r["status"] == "verified":
            for kind, lst in ids(r)[0].items():
                for k in lst:
                    buckets[kind].setdefault(k, _blank())["verified"] += 1

    def fill(items):
        return lambda src: [{**it, **src.get(it["id"], _blank()), "status": status_of(src.get(it["id"], _blank()))} for it in items]

    atlas_rows = []
    for k, (name, tacs) in TECHNIQUES.items():
        row = buckets["atlas"].get(k, _blank())
        atlas_rows.append({"id": k, "name": name, "tactics": [{"id": a, "name": TACTICS[a]} for a in tacs], **row, "status": status_of(row)})
    bench_rows = []
    for name in benchmarks:
        row = buckets["bench"].get(name, _blank())
        t = row["tested"]
        bench_rows.append({"name": name, "evaluated": t, "inconclusive": row["inconclusive"], "violations": row["violations"], "verified": row["verified"],
                           "asr": round(row["violations"] / t, 4) if t else None, "asr_verified": round(row["verified"] / t, 4) if t else None})
    family_rows = []
    for k in FAMILIES:
        row = buckets["family"].get(k, _blank())
        fw_ids = ATLAS_BY_FAMILY[k]
        family_rows.append({"id": k, "en": FAMILY_LABEL[k], "asi": ASI_BY_FAMILY[k], "atlas": [{"id": t, "name": TECHNIQUES[t][0]} for t in fw_ids], **row, "status": status_of(row)})
    return {"families": family_rows, "asi": fill(ASI)(buckets["asi"]), "nist": fill(NIST)(buckets["nist"]), "aisvs": fill(AISVS)(buckets["aisvs"]),
            "atlas": atlas_rows, "benchmarks": bench_rows, "versions": FRAMEWORK_VERSIONS,
            "note": "Evidence mapping, not a conformance certificate. AISVS is mapped at chapter level."}
