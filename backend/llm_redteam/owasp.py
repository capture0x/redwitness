"""
OWASP Top 10 for LLM Applications - taxonomy (the 2025 edition is canonical; 2023/v1.1 ids are accepted as aliases).

HONEST LIMIT: this module maps BEHAVIORAL quality probes made through a black-box API to OWASP categories.
The results are NOT a "compliance certificate". LLM03/LLM04/LLM08 (supply chain, data/model poisoning,
vector/embedding) in particular are only covered in a LIMITED way by black-box testing; a full assessment needs an architecture/process review.
"""
CATEGORIES: list[dict] = [
    {"id": "LLM01_PromptInjection", "code": "LLM01", "en": "Prompt Injection", "coverage": "direct",
     "desc": "Can user input or processed external content unintentionally change the model's instructions/behavior?"},
    {"id": "LLM02_SensitiveInfoDisclosure", "code": "LLM02", "en": "Sensitive Information Disclosure", "coverage": "direct",
     "desc": "Does the model expose personal data, confidential configuration or information belonging to other users?"},
    {"id": "LLM03_SupplyChain", "code": "LLM03", "en": "Supply Chain", "coverage": "limited",
     "desc": "Does it avoid inventing unverifiable claims about the origin/version of the models, plugins and data sources it uses? (limited in black-box)"},
    {"id": "LLM04_DataModelPoisoning", "code": "LLM04", "en": "Data and Model Poisoning", "coverage": "limited",
     "desc": "Does it claim a persistent knowledge/behavior change from a single user input? (limited in black-box)"},
    {"id": "LLM05_ImproperOutputHandling", "code": "LLM05", "en": "Improper Output Handling", "coverage": "direct",
     "desc": "Does the generated output carry content that could be passed unsafely to downstream systems (browser, database, shell)?"},
    {"id": "LLM06_ExcessiveAgency", "code": "LLM06", "en": "Excessive Agency", "coverage": "direct",
     "desc": "Does the agent tend to perform irreversible/high-impact actions without confirmation and authorization checks? (needs a test-environment attestation)"},
    {"id": "LLM07_SystemPromptLeakage", "code": "LLM07", "en": "System Prompt Leakage", "coverage": "direct",
     "desc": "Are hidden system instructions or the sensitive values inside them exposed to the user?"},
    {"id": "LLM08_VectorEmbeddingWeaknesses", "code": "LLM08", "en": "Vector and Embedding Weaknesses", "coverage": "limited",
     "desc": "Does unauthorized/confidential content from the knowledge base (RAG) leak into the response? (limited in black-box)"},
    {"id": "LLM09_Misinformation", "code": "LLM09", "en": "Misinformation", "coverage": "direct",
     "desc": "Does the model correct false premises and admit uncertainty, or does it confidently make things up?"},
    {"id": "LLM10_UnboundedConsumption", "code": "LLM10", "en": "Unbounded Consumption", "coverage": "direct",
     "desc": "Does the application put reasonable limits on requests for excessively long/costly output?"},
]
BY_ID = {c["id"]: c for c in CATEGORIES}
BY_CODE = {c["code"]: c for c in CATEGORIES}

# 2023 (v1.1) and shortened spellings -> 2025 canonical id. (Includes the example ids the user gave.)
ALIASES = {
    "LLM02_InsecureOutput": "LLM05_ImproperOutputHandling", "LLM02_InsecureOutputHandling": "LLM05_ImproperOutputHandling",
    "LLM03_TrainingDataPoisoning": "LLM04_DataModelPoisoning", "LLM04_ModelDoS": "LLM10_UnboundedConsumption",
    "LLM04_ModelDenialOfService": "LLM10_UnboundedConsumption", "LLM05_SupplyChainVulnerabilities": "LLM03_SupplyChain",
    "LLM06_SensitiveInfoDisclosure": "LLM02_SensitiveInfoDisclosure", "LLM06_SensitiveInformationDisclosure": "LLM02_SensitiveInfoDisclosure",
    "LLM07_InsecurePluginDesign": "LLM06_ExcessiveAgency", "LLM08_ExcessiveAgency": "LLM06_ExcessiveAgency",
    "LLM09_Overreliance": "LLM09_Misinformation", "LLM10_ModelTheft": "LLM10_UnboundedConsumption",
    "LLM01_PromptInjection": "LLM01_PromptInjection",
}

# Attack class -> default OWASP category (when neither the case nor the judge says anything)
DEFAULT_BY_CLASS = {
    "prompt_injection_direct": "LLM01_PromptInjection", "prompt_injection_indirect": "LLM01_PromptInjection",
    "jailbreak": "LLM01_PromptInjection", "system_prompt_extraction": "LLM07_SystemPromptLeakage",
    "data_leakage": "LLM02_SensitiveInfoDisclosure", "tool_abuse": "LLM06_ExcessiveAgency",
    "unsafe_output": "LLM05_ImproperOutputHandling", "misinformation": "LLM09_Misinformation",
    "resource_consumption": "LLM10_UnboundedConsumption",
    "model_extraction": "LLM10_UnboundedConsumption", "membership_inference": "LLM02_SensitiveInfoDisclosure",
    "vector_store_exposure": "LLM08_VectorEmbeddingWeaknesses",
}


def normalize(value: str | None) -> str | None:
    """Canonical id; None if undefined. Also accepts 'LLM01', 'llm01_promptinjection' and legacy ids."""
    if not value or not isinstance(value, str):
        return None
    v = value.strip()
    if v in BY_ID:
        return v
    if v in ALIASES:
        return ALIASES[v]
    low = {k.lower(): k for k in list(BY_ID) + list(ALIASES)}
    if v.lower() in low:
        k = low[v.lower()]
        return k if k in BY_ID else ALIASES[k]
    code = v.upper().split("_")[0]
    return BY_CODE[code]["id"] if code in BY_CODE and "_" not in v else None


def default_for(attack_class: str) -> str | None:
    return DEFAULT_BY_CLASS.get(attack_class)


def resolve(case_owasp: str | None, judge_suggestion: str | None, attack_class: str) -> tuple[str | None, str]:
    """(category, source). Priority: library case > judge suggestion > attack-class default."""
    if case_owasp:
        return case_owasp, "library"
    j = normalize(judge_suggestion)
    if j:
        return j, "judge"
    d = default_for(attack_class)
    return d, "default" if d else "none"
