class CVE:
    def __init__(self, id, description, vuln_status, base_score, vector_string, exploitability_score, base_severity):
        self.id = id
        self.description = description
        self.vuln_status = vuln_status
        self.base_score = base_score
        self.vector_string = vector_string
        self.exploitability_score = exploitability_score
        self.base_severity = base_severity

    def __str__(self):
        return f"ID: {self.id}\nDescription: {self.description}\nVulnerability Status: {self.vuln_status}\nBase Score: {self.base_score}\nVector String: {self.vector_string}"


class CWE:
    def __init__(self, id, name, description, likelihood):
        self.id = id
        self.name = name
        self.description = description
        self.likelihood = likelihood


class Vulnerability:
    def __init__(self, id, cve_id, cwe_ids):
        self.id = id
        self.cve_id = cve_id
        self.cwe_ids = cwe_ids