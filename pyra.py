
# Change working directory
import os
import re
import arango
import nistAPI
# import PyPDF2
from owlready2 import *

BRON_SERVER_IP = "localhost"
BRON_USERNAME = "guest"
BRON_PASSWORD = "guest"
DB = "BRON"
CWD = os.getcwd()

LOCAL_DB = True

query_self = """
FOR o IN {}
    FILTER o.original_id == "{}"
    RETURN o
"""

# Query with equality check
query_equal = """
FOR o IN {}
    FILTER o.original_id == "{}"
    FOR r IN 1..1 ANY o {}
        RETURN r
"""

# Query with LIKE check
query_like = """
FOR o IN {}
    FILTER o.original_id LIKE "{}"
    FOR r IN 1..1 ANY o {}
        RETURN r
"""

# Query with CONTAINS check
query_contains = """
FOR o IN {}
    FILTER CONTAINS(o.original_id, "{}")
    FOR r IN 1..1 ANY o {}
        RETURN r
"""

src_path = CWD + "/merged.owl"
dst_path = CWD + "/popolata_v11.owl"


def main():
    if LOCAL_DB:
        client = arango.ArangoClient(hosts=f"http://{BRON_SERVER_IP}:8529")
    else:
        client = arango.ArangoClient(hosts=f"http://bron.alfa.csail.mit.edu:8529/") # online DB

    # Open DB
    global db
    db = client.db(
        DB, username=BRON_USERNAME, password=BRON_PASSWORD, auth_method="basic"
    )

    # Load ontology
    global onto
    onto = get_ontology(src_path).load()

    # Make sure all the needed classes are defined in the ontology
    define_ontology_classes()

    # These dictionaries will be used to easily keep track of what is added to the ontology (to avoid duplicates)
    global cwes_dict, cves_dict, techniques_dict, tactics_dict, attack_mitigations_dict, defend_mitigations_dict, cwe_mitigations_dict
    cwes_dict, cves_dict, techniques_dict, tactics_dict, attack_mitigations_dict, defend_mitigations_dict, cwe_mitigations_dict = {}, {}, {}, {}, {}, {}, {}
    
    global vulns_count
    vulns_count = 0
    global risks_count
    risks_count = 0

    resource_class = onto.Asset
    resources = set(resource_class.instances()) # using set because, somehow, I get some resources twice in the array

    # Sort resources by name
    resources = sorted(resources, key=lambda x: x.name)
    for ont_resource in resources:
        print(ont_resource)
        cves_for_resource(ont_resource)

    onto.save(dst_path)

# def generate_pdf_report():
#     # Create a new PDF document
#     pdf = PyPDF2.PdfWriter()

#     # Add title and table headers
#     pdf.add_page()
#     pdf.set_font("Helvetica", 16)
#     pdf.cell(0, 20, "Vulnerability Analysis Report", align="center")

#     pdf.set_font("Helvetica", 10)
#     pdf.cell(30, 10, "CPE", 1)
#     pdf.cell(60, 10, "CVEs", 1)
#     pdf.cell(30, 10, "CWEs", 1)
#     pdf.cell(60, 10, "CAPECs", 1)
#     pdf.cell(30, 10, "ATT&CK Techniques", 1)
#     pdf.ln()

#     # Assuming you have a class called 'Resource' and a data property called 'CPE'
#     resource_class = onto.Resource
#     for ont_resource in resource_class.instances():
#         cpe = ont_resource.CPE[0]
#         vulns = ont_resource.hasVulnerability
#         for vuln in vulns:
#             cves = vuln.hasCVE
#             cwes = vuln.hasCWE
#             capecs = vuln.RelatedAttackPatterns
#             techniques = vuln.exploits
#             pdf.cell(30, 10, cpe, 1)
#             pdf.cell(60, 10, cves, 1)
#             pdf.cell(30, 10, cwes, 1)
#             pdf.cell(60, 10, capecs, 1)
#             pdf.cell(30, 10, techniques, 1)
#             pdf.ln()

#     # Save the PDF
#     pdf.output("report.pdf")


# Section: populate ontology
def define_ontology_classes():
    with onto:
        # Define hasSeverity data property for CAPEC
        class Severity(DataProperty):
            range = [str]

        # Define CVE's data properties
        class VulnStatus(DataProperty):
            range = [str]
        
        class BaseScore(DataProperty):
            range = [float]

        # class hasImpactScore(DataProperty):
        #     range = [float]

        # class hasExploitabilityScore(DataProperty):
        #     range = [float]

        class BaseSeverity(DataProperty):
            range = [str]


        # Define CWE's data properties
        class likelihood(DataProperty):
            range = [str]

        class Name(DataProperty):
            range = [str]
        
        # Define Vulnerability data properties
        class RelatedAttackPatterns(DataProperty):
            range = [str]

        class CVSS(DataProperty):
            range = [float]

        class CommonConsequences(DataProperty):
            range = [str]

        # Define Technique and Tectic classes
        class Technique(onto.ATTACK):
            pass
        
        class Tactic(onto.ATTACK):
            pass

        # Define object property for Technique
        class usedInTactic(ObjectProperty):
            domain = [Technique]
            range = [Tactic]

        # Define Mitigation sub-classes
        class ATTACKMitigations(onto.MITIGATIONS):      #TODO? farlo con attack - tactic - technique
            pass

        # Define object property for ATTACK Mitigation
        class hasMitigation(ObjectProperty):
            range = [ATTACKMitigations]

        class DEFENDMitigations(onto.MITIGATIONS):      #TODO? farlo con defend - tactic - technique
            pass

        # Define object property for DEFEND Mitigation
        class hasMitigation(ObjectProperty):
            range = [DEFENDMitigations]

        class CWEMitigations(onto.MITIGATIONS):         #TODO? farlo con cwe - mitigations?
            pass
        
        # Define object property for CWE Mitigation
        class hasMitigation(ObjectProperty):
            range = [CWEMitigations]

        class forPhase(DataProperty):
            range = [str]

        ## TODO: aggiungere classe resource per tenere traccia dei security mechanism collegati
        
def add_cve_to_ontology(cve):
    CveClass = onto.CVE
    new_cve = CveClass(cve.id)
    new_cve.comment.append(cve.description)
    new_cve.VulnStatus.append(cve.vuln_status)
    new_cve.BaseScore.append(cve.base_score)
    # new_cve.hasExploitabilityScore.append(cve.exploitability_score)
    # new_cve.hasImpactScore.append(cve.impact_score)
    new_cve.BaseSeverity.append(cve.base_severity)
    return new_cve

def add_cwe_to_ontology(cwe, cwe_id):
    CweClass = onto.CWE
    new_cwe = CweClass(cwe_id)
    if cwe["name"] is not None:
        new_cwe.Name.append(cwe["name"])

    metadata = cwe["metadata"]
    if metadata is not None:
        if "description" in metadata:
            description = description_from_metadata(metadata)
            if description:
                new_cwe.comment.append(description)

        if "common_consequences" in metadata:
            common_consequences = metadata["common_consequences"]
            if common_consequences is not None:
                for cc in common_consequences:
                    new_cwe.CommonConsequences.append(str(cc).strip() + "\n")


def add_technique_to_ontology(technique):
    TechniqueClass = onto.Technique
    new_technique = TechniqueClass(technique["original_id"])
    
    if technique["name"] is not None:
        new_technique.Name.append(technique["name"])

    description = None
    metadata = technique["metadata"]
    if metadata is not None:
        description = description_from_metadata(metadata)
    
    if description is not None:
        new_technique.comment.append(description)

    return new_technique

def add_tactic_to_ontology(tactic):
    TacticClass = onto.Tactic
    new_tactic = TacticClass(tactic["original_id"])
    
    if tactic["name"] is not None:
        new_tactic.Name.append(tactic["name"])

    description = None
    metadata = tactic["metadata"]
    if metadata is not None:
        description = description_from_metadata(metadata)
    
    if description is not None:
        new_tactic.comment.append(description)

    return new_tactic

def create_vulnerability_for_cve_and_cwes(resource, cve, cwes):
    global vulns_count
    cwes_values = cwes.values()

    if cve is not None:
        vulns_count += 1
        vuln_id = "VULN-" + str(vulns_count)

        # Add vuln to the ontology
        VulnClass = onto.Vulnerability

        new_vuln = VulnClass(vuln_id)
        new_vuln.hasCVE.append(cve)

        CVSS = cve.BaseScore
        new_vuln.CVSS.append(CVSS[0])

        for cwe in cwes_values:
            new_vuln.hasCWE.append(cwe)
            capecs = capecs_for_cwe(cwe)  #interroga capecCwe
            cwe.relatedAttackPatterns.append(string_from_capecs(capecs.keys()))#TODO da provare
            if len(capecs) > 0:
                capecs_ids = capecs.keys()
                
                for capec_id in capecs_ids:#in questo modo si può costruire report con asset - capec - score. Da aggiungere un campo che dica quanto viene mitigato lo score e questo campo viene calcolato da proprietà di asset isProtectedBy -> relazione 'protecs' a confronto con consequences di ogni capec
                    capec = onto.CAPEC("CAPEC-" + capec_id) #TODO da provare oppure
                    #capec = onto.search_one(iri="*CAPEC-"+capec_id)
                    new_vuln.hasCAPEC.append(capec)#TODO da provare
                    calculate_mitigated_score(new_vuln, resource, capec)

                # For each Capec, get ATT&CK Techniques
                for capec_id in capecs_ids:
                    techniques = techniques_for_capec(capec_id)   # interroga TechniqueCapec dove technique rappresenta attack technique
                    for t in techniques.values():                 # gerarchia attack: tactic - technique - sub-technique
                        t.exploits.append(new_vuln)

                        tactics = tactics_for_technique(t.name)   # interroga TacticTechnique
                        for ta in tactics.values():
                            t.usedInTactic.append(ta)

                        attack_mitigations = attack_mitigations_for_technique(t.name)  #interroga TechniqueTechnique_mitigation (attack mitigations)
                        for m in attack_mitigations.values():
                            t.hasMitigation.append(m)

                        defend_mitigations = defend_mitigations_for_technique(t.name)  #interroga D3fend_mitigationTechnique (defend mitigations)
                        for m in defend_mitigations.values():       #TODO? da organizzare meglio in tactic - technique
                            t.hasMitigation.append(m)

            mitigations = mitigations_for_cwe(cwe.name)  #interroga CweCwe_mitigation (cwe mitigations)
            for m in mitigations.values():
                new_vuln.hasMitigation.append(m)

        resource.hasVulnerability.append(new_vuln)

def calculate_mitigated_score(vuln, resource, capec):
    global risks_count

    conv_table = {"Very Low": 1, "Low": 2, "Medium": 3, "High": 4, "Very High": 5}
    
    # cerca risk con questi capec e resource
    existing_risk = None
    for risk in onto.Risk.instances():  #TODO da fare con query sparql
        if (resource in risk.hasSourceAsset and capec in risk.hasSourceCAPEC):
            existing_risk = risk
            break
    
    if existing_risk:
        # aggiunge la vulnerabilità se non è già presente
        if vuln not in existing_risk.hasSourceVuln:
            existing_risk.hasSourceVuln.append(vuln)
    else:
        # crea risk
        risks_count += 1
        risk_id = "RISK-" + str(risks_count)
        RiskClass = onto.Risk
        new_risk = RiskClass(risk_id)
        
        new_risk.hasSourceAsset.append(resource)
        new_risk.hasSourceCAPEC.append(capec)
        new_risk.hasSourceVuln.append(vuln)
        dict_security_type = {"_Prevention": 1, "_Detection": 1, "_Recovery": 1, "_Correction": 1, "_Deflection": 1, "_Deterrence": 1}
        dict_asset_type = {str(c).split(".")[1]: 1 for c in resource.is_a if issubclass(c, onto.HasAsset)}
        print(dict_asset_type)
        if len(capec.consequence) == 0 or resource.isProtectedBy is None:
            return
        weight_for_cons = 1/len(set(cons.split("::")[0] for cons in capec.consequence))
        dict_security_property = {}
        for cons in capec.consequence:
            prop = cons.split("::")[0]
            if prop == "Access Control":
                dict_security_property["_Authorisation"] = weight_for_cons
            else:
                dict_security_property["_" + prop] = weight_for_cons
        if resource.isProtectedBy:
            for sec_mec in resource.isProtectedBy:
                secMecClass = [subc for subc in sec_mec.is_a if issubclass(subc, onto.SecurityMechanism)]
                modifier = 1
                for s in secMecClass:
                    print(s.protects)
                    for x in s.protects:
                        print(str(x))
                        input_values = {**dict_asset_type, **dict_security_property, **dict_security_type}
                        print(input_values)
                        def replace_expression(expr, values):
                            def replacer(match):
                                key = match.group(1)
                                return str(values.get(key, 0))
                            return re.sub(r"merged\.(_\w+)", replacer, expr)

                        converted_expression = replace_expression(str(x), input_values)
                        print(f"Espressione convertita: {converted_expression}")

                        result = 1 - eval(converted_expression.replace("&", "*").replace("|", "+"))#TODO eventualmente cambiare come si calcola: considerare quale proprietà è mitigata e calcolarlo per quella proprietà solo una volta?
                        modifier = modifier * result
                        print(f"Risultato: {result}")
                new_risk.capecScore.append(str(conv_table.get(str(capec.likelihood[0]), 4) * conv_table.get(str(capec.severity[0]), 4)))
                if onto.Firewall in secMecClass:    #TODO probabilmente da estendere ad altre classi dopo analisi
                    new_risk.mitigatedCapecScore.append(str(modifier * conv_table.get(str(capec.likelihood[0]), "4") * conv_table.get(str(capec.severity[0]), "4")) + "*")
                else:
                    new_risk.mitigatedCapecScore.append(str(modifier * conv_table.get(str(capec.likelihood[0]), "4") * conv_table.get(str(capec.severity[0]), "4")))
                print(f"Rischio non mitigato: {new_risk.capecScore}")
                print(f"Rischio mitigato: {new_risk.mitigatedCapecScore}")
                

def add_attack_mitigation_to_ontology(mitigation):
    MitigationClass = onto.ATTACKMitigations
    new_mitigation = MitigationClass(mitigation["original_id"])
    
    if "name" in mitigation and mitigation["name"] is not None:
        new_mitigation.Name.append(mitigation["name"])

    return new_mitigation

def add_defend_mitigation_to_ontology(mitigation):
    MitigationClass = onto.DEFENDMitigations
    new_mitigation = MitigationClass(mitigation["original_id"])
    
    if "name" in mitigation and mitigation["name"] is not None:
        new_mitigation.Name.append(mitigation["name"])

    return new_mitigation

def add_cwe_mitigation_to_ontology(mitigation):
    MitigationClass = onto.CWEMitigations
    
    id = "CM" + mitigation["original_id"]
    new_mitigation = MitigationClass(id)
    
    if "name" in mitigation and mitigation["name"] is not None:
        new_mitigation.Name.append(mitigation["name"])

    if "metadata" in mitigation:
        metadata = mitigation["metadata"]
        if metadata is not None:
            description = description_from_metadata(metadata)
            if description is not None:
                new_mitigation.comment.append(description)

        if "Phase" in metadata:
            new_mitigation.forPhase.append(metadata["Phase"])

    return new_mitigation

def populate_existing_capecs():
    capec_class = onto.CAPEC
    capecs = set(capec_class.instances())
    for onto_capec in capecs:
        capec_id = onto_capec.name.split('-')[1]
        capec_for_capec_query = query_self.format("capec", capec_id, "capec")
        assert db.aql.validate(capec_for_capec_query)
        cursor = db.aql.execute(capec_for_capec_query)
        capecs_for_capec = {capec["original_id"]: capec for capec in cursor}
        if len(capecs_for_capec) > 1:
            print(f"CAPEC {capec_id} has more than one match in the DB")

        for capec in capecs_for_capec.values():
            if "metadata" in capec:
                metadata = capec["metadata"]
                if metadata is not None:
                    description = description_from_metadata(metadata)
                    if description is not None:
                        onto_capec.comment.append(description)

                    # Get likelihood_of_attack and assign High if empty
                    if "likelihood_of_attack" in metadata:
                        likelihood = metadata["likelihood_of_attack"]
                        if likelihood == "":
                            likelihood = "High*"
                        onto_capec.likelihood.append(likelihood)

                    # Get typical_severity and assign High if empty
                    if "typical_severity" in metadata:
                        severity = metadata["typical_severity"]
                        if severity == "":
                            severity = "High"
                        onto_capec.hasSeverity.append(severity)

# Define a new function that gets cves for a given cpe from BRON, rather than from NIST api
def cves_for_cpe(cpe):
    cves_query = query_like.format("cpe", cpe, "CveCpe")
    assert db.aql.validate(cves_query)
    cursor = db.aql.execute(cves_query)
    cves = {cve["original_id"]: cve for cve in cursor}

    return cves

# Section: mapping
def cwes_for_cve(cve):
    cwes_query = query_equal.format("cve", cve.id, "CweCve")
    assert db.aql.validate(cwes_query)
    cursor = db.aql.execute(cwes_query)
    if cursor is None:
        raise ValueError("Cursor is None. Check the data source or query.")
    cwes = {cwe["original_id"]: cwe for cwe in cursor if cwe and "original_id" in cwe}

    cwes_for_cve = {}
    for cwe_id, cwe in sorted(cwes.items()):
        new_cwe = None

        # Add to CWEs dictionary and to the ontology only once
        cwe_id = "CWE-" + cwe_id
        if cwe_id not in cwes_dict:
            cwes_dict[cwe_id] = cwe
            
            new_cwe = add_cwe_to_ontology(cwe, cwe_id)
        else:
            new_cwe = onto.search_one(iri="*"+cwe_id)

        if new_cwe is not None:
            cwes_for_cve[cwe_id] = new_cwe

    return cwes_for_cve

def capecs_for_cwe(cwe):    #TODO se capec son già popolati da script non c'è bisogno di aggiungerli a ontologia anche qua come si fa per cwe, ecc; se no bisogna farlo
    cweid = cwe.name.split('-')[1]
    capec4cwe_query = query_equal.format("cwe", cweid, "CapecCwe")
    assert db.aql.validate(capec4cwe_query)
    cursor = db.aql.execute(capec4cwe_query)
    capecs = {capec["original_id"]: capec for capec in cursor}

    return capecs

def techniques_for_capec(capec_id):
    techniques_query = query_equal.format("capec", capec_id, "TechniqueCapec")
    assert db.aql.validate(techniques_query)
    cursor = db.aql.execute(techniques_query)
    techniques = {technique["original_id"]: technique for technique in cursor}

    techniques_for_capec = {}
    for techn_id, technique in sorted(techniques.items()):
        new_technique = None

        # Add to Techniques dictionary and to the ontology only once
        if techn_id not in techniques_dict:
            techniques_dict[techn_id] = technique
            new_technique = add_technique_to_ontology(technique)
        else:
            new_technique = onto.search_one(iri="*"+techn_id)

        if new_technique is not None:
            techniques_for_capec[techn_id] = new_technique

    return techniques_for_capec

def tactics_for_technique(technique_id):
    tactics_query = query_equal.format("technique", technique_id, "TacticTechnique")
    assert db.aql.validate(tactics_query)
    cursor = db.aql.execute(tactics_query)
    tactics = {tactic["original_id"]: tactic for tactic in cursor}

    tactics_for_capec = {}
    for techn_id, tactic in sorted(tactics.items()):
        new_tactic = None

        # Add to Techniques dictionary and to the ontology only once
        if techn_id not in tactics_dict:
            tactics_dict[techn_id] = tactic
            new_tactic = add_tactic_to_ontology(tactic)
        else:
            new_tactic = onto.search_one(iri="*"+techn_id)

        if new_tactic is not None:
            tactics_for_capec[techn_id] = new_tactic

    return tactics_for_capec

import re

def get_cpe_part(ont_resource):
    """
    Determines the CPE part based on the given ontology resource.

    Args:
        ont_resource (OntologyResource): The ontology resource to determine the CPE part for.

    Returns:
        str: The CPE part ('h' for hardware, 'o' for operating system or firmware, 'a' for other).
    """
    # Get class name
    class_name = ont_resource.is_a[0].name

    # if class_name contains 'hardware' (ignoring case) return 'h'
    if re.search(r'hardware', class_name, re.IGNORECASE):
        return "h"
    elif class_name == "OperatingSystem" or class_name == "Firmware":
        return "o"
    
    return "a"

def cves_for_resource(ont_resource):
    """
    Retrieves the CVEs (Common Vulnerabilities and Exposures) associated with the given ontology resource,
    and adds them to the ontology.

    Parameters:
    ont_resource (object): The ontology resource for which to retrieve the CVEs.

    Returns:
    None
    """
    if ont_resource.CPE:
        cpe = ont_resource.CPE[0]
        print(f"{ont_resource.name}:\t\t {cpe}")
    elif ont_resource.vendor and ont_resource.product:
        cpe = "cpe:2.3:"

        part = get_cpe_part(ont_resource)
        vendor = ont_resource.vendor[0]
        product = ont_resource.product[0]

        cpe += part + ":" + vendor + ":" + product

        if ont_resource.version:
            version = ont_resource.version[0]
            cpe += ":" + version
        
        print(f"{ont_resource.name}:\t\t {cpe}")
    else:
        print(f"{ont_resource.name}:\t\t No CPE property")
        return

    #TODO ont_resource.isProtectedBy per recuperare sec mec collegati e a questo punto calcolare cvss mitigato? e quindi filtrare cve?
    if(len(ont_resource.isProtectedBy) > 0):
        pass
        #TODO aggiungere a classe resource i security mechanism
    
    cves = nistAPI.get_cves_for_cpe(cpe)
    # cves = cves_for_cpe(cpe)
    print(f"{ont_resource.name} - {cpe}:\t\t {len(cves)} CVEs")
    for cve in cves:
        # print(f"\t{cve.id}")
        new_cve = None

        # Add to CVEs dictionary and to the ontology only if new, otherwise look for it in the ontology
        if cve.id not in cves_dict:
            cves_dict[cve.id] = cve
            new_cve = add_cve_to_ontology(cve)
        else:
            new_cve = onto.search_one(iri="*"+cve.id)

        # Get cwes for current cve (the method also adds them to the ontology if necessary)
        cwes = cwes_for_cve(cve)

        # Add vuln to vulns dictionary and to the ontology only once
        # A unique hash is computed based on CVE + CWES... is this correct? Can a VULN be associated to more than one resource?
        if new_cve is not None:
            create_vulnerability_for_cve_and_cwes(ont_resource, new_cve, cwes)

def defend_mitigations_for_technique(technique_id):
    """
    Retrieves the mitigations associated with a given technique.

    Args:
        technique_id (str): The ID of the technique.

    Returns:
        dict: A dictionary containing the mitigations for the technique, where the keys are the mitigation IDs and the values are the corresponding mitigations.
    """
    mitigations_query = query_equal.format("technique", technique_id, "D3fend_mitigationTechnique")
    assert db.aql.validate(mitigations_query)
    cursor = db.aql.execute(mitigations_query)
    mitigations = {mitigation["original_id"]: mitigation for mitigation in cursor}

    mitigations_for_technique = {}
    for mitigation_id, mitigation in sorted(mitigations.items()):
        new_mitigation = None

        # Add to Mitigations dictionary and to the ontology only once
        if mitigation_id not in defend_mitigations_dict:
            defend_mitigations_dict[mitigation_id] = mitigation
            new_mitigation = add_defend_mitigation_to_ontology(mitigation)
        else:
            new_mitigation = onto.search_one(iri="*"+mitigation_id)

        if new_mitigation is not None:
            mitigations_for_technique[mitigation_id] = new_mitigation

    return mitigations_for_technique

def attack_mitigations_for_technique(technique_id):
    """
    Retrieves the mitigations associated with a given technique.

    Args:
        technique_id (str): The ID of the technique.

    Returns:
        dict: A dictionary containing the mitigations for the technique, where the keys are the mitigation IDs and the values are the corresponding mitigations.
    """
    mitigations_query = query_equal.format("technique", technique_id, "TechniqueTechnique_mitigation")
    assert db.aql.validate(mitigations_query)
    cursor = db.aql.execute(mitigations_query)
    mitigations = {mitigation["original_id"]: mitigation for mitigation in cursor}

    mitigations_for_technique = {}
    for mitigation_id, mitigation in sorted(mitigations.items()):
        new_mitigation = None

        # Add to Mitigations dictionary and to the ontology only once
        if mitigation_id not in attack_mitigations_dict:
            attack_mitigations_dict[mitigation_id] = mitigation
            new_mitigation = add_attack_mitigation_to_ontology(mitigation)
        else:
            new_mitigation = onto.search_one(iri="*"+mitigation_id)

        if new_mitigation is not None:
            mitigations_for_technique[mitigation_id] = new_mitigation

    return mitigations_for_technique

def mitigations_for_cwe(cwe_id):
    """
    Retrieves mitigations for a given CWE ID.

    Args:
        cwe_id (str): The CWE ID to retrieve mitigations for.

    Returns:
        dict: A dictionary containing the mitigations for the CWE ID, where the keys are the mitigation IDs and the values are the corresponding mitigations.
    """
    # if cwe_id starts with CWE- remove it
    if cwe_id.startswith("CWE-"):
        cwe_id = cwe_id[4:]

    mitigations_query = query_equal.format("cwe", cwe_id, "CweCwe_mitigation")
    assert db.aql.validate(mitigations_query)
    cursor = db.aql.execute(mitigations_query)
    mitigations = {mitigation["original_id"]: mitigation for mitigation in cursor}

    mitigations_for_cwe = {}
    for mitigation_id, mitigation in sorted(mitigations.items()):
        new_mitigation = None

        # Add to Mitigations dictionary and to the ontology only once
        id = "CM" + mitigation_id
        if id not in cwe_mitigations_dict:
            cwe_mitigations_dict[id] = mitigation
            new_mitigation = add_cwe_mitigation_to_ontology(mitigation)
        else:
            new_mitigation = onto.search_one(iri="*"+id)

        if new_mitigation is not None:
            mitigations_for_cwe[id] = new_mitigation

    return mitigations_for_cwe

# Section: Utility
def description_from_metadata(metadata):
    """
    Extracts the description from the given metadata dictionary.

    Args:
        metadata (dict): The metadata dictionary.

    Returns:
        str: The stripped description.

    """
    stripped_description = None
    description = None

    if "short_description" in metadata:
        description = metadata["short_description"]
        if description is not None:
            description = description.strip()
            stripped_description = re.sub(r'\s+', ' ', description).strip()
            return stripped_description

    if "description" in metadata:
        description = metadata["description"]
        if description is not None:
            description = description.strip()
            stripped_description = re.sub(r'\s+', ' ', description).strip()
            return stripped_description
        
    if "Description" in metadata:
        description = metadata["Description"]
        if description is not None:
            description = description.strip()
            stripped_description = re.sub(r'\s+', ' ', description).strip()

    return stripped_description

def string_from_capecs(capecs_ids):
    ncapecs = ["CAPEC-" + item for item in capecs_ids]
    capecs_str = ", ".join(ncapecs)

    return capecs_str

def query_arangodb_for_available_colletions_and_views_and_print_all():
    # Get list of collections
    collections = db.collections()
    print("Collections:")
    for collection in collections:
        print(collection["name"])

    # Get list of views
    views = db.views()
    print("Views:")
    for view in views:
        print(view["name"])


if __name__ == "__main__":
    main()