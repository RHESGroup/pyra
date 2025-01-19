# Change working directory
import os
import re
import arango
# import PyPDF2
from owlready2 import *
import pandas as pd

BRON_SERVER_IP = "localhost"
BRON_USERNAME = "guest"
BRON_PASSWORD = "guest"
DB = "BRON"
CWD = os.getcwd()

LOCAL_DB = True

query = """
FOR o IN {}
    RETURN o
"""

query_self = """
FOR o IN {}
    FILTER o.original_id == "{}"
    RETURN o
"""

src_path = CWD + "/merged.owl"

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

    capec_query = query.format("capec")
    assert db.aql.validate(capec_query)
    cursor = db.aql.execute(capec_query)
    capecs = {capec["original_id"]: capec for capec in cursor}
    #print(onto.CAPEC.instances())
    for c in capecs.values():
        #print(c["original_id"])
        if c in onto.CAPEC.instances():
            print("CAPEC already in ontology " + c["original_id"])
            continue
        else:
            capec = onto.CAPEC("CAPEC-" + c["original_id"]) #TODO a quanto pare non tutti i capec vengono aggiunti
    
    populate_existing_capecs()
    add_relationship_for_capecs_from_csv()
    add_stride_relations()
    onto.save(src_path)

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
            if "name" in capec:
                onto_capec.comment.append(capec["name"])
            if "metadata" in capec:
                metadata = capec["metadata"]
                if metadata is not None:
                    description = description_from_metadata(metadata)
                    if description is not None:
                        onto_capec.comment.append(description)

                    if "consequences" in metadata:
                        consequences = metadata["consequences"]
                        for consequence in consequences:
                            cons = ""
                            if "Scope" in consequence:
                                scope = consequence["Scope"]
                                cons += scope + "::"
                            if "Impact" in consequence:
                                impact = consequence["Impact"]
                                cons += impact + "::"
                            if "Note" in consequence:
                                note = consequence["Note"]
                                cons += note
                            if cons != "":
                                onto_capec.consequence.append(cons)

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
                        onto_capec.severity.append(severity)

def add_relationship_for_capecs_from_csv():
    
    # Read CSV file
    df = pd.read_csv('3000.csv')
    
    # dizionario con chiave id del capec e valore l'oggetto capec per cercare capec velocemente: con tutti i capec
    dict_all_capec_instances = {int(capec.name.split('-')[1]): capec for capec in set(onto.CAPEC.instances())}
    # dizionario con chiave id del capec e valore l'oggetto capec per cercare capec velocemente: con solo i capec già divisi in relazioni
    dict_sub_capec_instances = {}
    for subcls in onto.CAPEC.subclasses():
        dict_sub_capec_instances.update({int(capec.name.split('-')[1]): capec for capec in set(subcls.instances())})
    print(len(dict_sub_capec_instances.keys()))
    for _ in range(3):  #ciclo per profondità massima della gerarchia di capec
        set_dei_not_found = set()
        for capec in df.iterrows():
            if int(capec[1]["ID"]) not in dict_sub_capec_instances:
                id = int(capec[1]["ID"])
                related_attack_pattern = capec[1]["Related Attack Patterns"]
                #print(related_attack_pattern)
                if pd.isna(related_attack_pattern):
                    continue
                related_attack_pattern = [rap for rap in related_attack_pattern.split('::') if rap != '']
                for rap in related_attack_pattern:
                        rap = rap.split(':')
                        if rap[1] != "ChildOf":
                            continue
                        parent_id = int(rap[3])
                        if parent_id in dict_sub_capec_instances:
                            subclass = [subc for subc in dict_sub_capec_instances[parent_id].is_a if subc.name.startswith("CAPEC-")]
                            #print(subclass)
                            dict_sub_capec_instances.update({id: dict_all_capec_instances[id]})
                            for subc in subclass:
                                dict_all_capec_instances[id].is_a.append(subc)
                        else:
                            set_dei_not_found.add(parent_id)
                            #print(f"CAPEC-{parent_id} not found in ontology") #ci si aspetta che succeda per quei capec che appartengono esclusivamente a social engineering e physical security
        print(sorted(set_dei_not_found)) #giusto che manchino questi perchè sono o social engineering o physical security oppure non avevano un parente "Meta"
    print(len(dict_all_capec_instances.keys()))
    print(len(dict_sub_capec_instances.keys()))
    print(dict_all_capec_instances.keys() - dict_sub_capec_instances.keys())

    #print(sorted(dict_sub_capec_instances.keys()))

def add_stride_relations():
    dict_all_capec_instances = {int(capec.name.split('-')[1]): capec for capec in set(onto.CAPEC.instances())}

    dict_stride_individuals = {str(stride.name): stride for stride in onto.STRIDE.instances()}

    #dizionario popolato con la funzione get_capec_ids_from_file() fatta girare per ogni file corrispondente a ciascun stride, dove i file sono stati presi da https://ostering.com/blog/2022/03/07/capec-stride-mapping/
    dict_STRIDE = {"Tampering": [10, 100, 105, 113, 120, 123, 124, 126, 128, 129, 133, 139, 14, 140, 141, 142, 146, 153, 160, 161, 165, 166, 168, 176, 184, 185, 186, 187, 201, 203, 206, 220, 221, 24, 256, 26, 267, 268, 27, 270, 271, 272, 273, 274, 276, 277, 278, 279, 28, 29, 3, 33, 33, 34, 34, 4, 401, 402, 42, 43, 438, 439, 44, 440, 441, 442, 443, 444, 445, 446, 447, 448, 45, 452, 456, 457, 458, 46, 47, 478, 481, 5, 51, 51, 511, 516, 517, 518, 519, 52, 520, 521, 522, 523, 524, 53, 530, 531, 532, 533, 534, 535, 536, 537, 538, 539, 540, 548, 571, 572, 578, 594, 595, 596, 597, 614, 624, 625, 635, 636, 638, 64, 649, 655, 657, 663, 663, 665, 669, 67, 670, 671, 672, 673, 674, 677, 678, 71, 72, 73, 74, 75, 75, 76, 78, 79, 8, 80, 81, 9, 90, 92, 93], 
                "Spoofing": [103, 132, 141, 142, 145, 148, 151, 154, 159, 163, 164, 173, 181, 194, 195, 218, 222, 275, 38, 383, 389, 407, 412, 413, 414, 415, 416, 417, 418, 420, 421, 422, 423, 424, 425, 426, 427, 428, 429, 433, 434, 435, 459, 471, 473, 474, 475, 476, 477, 479, 485, 501, 502, 504, 505, 506, 51, 543, 544, 587, 598, 599, 611, 615, 616, 617, 627, 628, 630, 631, 632, 633, 641, 654, 656, 667, 89, 98], 
                "Repudiation": [195, 268, 571, 587, 599, 67, 81, 93], 
                "InformationDisclosure": [11, 111, 116, 117, 12, 127, 129, 143, 144, 149, 155, 157, 158, 167, 169, 170, 179, 188, 189, 190, 191, 192, 204, 212, 215, 216, 217, 224, 261, 285, 287, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 312, 313, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332, 37, 383, 406, 407, 410, 412, 413, 414, 415, 462, 463, 464, 465, 472, 48, 497, 498, 499, 501, 508, 529, 54, 541, 545, 546, 554, 568, 569, 57, 573, 574, 575, 576, 577, 580, 581, 606, 608, 609, 612, 613, 618, 619, 620, 621, 622, 623, 634, 634, 637, 639, 643, 646, 647, 648, 65, 651, 675, 85, 95, 97], 
                "DenialOfService": [125, 130, 131, 147, 197, 2, 201, 227, 229, 230, 231, 25, 469, 482, 486, 487, 488, 489, 490, 491, 492, 493, 494, 495, 496, 528, 547, 559, 582, 583, 584, 585, 589, 590, 601, 603, 604, 605, 607, 666, 96], 
                "ElevationOfPrivilege": [1, 101, 102, 104, 107, 108, 109, 110, 112, 114, 115, 121, 122, 13, 134, 135, 136, 137, 138, 15, 16, 162, 17, 174, 175, 177, 178, 18, 18, 18, 180, 182, 183, 19, 193, 196, 198, 198, 198, 199, 199, 199, 20, 200, 202, 207, 208, 209, 21, 219, 22, 221, 226, 228, 23, 233, 234, 237, 240, 242, 243, 243, 243, 244, 244, 244, 245, 245, 245, 247, 247, 247, 248, 250, 251, 252, 253, 263, 30, 31, 32, 32, 32, 35, 36, 384, 385, 386, 387, 388, 389, 39, 390, 391, 392, 393, 394, 395, 397, 398, 399, 40, 400, 41, 44, 460, 461, 466, 467, 468, 470, 480, 49, 5, 50, 500, 503, 507, 509, 510, 542, 549, 55, 550, 551, 552, 555, 556, 558, 560, 561, 562, 563, 564, 565, 579, 58, 586, 588, 59, 591, 592, 593, 6, 60, 600, 61, 610, 62, 626, 629, 63, 640, 642, 644, 645, 650, 652, 653, 66, 660, 661, 662, 664, 668, 676, 679, 68, 680, 681, 69, 7, 70, 77, 83, 84, 86, 86, 86, 87, 88, 90, 94]}

    for stride in dict_STRIDE.keys():
        for capec_id in dict_STRIDE[stride]:
            if capec_id in dict_all_capec_instances:
                if dict_all_capec_instances[capec_id].isLabelledWithSTRIDE and dict_all_capec_instances[capec_id].isLabelledWithSTRIDE == dict_stride_individuals[stride]:
                    continue
                dict_all_capec_instances[capec_id].isLabelledWithSTRIDE.append(dict_stride_individuals[stride])
            else:
                print(f"CAPEC-{capec_id} not found in ontology")

# function to get the capec ids from the stride file
def get_capec_ids_from_file():
    # Initialize empty list to store CAPEC IDs
    capec_ids = []
    with open('elevation-of-privilege.md', 'r') as file:
        for line in file:
            # Check if line contains "CAPEC-"
            if "CAPEC-" in line:
                # Extract the CAPEC-N part using string split
                start = line.find("CAPEC-")
                # Split at the first "]" and take the first part
                capec_part = line[start:].split(":")[0].split(" ")[0]

                capec_part = capec_part.split("-")[1]
                # Add to the list
                capec_ids.append(capec_part)

    # Sort the list numerically based on the number after "CAPEC-"
    sorted_capec = sorted(capec_ids)

    # Print the sorted list
    print("Sorted CAPEC IDs:")
    res = ""
    for capec in sorted_capec:
        res += str(capec) + ", "
    print(res)
    
if __name__ == "__main__":
    main()