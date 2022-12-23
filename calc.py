import requests
import sys
import json
from cvss import CVSS3 
import re


class Constants:
    PATCH = "Patch"
    VENDOR_ADVISORY= "Vendor Advisory"
    THIRD_PARTY_ADVISORY= "Third Party Advisory"
    EXPLOIT= "Exploit"

def is_valid_cve(cve):
  pattern = r"CVE-\d{4}-\d{4}"
  return bool(re.match(pattern, cve))


def run_main(params):
    auth = None
    headers = {'Accept': 'application/json'}
    try:
        response = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}".format(params[0]), auth=auth, headers=headers)
    except:
        exit("A connection error occured, please retry")
    if response.status_code != 200:
        exit("CVE {} not found".format(params[0]))
    response_json = response.json()
    cve_references = response_json['vulnerabilities'][0]['cve']['references']
    cvss3_base_score = response_json['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
    cvss3_base_vector_string = response_json['vulnerabilities'][0]['cve']['metrics']['cvssMetricV31'][0]['cvssData']['vectorString']
    cvss3_final_vector_string = cvss3_base_vector_string


    total_refs_count = len(cve_references)
    vendor_adv_refs_count = 0
    third_party_adv_refs_count = 0
    patch_refs_count = 0
    exploit_refs_count = 0

    for cve_ref in cve_references:
        tags = cve_ref.get("tags",None)
        if tags != None:
            for tag in tags:
                match tag:
                    case Constants.PATCH:
                         patch_refs_count += 1
                    case Constants.VENDOR_ADVISORY:
                         vendor_adv_refs_count += 1
                    case Constants.THIRD_PARTY_ADVISORY:
                         third_party_adv_refs_count += 1
                    case Constants.EXPLOIT:
                         exploit_refs_count += 1


    # Temporal Exploit Code Maturity (E)
    if exploit_refs_count == 0:
        cvss3_final_vector_string += "/E:U"
    else:
        cvss3_final_vector_string += "/E:P"

    # Temporal Remediation Level (RL)
    if patch_refs_count > 0:
        cvss3_final_vector_string += "/RL:T"

    # Temporal Report Confidence (RC)
    if vendor_adv_refs_count > 0:
        cvss3_final_vector_string += "/RC:C"
    elif third_party_adv_refs_count > 0:
        cvss3_final_vector_string += "/RC:R"
    else:
        cvss3_final_vector_string += "/RC:U"
    


    cvss = CVSS3(cvss3_final_vector_string)

    #print("Total refs: {}".format(total_refs_count))
    #print("Vendor adv refs: {}".format(vendor_adv_refs_count))
    #print("Third party adv refs: {}".format(third_party_adv_refs_count))
    #print("Patch refs: {}".format(patch_refs_count))
    #print("Exploit refs: {}".format(exploit_refs_count))
    print("CVSS 3 base vector string: {}".format(cvss3_base_vector_string))
    print("CVSS 3 base score: {}".format(cvss3_base_score))
    print("CVSS 3 computed final vector string: {}".format(cvss3_final_vector_string))
    print("CVSS 3 computed temporal score: {}".format(cvss.scores()[1]))
    print("CVSS 3 computed overall score: {}".format(cvss.scores()[1]))

    

if __name__ == "__main__":
    params = sys.argv[1:]
    if not is_valid_cve(params[0]):
        exit("{} is not a valid CVE code".format(params[0]))
    run_main(params)