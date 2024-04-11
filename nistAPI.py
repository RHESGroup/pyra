import asyncio
import aiohttp
import requests
import time
import classes

# You can get your own API key at https://nvd.nist.gov/developers/request-an-api-key
# Replace "YOUR_API_KEY" with your actual API key, then de-comment the line 'headers = {"apiKey": "API_KEY"}' in the get_cves_for_cpe_async function
# The public rate limit (without an API key) is 5 requests in a rolling 30 second window; 
# the rate limit with an API key is 50 requests in a rolling 30 second window. (see https://nvd.nist.gov/developers/start-here)
API_KEY = "YOUR_API_KEY"

# Global variables to keep track of rate limiting
REQUESTS_LIMIT = 5  # 5 requests per 30 seconds
TIME_WINDOW = 30  # 30 seconds
request_count = 0
last_request_time = 0

FILTER_CVE_YEAR = 2021
FILTER_RECENTS = True


async def make_request(url, headers, params):
    """
    Makes an asynchronous HTTP GET request to the specified URL with the given headers and parameters.

    Args:
        url (str): The URL to send the request to.
        headers (dict): The headers to include in the request.
        params (dict): The parameters to include in the request.

    Returns:
        dict: The JSON response data if the request is successful, None otherwise.
    """
    global request_count, last_request_time

    current_time = time.time()

    if request_count >= REQUESTS_LIMIT and current_time - last_request_time < TIME_WINDOW:
        sleep_duration = TIME_WINDOW - (current_time - last_request_time)
        await asyncio.sleep(sleep_duration)
        request_count = 0  # Reset request count after sleeping

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params=params) as response:
            # print("Result:", response.status)
            if not response.ok:
                return None
            
            data = await response.json()

            request_count += 1
            last_request_time = current_time

            return data

def get_cves_for_cpe(cpe):
    """
    Retrieves Common Vulnerabilities and Exposures (CVE) data for a given Common Platform Enumeration (CPE).

    Args:
        cpe (str): The Common Platform Enumeration (CPE) string.

    Returns:
        list: A list of CVE data associated with the given CPE.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    data = loop.run_until_complete(get_cves_for_cpe_async(cpe))
    return data

async def get_cves_for_cpe_async(cpe):
    """
    Retrieves a list of Common Vulnerabilities and Exposures (CVEs) associated with a given Common Platform Enumeration (CPE).

    Args:
        cpe (str): The Common Platform Enumeration (CPE) representing the software or hardware product.

    Returns:
        list: A list of CVE objects containing information about each CVE, including the CVE ID, description, vulnerability status, base score, CVSS vector string, exploitability score, and base severity.
    """
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Add API key into request header 
    headers = {} # headers = {"apiKey": API_KEY}

    # Split CPE into vendor, product, and version and check that all of them
    # are defined (i.e., different from "*" and "-")
    cpe_parts = cpe.split(":")
    use_cpeName = False

    if len(cpe_parts) >= 6:  # Check if the list has at least 6 elements
        use_cpeName = True
        for i in range(2, 6):
            if cpe_parts[i] == "*" or cpe_parts[i] == "-":
                use_cpeName = False
                break

    query_params = {
        "resultsPerPage": 2000,  # Number of results per page
        "startIndex": 0  # Starting index for pagination
    }

    if use_cpeName:
        query_params["cpeName"] = cpe
    else:
        # string composed by first 5 parts of cpe
        string = ":".join(cpe_parts[:5])
        query_params["virtualMatchString"] = string

    cve_list = []

    while True:
        data = await make_request(base_url, headers=headers, params=query_params)
        if data == None:
            return cve_list

        if "vulnerabilities" in data:
            cve_items = data["vulnerabilities"]
            # print("Number of CVEs: ", len(cve_items))

            for cve_item in cve_items:
                cve_id = cve_item["cve"]["id"]

                # Check if the CVE is from 2021 or later (to avoid old CVEs that are not relevant anymore)
                substrs = cve_id.split("-")
                if substrs[1] >= "2021" or not FILTER_RECENTS:
                    cve = classes.CVE(cve_id, get_description(cve_item), get_vuln_status(cve_item), get_base_score(cve_item), get_cvss_vstring(cve_item), get_exploitability_score(cve_item), get_base_severity(cve_item))
                    cve_list.append(cve)

        if "totalResults" in data and "startIndex" in data:
            total_results = data["totalResults"]
            start_index = data["startIndex"]
            if start_index + query_params["resultsPerPage"] >= total_results:
                break
            query_params["startIndex"] = start_index + query_params["resultsPerPage"]
        else:
            break

    return cve_list

def get_description(cve_item):
    descriptions = cve_item["cve"]["descriptions"]
    for d in descriptions:
        if d["lang"] == "en":
            return d["value"]
    
    return ""

def get_cwes(cve_item):
    cwes_list = []
    cwes = cve_item["cve"]["weaknesses"]
    for c in cwes:
        description = c["description"]
        for d in description:
            if d["lang"] == "en" and d["value"] != "NVD-CWE-noinfo":
                cwes_list.append(d["value"])
    
    return cwes_list

def get_vuln_status(cve_item):
    return cve_item["cve"]["vulnStatus"]

def get_cvss(cve_item):
    metrics = sorted(cve_item["cve"]["metrics"].keys(), reverse=True)
    return cve_item["cve"]["metrics"][metrics[0]][0]

def get_cvss_data(cve_item):
    cvss = get_cvss(cve_item)
    return cvss["cvssData"]

def get_cvss_vstring(cve_item):
    cvss_data = get_cvss_data(cve_item)
    return cvss_data["vectorString"]

def get_base_score(cve_item):
    cvss_data = get_cvss_data(cve_item)
    return cvss_data["baseScore"]

def get_impact_score(cve_item):
    cvss = get_cvss(cve_item)
    return cvss.get("impactScore", None)

def get_exploitability_score(cve_item):
    cvss = get_cvss(cve_item)
    return cvss.get("exploitabilityScore", None)

def get_base_severity(cve_item):
    cvss_data = get_cvss_data(cve_item)
    if "baseSeverity" in cvss_data:
        return cvss_data["baseSeverity"]
    return ""


# This main is only intended to test the functionality of the NIST API
if __name__ == "__main__":
    # target_cpe = "cpe:2.3:h:dell:alienware_13_r2"  # Replace with your target CPE
    # target_cpe = "cpe:2.3:o:microsoft:windows_10:1607"  # Replace with your target CPE
    # target_cpe = "cpe:2.3:a:mozilla:thunderbird:101.0"  # Replace with your target CPE
    # target_cpe = "cpe:2.3:a:apple:numbers:*:*:*:*:*:mac_os_x:*:*"  # Replace with your target CPE
    target_cpe = "cpe:2.3:o:microsoft:windows_11_22h2:*:*:*:*:*:*:x64:*"  # Replace with your target CPE
    cve_list = get_cves_for_cpe(target_cpe)

    print(f"Total CVEs for {target_cpe}: {len(cve_list)}")
    # print("CVE List:")
    # for cve_id in cve_list:
    #     print(cve_id)
