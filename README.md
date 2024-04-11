# PyRA

PyRA efficiently processes an ontology that describes the ICT infrastructure, including assets, data flows, security mechanisms, and CPEs of resources. The ontology also incorporates CAPECs for threat modeling and risk assessment, supported by SWRL rules for systematic mapping. With the help of the ontology reasoner, the tool can produce a threat model in seconds. Once threats have been identified, it automates risk assessment by computing the risk for each threat.

The tool also makes it easier to identify vulnerabilities by retrieving CVEs based on the CPEs provided in the ICT ontology. It adds to the ontology additional knowledge from the CVE, CWE, and ATT&CK knowledge bases, such as vulnerabilities and weaknesses affecting the resources in the system, as well as attack tactics and techniques that could exploit these vulnerabilities. When available, it also collects the suggested mitigations from CWE and ATT\&CK, thus streamlining the next steps in the vulnerability and risk management process.

## Getting started

PyRA heavily relies on BRON (https://github.com/ALFA-group/BRON/tree/master).
The project is fully documented, so you can choose the way you prefer to launch a working instance of BRON. I would suggest to use the docker, which only requires to clone the project and launch `sudo docker-compose up -d` from within the BRON project's folder.

Keep in mind that BRON database is not ready as soon as you run the aforementioned command. You can see the progress of its creation by running `docker logs bootstrap --follow`, where `bootstrap` is the name of the container that builds the database.

Also keep in mind that, if you run `sudo docker-compose down` from within BRON's project folder, you will need to wait for the database to be created from scratch next time. If you want to avoid that, use `sudo docker-compose stop` instead, and start only `brondb` container the next time you need it, running `sudo docker start brondb`.

As explained in the *"Setup PyRA"* section, you can also use the online version of BRON (available at http://bron.alfa.csail.mit.edu:8529/) if you do not want to create your own instance locally.

Remember to set the `LOCAL_DB` to:
 - `True` if you want PyRA to use your local instance of BRON
 - `False` if you want PyRA to use the online one

 \
 **PLEASE NOTE**\
 The online instance of BRON does not always work as expected, so you can try using it but be aware that **pyra** could arise some errors.


## Setup dev environment
Here is how to setup the Python development environment.
```
# Create a Python venv
python3 -m venv ~/.venvs/pyra-dev

# Activate the venv
source ~/.venvs/pyra-dev/bin/activate

# Export pythonpath
export PYTHONPATH=.
```
This is good practice to have all the required libraries relied to a virtual environment dedicated to this project, but it is not mandatory.
If you do create the *venv*, remember that you need to activate it every time before running pyra. See official documentation on *venv* for more details.

To install the **required** libraries (it does not matter if you created the *venv* or not), run
```
pip install -r requirements.txt
```
or
```
pip3 install -r requirements.txt
```
according to the version of *Python* and *pip* on your system.


## Setup PyRA
In `pyra.py`
- make sure to update the `src_path` variable to point to your ontology (by default, it looks for an ontology named `ontologiaBasev11.owl` placed in the same directory of `pyra.py`)
- you can also change `dst_path` to write the output file wherever you prefer
- you can set `LOCAL_DB` to `False` if you do not want to use a local BRON DB (but keep in mind that the one available online may not be up to date)

in `nistAPI.py`
- to reduce the time needed by PyRA to populate the ontology, you can request an API Key to NIST at https://nvd.nist.gov/developers/request-an-api-key. You can than set it in `nistAPI.py`:
   * replace `YOUR_API_KEY` with the key you receive from NIST
   * replace `headers = {}` with `headers = {"apiKey": API_KEY}` under the comment line `#Add API key into request header`


## Generating reports
This feature is not complete. The file `report.py` contains various functions, that should be reviewed, that can generate piecharts, Excel tables and LateX tables. Feel free to play with them and adapt them to your needs.
Here's a couple of things that must be done:
 - set the `owlready2.JAVA_EXE` to a valid path of a JRE in your system
 - set the path of the input ontology (in this case, it should be the one populated by PyRA)