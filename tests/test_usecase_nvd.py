#!/usr/bin/env python3

from dataclasses import dataclass
from datetime import date,datetime
from json import loads
import logging
from os.path import dirname
from nvd_api import NvdApiClient
from random import getrandbits
from typing import Any, Dict, List, Optional

@dataclass
class NVDRecordConfigurationCPEMatch:
    vulnerable: bool
    criteria: str
    match_criteria_id: str

@dataclass
class NVDRecordConfigurationNode:
    operator: str
    cpe_match: List[NVDRecordConfigurationCPEMatch]

@dataclass
class NVDRecordConfiguration:
    nodes: List[NVDRecordConfigurationNode]
    negate: bool

@dataclass
class NVDRecordDescription:
    lang: str
    value: str

@dataclass
class NVDRecordWeakness:
    source: str
    type: str
    description: List[NVDRecordDescription]

class NVDRecordCVSSData:
    version: str
    vector_string: str
    base_score: float
    base_severity: str
    access_vector: str
    access_complexity: str
    authentication: str
    access_vector: str
    access_complexity: str
    attack_vector: str
    attack_complexity: str
    authentication: str
    confidentiality_impact: str
    integrity_impact: str
    availability_impact: str

@dataclass
class NVDRecordCVSSMetric:
    source: str
    type: str
    cvss_data: NVDRecordCVSSData
    base_severity: str
    exploitability_score: str
    impact_score: float
    ac_insuf_info: bool
    obtain_all_privilege: bool
    obtain_user_privilege: bool
    obtain_other_privilege: bool
    user_interaction_required: bool

@dataclass
class NVDRecordReference:
    url: str
    source: str
    tags: List[str]

@dataclass
class NVDRecord:
    id: str
    published: datetime
    last_modified: datetime
    descriptions: List[NVDRecordDescription]
    references: List[NVDRecordReference]
    source_identifier: str
    vuln_status: str
    cisa_exploit_add: date
    cisa_action_due: date
    cisa_required_action: str
    cisa_vulnerability_name: str
    metrics: Dict[str, List[NVDRecordCVSSMetric]]
    weaknesses: List[NVDRecordWeakness]
    configurations: List[NVDRecordConfiguration]
    evaluator_solution: Optional[str] = None
    evaluator_impact: Optional[str] = None
    evaluator_comment: Optional[str] = None

@dataclass
class BOMVEXRecordSourceMetadata:
    name: str
    url: str

@dataclass
class BOMVEXRecordReference:
    id: str
    source: BOMVEXRecordSourceMetadata

@dataclass
class BOMVEXRecordAdvisory:
    title: str
    url: str

@dataclass
class BOMVEXRecordCreditsIndividual:
    name: str

@dataclass
class BOMVEXRecordAnalysis:
    state: str
    justification: str
    response: List[str]
    detail: List[str]

@dataclass
class BOMVEXRecordVulnerability:
    id: str
    source: BOMVEXRecordSourceMetadata
    references: List[BOMVEXRecordReference]
    ratings: List[str]
    cwes: List[str]
    description: str
    detail: str
    recommendation: str
    advisories: List[BOMVEXRecordAdvisory]
    created: datetime
    published: datetime
    updated: datetime
    credits: List[BOMVEXRecordCreditsIndividual]
    analysis: List[BOMVEXRecordAnalysis]
    # TODO: Add affects?
    # affects: List[]

@dataclass
class BOMVEXRecord:
    vulnerabilities: List[BOMVEXRecordVulnerability]
    bomFormat: str
    specVersion: str
    version: int

@dataclass
class BOMVEXRecordRating:
    source: BOMVEXRecordSourceMetadata
    score: str
    severity: str
    method: str
    vector: str

def extract(cve_data: Dict[str, Dict]) -> List[NVDRecord]:
    """Extract raw NVD CVE records into structured instances of NVDRecord
    objects.
    """
    cves = []

    for raw_record in cve_data:
        record = raw_record.get('cve', {})
        logging.debug(f"Extracting NVD CVE {record.get('id', 'ECVENOID')}")
        try:
            cve = NVDRecord(**record)
            cves.append(cve)
        except Exception as err:
            logging.exception(f"Failed to extract NVD CVE {record.get('id', 'ECVENOID')}")
    
    return cves

def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))

def transform(cves: List[NVDRecord]) -> List[BOMVEXRecord]:
    """Transform NVD CVE records in the CycloneDX BOX VEX specification.
    """
    pass

def load(records: List[BOMVEXRecord]) -> List[str]:
    """Load the example BOM VEX records into the test SCITT Emulator API instance.
    """
    pass

if __name__ == '__main__':
    with open(f"{dirname(__file__)}/cves_in_kev.json") as fd:
        raw_data = fd.read()
        cve_data = loads(raw_data)
        cves = extract(cve_data)
        boms = transform(cves)
        len(boms)