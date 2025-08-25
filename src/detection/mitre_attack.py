from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum

class MitreTactic(Enum):
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"

@dataclass
class MitreTechnique:
    technique_id: str
    name: str
    tactic: MitreTactic
    description: str
    detection_patterns: List[str]
    risk_score: float

class MitreAttackFramework:
    def __init__(self):
        self.techniques = self._initialize_techniques()
    
    def _initialize_techniques(self) -> Dict[str, MitreTechnique]:
        techniques = {}
        
        # T1078 - Valid Accounts
        techniques["T1078"] = MitreTechnique(
            technique_id="T1078",
            name="Valid Accounts",
            tactic=MitreTactic.INITIAL_ACCESS,
            description="Adversaries may obtain and abuse credentials of existing accounts",
            detection_patterns=[
                "unusual_login_time",
                "unusual_login_location",
                "multiple_failed_logins",
                "privileged_account_usage"
            ],
            risk_score=6.0
        )
        
        # T1110 - Brute Force
        techniques["T1110"] = MitreTechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic=MitreTactic.CREDENTIAL_ACCESS,
            description="Adversaries may use brute force techniques to gain access to accounts",
            detection_patterns=[
                "rapid_failed_logins",
                "dictionary_attack",
                "password_spray"
            ],
            risk_score=7.0
        )
        
        # T1059 - Command and Scripting Interpreter
        techniques["T1059"] = MitreTechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic=MitreTactic.EXECUTION,
            description="Adversaries may abuse command and script interpreters",
            detection_patterns=[
                "suspicious_powershell",
                "suspicious_cmd",
                "suspicious_bash",
                "encoded_commands"
            ],
            risk_score=5.5
        )
        
        # T1055 - Process Injection
        techniques["T1055"] = MitreTechnique(
            technique_id="T1055",
            name="Process Injection",
            tactic=MitreTactic.DEFENSE_EVASION,
            description="Adversaries may inject code into processes",
            detection_patterns=[
                "process_hollowing",
                "dll_injection",
                "process_doppelganging"
            ],
            risk_score=8.0
        )
        
        # T1083 - File and Directory Discovery
        techniques["T1083"] = MitreTechnique(
            technique_id="T1083",
            name="File and Directory Discovery",
            tactic=MitreTactic.DISCOVERY,
            description="Adversaries may enumerate files and directories",
            detection_patterns=[
                "excessive_file_enumeration",
                "sensitive_directory_access",
                "bulk_file_listing"
            ],
            risk_score=4.0
        )
        
        # T1070 - Indicator Removal on Host
        techniques["T1070"] = MitreTechnique(
            technique_id="T1070",
            name="Indicator Removal on Host",
            tactic=MitreTactic.DEFENSE_EVASION,
            description="Adversaries may delete or alter generated artifacts on a host system",
            detection_patterns=[
                "log_deletion",
                "event_log_clearing",
                "file_deletion_bulk"
            ],
            risk_score=7.5
        )
        
        # T1021 - Remote Services
        techniques["T1021"] = MitreTechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic=MitreTactic.LATERAL_MOVEMENT,
            description="Adversaries may use valid accounts to log into a service",
            detection_patterns=[
                "unusual_rdp_access",
                "unusual_ssh_access",
                "service_account_lateral_movement"
            ],
            risk_score=6.5
        )
        
        return techniques
    
    def get_technique(self, technique_id: str) -> Optional[MitreTechnique]:
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: MitreTactic) -> List[MitreTechnique]:
        return [tech for tech in self.techniques.values() if tech.tactic == tactic]
    
    def get_all_techniques(self) -> List[MitreTechnique]:
        return list(self.techniques.values())