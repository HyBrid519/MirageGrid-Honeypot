"""
Smart Adaptive Honeypot - Multi-Agent System (MAS)
Course Project: Agent-Based Systems

Architecture Overview:
- Task 1: HoneypotEnvironment (PEAS & State Manager)
- Task 2: BaseAgent (ABC & Contract Net Protocol)
- Task 3: SensorAgent (Perception & Regex Attack Detection)
- Task 4: PlannerAgent (BDI Architecture & STRIPS Planning)
- Task 5: DecisionAgent (Game Theory & Expected Utility)
- Task 6: ActuatorAgent (Deception Execution & Environment Modification)
- Task 7: LearningAgent (Critic, Q-Learning & JSON Knowledge Base)
- Task 8: DashboardAgent (Live Terminal Visualization)

Unified Beliefs Dictionary Keys (DO NOT RENAME):
- "command"  (str)       : Raw command entered by the attacker
- "attack"   (str)       : Detected attack type (e.g., SQL_Injection, XSS)
- "severity" (str)       : Attack severity level (Low, Medium, High, Critical)
- "plan"     (List[str]) : Ordered sequence of deception steps from STRIPS
- "risk"     (float)     : Calculated risk / Expected Utility score
- "action"   (str)       : Final deception action executed in the Honeypot
- "success"  (bool)      : True if attacker fell for the bait, False if suspicious
- "logs"     (List[str]) : Timestamped log entries for live visualization
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from datetime import datetime
import uuid
import re
import json
import os
import random
import numpy as np

# Optional import for Task 8 (DashboardAgent)
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


# =====================================================================
# TASK 1: ENVIRONMENT & STATE MANAGER
# =====================================================================
class HoneypotEnvironment:
    """
    Represents the simulated deceptive server (Honeypot).
    Maintains system state, fake files, open ports, and attacker suspicion level.
    """

    def __init__(self) -> None:
        self.open_ports: List[int] = [21, 22, 80, 443, 3306]
        self.fake_files: List[str] = ["index.html", "config.php.bak", "passwords.txt"]
        self.fake_db_tables: List[str] = ["users", "transactions", "admin_logs"]
        self.suspicion_level: float = 0.2  # Scale from 0.0 (trusting) to 1.0 (detected trap)

    def generate_attacker_command(self) -> str:
        """Simulates incoming attacker commands for testing the environment."""
        sample_commands = [
            "SELECT * FROM users WHERE '1'='1' --",
            "<script>alert('XSS')</script>",
            "GET /../../etc/passwd HTTP/1.1",
            "hydra -l admin -P rockyou.txt ssh://192.168.1.10",
            "nmap -sS -p 1-65535 192.168.1.10"
        ]
        return random.choice(sample_commands)

    def apply_deception(self, action: str) -> bool:
        """
        Updates the environment based on the ActuatorAgent's deception action.
        Returns True if the attacker falls for the trap, False if suspicion is too high.
        """
        # TODO (Task 1 Member): Expand environment state transitions and suspicion logic
        if action == "inject_fake_sql_rows":
            self.fake_db_tables.append(" leaked_credentials_backup")
            self.suspicion_level = max(0.0, self.suspicion_level - 0.05)
        elif action == "add_artificial_delay":
            self.suspicion_level = min(1.0, self.suspicion_level + 0.1)

        return self.suspicion_level < 0.75

    def process(self, beliefs: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry point to initialize or update the environment state."""
        # TODO (Task 1 Member): Customize environment perception updates
        if not beliefs.get("command"):
            beliefs["command"] = self.generate_attacker_command()

        timestamp = datetime.now().strftime("%H:%M:%S")
        beliefs["logs"].append(f"[{timestamp}] [ENV] Attacker executed: {beliefs['command']}")
        return beliefs


# =====================================================================
# TASK 2: BASE AGENT & CONTRACT NET PROTOCOL
# =====================================================================
class BaseAgent(ABC):
    """
    Abstract Base Class enforcing unified structure across all agents.
    Implements the Contract Net Protocol (Task Announcement, Bidding, Awarding).
    """

    def __init__(self, name: str) -> None:
        self.name: str = name
        self.agent_id: str = str(uuid.uuid4())[:8]

    def create_message(self, receiver: str, performative: str, content: Any) -> Dict[str, Any]:
        """Creates a standardized FIPA-ACL / Contract Net message with a unique UUID."""
        return {
            "message_id": str(uuid.uuid4()),
            "sender": self.name,
            "receiver": receiver,
            "performative": performative,  # e.g., CFP (Call For Proposal), PROPOSE, ACCEPT
            "content": content,
            "timestamp": datetime.now().isoformat()
        }

    def announce_task(self, task_description: str, candidates: List["BaseAgent"]) -> "BaseAgent":
        """
        Contract Net Protocol: Announces a task, collects bids, and awards the best agent.
        """
        # TODO (Task 2 Member): Expand bidding evaluation criteria
        best_agent = candidates[0]
        highest_bid = -1.0

        for candidate in candidates:
            bid = candidate.submit_bid(task_description)
            if bid > highest_bid:
                highest_bid = bid
                best_agent = candidate

        return best_agent

    def submit_bid(self, task_description: str) -> float:
        """Returns a readiness bid score (0.0 to 1.0) for the Contract Net Protocol."""
        return random.uniform(0.5, 1.0)

    @abstractmethod
    def perceive(self, beliefs: Dict[str, Any]) -> None:
        """Extracts relevant data from the shared beliefs dictionary."""
        pass

    @abstractmethod
    def decide(self) -> Any:
        """Executes internal reasoning to determine the next output."""
        pass

    @abstractmethod
    def act(self, beliefs: Dict[str, Any], decision: Any) -> Dict[str, Any]:
        """Updates the shared beliefs dictionary with the agent's output."""
        pass

    def process(self, beliefs: Dict[str, Any]) -> Dict[str, Any]:
        """Template method executing the standard Agent lifecycle: Perceive -> Decide -> Act."""
        self.perceive(beliefs)
        decision = self.decide()
        return self.act(beliefs, decision)


# =====================================================================
# TASK 3: SENSOR AGENT (PERCEPTION)
# =====================================================================
class SensorAgent(BaseAgent):
    """
    Analyzes raw attacker commands using Regular Expressions (re) to classify
    attack types and severity levels.
    """

    def __init__(self) -> None:
        super().__init__(name="SensorAgent")
        self.current_command: str = ""
        self.attack_patterns: Dict[str, str] = {
            "SQL_Injection": r"(?i)(select\s+.*\s+from|union\s+select|'1'='1|--)",
            "XSS": r"(?i)(<script>|alert\(|onerror=)",
            "Directory_Traversal": r"(\.\./|\.\.\|/etc/passwd|cmd\.exe)",
            "Brute_Force": r"(?i)(hydra|medusa|rockyou\.txt|login_attempt)",
            "Port_Scanning": r"(?i)(nmap|masscan|-sS|-p\s+1-65535)"
        }

    def perceive(self, beliefs: Dict[str, Any]) -> None:
        self.current_command = beliefs.get("command", "")

    def decide(self) -> Dict[str, str]:
        # TODO (Task 3 Member): Add more regex patterns and refine severity heuristics
        detected_attack = "Unknown_Recon"
        severity = "Low"

        for attack_type, pattern in self.attack_patterns.items():
            if re.search(pattern, self.current_command):
                detected_attack = attack_type
                severity = "High" if attack_type in ["SQL_Injection", "Directory_Traversal"] else "Medium"
                break

        return {"attack": detected_attack, "severity": severity}

    def act(self, beliefs: Dict[str, Any], decision: Dict[str, str]) -> Dict[str, Any]:
        beliefs["attack"] = decision["attack"]
        beliefs["severity"] = decision["severity"]
        timestamp = datetime.now().strftime("%H:%M:%S")
        beliefs["logs"].append(
            f"[{timestamp}] [SENSOR] Detected {decision['attack']} (Severity: {decision['severity']})"
        )
        return beliefs


# =====================================================================
# TASK 4: PLANNER AGENT (BDI & STRIPS PLANNING)
# =====================================================================
class PlannerAgent(BaseAgent):
    """
    Implements BDI (Beliefs, Desires, Intentions) and STRIPS planning
    (Preconditions, Add-List, Delete-List) to construct a multi-step deception plan.
    """

    def __init__(self) -> None:
        super().__init__(name="PlannerAgent")
        self.current_attack: str = ""
        self.desire: str = "Maximize attacker engagement without revealing Honeypot identity"

        # STRIPS Operators Definition
        self.strips_operators: Dict[str, Dict[str, List[str]]] = {
            "SQL_Injection": {
                "preconditions": ["Port_3306_Open", "SQL_Payload_Detected"],
                "add_list": ["Fake_DB_Schema_Exposed", "Attacker_Hooked"],
                "delete_list": ["Attacker_Suspicious"],
                "plan_steps": ["emulate_mysql_error", "inject_fake_sql_rows", "log_sql_payload"]
            },
            "XSS": {
                "preconditions": ["Port_80_Open", "Script_Tag_Detected"],
                "add_list": ["Fake_Session_Cookie_Leaked"],
                "delete_list": ["Attacker_Suspicious"],
                "plan_steps": ["render_fake_dom", "return_dummy_admin_cookie"]
            },
            "Directory_Traversal": {
                "preconditions": ["File_Request_Detected"],
                "add_list": ["Fake_Passwd_File_Served"],
                "delete_list": ["Attacker_Suspicious"],
                "plan_steps": ["generate_fake_etc_passwd", "monitor_file_access"]
            }
        }

    def perceive(self, beliefs: Dict[str, Any]) -> None:
        self.current_attack = beliefs.get("attack", "Unknown_Recon")

    def decide(self) -> List[str]:
        # TODO (Task 4 Member): Implement full STRIPS forward/backward state search
        if self.current_attack in self.strips_operators:
            return self.strips_operators[self.current_attack]["plan_steps"]
        return ["open_decoy_port", "add_artificial_delay", "record_fingerprint"]

    def act(self, beliefs: Dict[str, Any], decision: List[str]) -> Dict[str, Any]:
        beliefs["plan"] = decision
        timestamp = datetime.now().strftime("%H:%M:%S")
        beliefs["logs"].append(f"[{timestamp}] [PLANNER] Generated STRIPS Plan: {decision}")
        return beliefs


# =====================================================================
# TASK 5: DECISION & GAME THEORY AGENT
# =====================================================================
class DecisionAgent(BaseAgent):
    """
    Uses Game Theory (Payoff Matrix) and Expected Utility with NumPy
    to evaluate risk and select the optimal deception action.
    """

    def __init__(self) -> None:
        super().__init__(name="DecisionAgent")
        self.candidate_plan: List[str] = []
        self.severity: str = "Low"

        # Rows: Deception Strategies | Columns: Attacker Responses [Stay, Probe, Leave]
        self.payoff_matrix: np.ndarray = np.array([
            [10.0,  5.0, -5.0],  # High-Interaction Bait (e.g., fake DB rows)
            [ 6.0,  8.0, -2.0],  # Medium-Interaction Bait (e.g., fake errors)
            [ 2.0,  3.0,  1.0]   # Low-Risk Delay / Passive Observation
        ])

    def perceive(self, beliefs: Dict[str, Any]) -> None:
        self.candidate_plan = beliefs.get("plan", [])
        self.severity = beliefs.get("severity", "Low")

    def decide(self) -> Dict[str, Any]:
        # TODO (Task 5 Member): Calculate Nash Equilibrium & Expected Utility dynamically
        attacker_probabilities = np.array([0.5, 0.3, 0.2])  # P(Stay), P(Probe), P(Leave)
        expected_utilities = self.payoff_matrix.dot(attacker_probabilities)

        best_strategy_idx = int(np.argmax(expected_utilities))
        max_utility = float(expected_utilities[best_strategy_idx])

        # Convert utility into a normalized risk score (0.0 = safe, 1.0 = high risk)
        calculated_risk = round(max(0.05, min(0.95, 1.0 - (max_utility / 10.0))), 2)
        selected_action = self.candidate_plan[1] if len(self.candidate_plan) > 1 else "add_artificial_delay"

        return {"risk": calculated_risk, "selected_action": selected_action}

    def act(self, beliefs: Dict[str, Any], decision: Dict[str, Any]) -> Dict[str, Any]:
        beliefs["risk"] = decision["risk"]
        beliefs["action"] = decision["selected_action"]
        timestamp = datetime.now().strftime("%H:%M:%S")
        beliefs["logs"].append(
            f"[{timestamp}] [DECISION] Selected '{decision['selected_action']}' (Risk Score: {decision['risk']})"
        )
        return beliefs


# =====================================================================
# TASK 6: ACTUATOR AGENT (EXECUTION)
# =====================================================================
class ActuatorAgent(BaseAgent):
    """
    Executes the chosen deception action inside the Honeypot environment
    and evaluates whether the attacker fell for the bait.
    """

    def __init__(self, environment: HoneypotEnvironment) -> None:
        super().__init__(name="ActuatorAgent")
        self.env: HoneypotEnvironment = environment
        self.action_to_execute: str = ""
        self.current_risk: float = 0.5

    def perceive(self, beliefs: Dict[str, Any]) -> None:
        self.action_to_execute = beliefs.get("action", "add_artificial_delay")
        self.current_risk = beliefs.get("risk", 0.5)

    def decide(self) -> bool:
        # TODO (Task 6 Member): Generate realistic fake responses (hashes, banners, delays)
        env_success = self.env.apply_deception(self.action_to_execute)
        return env_success and (self.current_risk < 0.80)

    def act(self, beliefs: Dict[str, Any], decision: bool) -> Dict[str, Any]:
        beliefs["success"] = decision
        status_str = "SUCCESS (Attacker Hooked)" if decision else "FAILED (Attacker Suspicious)"
        timestamp = datetime.now().strftime("%H:%M:%S")
        beliefs["logs"].append(
            f"[{timestamp}] [ACTUATOR] Executed '{self.action_to_execute}' -> {status_str}"
        )
        return beliefs


# =====================================================================
# TASK 7: LEARNING AGENT (Q-LEARNING & CRITIC)
# =====================================================================
class LearningAgent(BaseAgent):
    """
    Implements the 4 components of a Learning Agent:
    Critic, Learning Element (Q-Learning), Performance Element, and Problem Generator.
    Persists learned Q-values to an external JSON file.
    """

    def __init__(self, q_table_file: str = "q_table.json") -> None:
        super().__init__(name="LearningAgent")
        self.q_table_file: str = q_table_file
        self.q_table: Dict[str, Dict[str, float]] = self._load_q_table()
        self.alpha: float = 0.1   # Learning rate
        self.gamma: float = 0.9   # Discount factor
        self.last_attack: str = ""
        self.last_action: str = ""
        self.last_success: bool = False

    def _load_q_table(self) -> Dict[str, Dict[str, float]]:
        if os.path.exists(self.q_table_file):
            try:
                with open(self.q_table_file, "r", encoding="utf-8") as file:
                    return json.load(file)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}

    def _save_q_table(self) -> None:
        with open(self.q_table_file, "w", encoding="utf-8") as file:
            json.dump(self.q_table, file, indent=4)

    def perceive(self, beliefs: Dict[str, Any]) -> None:
        self.last_attack = beliefs.get("attack", "Unknown_Recon")
        self.last_action = beliefs.get("action", "none")
        self.last_success = beliefs.get("success", False)

    def decide(self) -> float:
        # Critic Component: Assigns reward (+10 for hooking attacker, -10 if detected)
        reward = 10.0 if self.last_success else -10.0

        # Learning Element: Update Q-Value
        if self.last_attack not in self.q_table:
            self.q_table[self.last_attack] = {}

        old_q = self.q_table[self.last_attack].get(self.last_action, 0.0)
        new_q = round(old_q + self.alpha * (reward - old_q), 2)
        self.q_table[self.last_attack][self.last_action] = new_q
        self._save_q_table()

        # TODO (Task 7 Member): Add Problem Generator (epsilon-greedy exploration)
        return new_q

    def act(self, beliefs: Dict[str, Any], decision: float) -> Dict[str, Any]:
        timestamp = datetime.now().strftime("%H:%M:%S")
        beliefs["logs"].append(
            f"[{timestamp}] [LEARNING] Updated Q({self.last_attack}, {self.last_action}) = {decision}"
        )
        return beliefs


# =====================================================================
# TASK 8: DASHBOARD & VISUALIZATION AGENT
# =====================================================================
class DashboardAgent(BaseAgent):
    """
    Renders a live terminal dashboard showing attacker commands, BDI plans,
    Game Theory metrics, and color-coded execution logs.
    """

    def __init__(self) -> None:
        super().__init__(name="DashboardAgent")
        self.snapshot: Dict[str, Any] = {}

    def perceive(self, beliefs: Dict[str, Any]) -> None:
        self.snapshot = beliefs.copy()

    def decide(self) -> str:
        return "RENDER_RICH" if RICH_AVAILABLE else "RENDER_STANDARD"

    def act(self, beliefs: Dict[str, Any], decision: str) -> Dict[str, Any]:
        # TODO (Task 8 Member): Customize Rich panels/layout or build Streamlit view
        if decision == "RENDER_RICH":
            console = Console()
            table = Table(title="Smart Honeypot Multi-Agent System - Live State")
            table.add_column("Metric / Key", style="cyan", no_wrap=True)
            table.add_column("Current Value", style="magenta")

            table.add_row("Attacker Command", str(self.snapshot.get("command")))
            table.add_row("Detected Attack", f"{self.snapshot.get('attack')} ({self.snapshot.get('severity')})")
            table.add_row("STRIPS Plan", ", ".join(self.snapshot.get("plan", [])))
            table.add_row("Risk Score (Utility)", str(self.snapshot.get("risk")))
            table.add_row("Executed Action", str(self.snapshot.get("action")))
            table.add_row("Deception Success", str(self.snapshot.get("success")))

            console.print(table)
            console.print(Panel("\n".join(self.snapshot.get("logs", [])), title="Event Logs", border_style="green"))
        else:
            print("\n" + "=" * 65)
            print(" SMART HONEYPOT MAS - LIVE DASHBOARD ")
            print("=" * 65)
            print(f" [1] Command  : {self.snapshot.get('command')}")
            print(f" [2] Attack   : {self.snapshot.get('attack')} (Severity: {self.snapshot.get('severity')})")
            print(f" [3] BDI Plan : {self.snapshot.get('plan')}")
            print(f" [4] Risk     : {self.snapshot.get('risk')}")
            print(f" [5] Action   : {self.snapshot.get('action')}")
            print(f" [6] Success  : {self.snapshot.get('success')}")
            print("-" * 65)
            print(" Event Logs:")
            for log_entry in self.snapshot.get("logs", []):
                print(f"   {log_entry}")
            print("=" * 65 + "\n")

        return beliefs


# =====================================================================
# MAIN INTEGRATION & DUMMY DATA TESTING (REMOVE BEFORE PUSHING CLASS)
# =====================================================================
if __name__ == "__main__":
    # Unified Dummy Data Dictionary for testing individual classes
    shared_beliefs: Dict[str, Any] = {
        "command": "SELECT * FROM users WHERE '1'='1' --",
        "attack": "",
        "severity": "",
        "plan": [],
        "risk": 0.0,
        "action": "",
        "success": False,
        "logs": []
    }

    # Instantiate Environment and Agents
    env = HoneypotEnvironment()
    sensor = SensorAgent()
    planner = PlannerAgent()
    decision_maker = DecisionAgent()
    actuator = ActuatorAgent(environment=env)
    learner = LearningAgent()
    dashboard = DashboardAgent()

    # Run complete Multi-Agent pipeline
    shared_beliefs = env.process(shared_beliefs)
    shared_beliefs = sensor.process(shared_beliefs)
    shared_beliefs = planner.process(shared_beliefs)
    shared_beliefs = decision_maker.process(shared_beliefs)
    shared_beliefs = actuator.process(shared_beliefs)
    shared_beliefs = learner.process(shared_beliefs)
    shared_beliefs = dashboard.process(shared_beliefs)
