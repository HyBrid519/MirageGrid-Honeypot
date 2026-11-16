# MirageGrid-Honeypot
Autonomous Multi-Agent Adaptive Honeypot - Huawei ICT Competition
# 🛡️ MirageGrid: Autonomous Multi-Agent Adaptive Honeypot
![Competition](https://img.shields.io/badge/11th_Huawei_ICT_Competition-Innovation_Track-red?style=for-the-badge)
![Huawei Cloud](https://img.shields.io/badge/Powered_By-Huawei_Cloud_(RDS_%7C_Redis_%7C_ECS)-blue?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.10%2B-yellow?style=for-the-badge&logo=python)
![AI](https://img.shields.io/badge/AI-Multi--Agent_System_(MAS)-green?style=for-the-badge)

**MirageGrid** is an intelligent, self-adapting cyber-deception framework powered by a **Multi-Agent System (MAS)**, **BDI/STRIPS Automated Planning**, **Game Theory**, and **Reinforcement Learning (Q-Learning)**, engineered to dynamically provision decoy resources on **Huawei Cloud**.

---

## 🏗️ System Architecture
![MirageGrid MAS Architecture](architecture.jpg)

---

## 🧠 8-Tier Multi-Agent Pipeline
| Module | Class Name | Core AI & Cloud Responsibility |
| :--- | :--- | :--- |
| **1. Environment** | `HoneypotEnvironment` | Maintains open ports, decoy files, fake DB schemas, and attacker suspicion metrics. |
| **2. Coordinator** | `BaseAgent` | Abstract Base Class enforcing FIPA-ACL / Contract Net Protocol task bidding & UUID messaging. |
| **3. Perception** | `SensorAgent` | Inspects raw payloads via Regex patterns to classify attack vectors and severity levels. |
| **4. Planning** | `PlannerAgent` | Synthesizes multi-step deception plans using BDI architecture and STRIPS operators. |
| **5. Decision** | `DecisionAgent` | Computes Expected Utility via a NumPy Game Theory Payoff Matrix to balance bait vs. risk. |
| **6. Execution** | `ActuatorAgent` | Executes deception actions and triggers on-demand **Huawei Cloud RDS** decoy tables. |
| **7. Learning** | `LearningAgent` | Evaluates outcomes via a Critic and updates the **Q-Learning** state-action matrix in JSON / **Huawei Cloud Redis**. |
| **8. Telemetry** | `DashboardAgent` | Streams real-time SOC execution logs and risk scores to a live terminal dashboard. |

---

## 🖥️ Live Prototype Execution (Proof of Concept)
Below is a live run of the MAS pipeline detecting a high-severity `SQL_Injection` attack, generating a STRIPS plan, calculating Game Theory risk, and updating the Q-Learning table:

![Live Terminal Dashboard](terminal.png)

---

## ☁️ Huawei Cloud Integration Architecture
* **Huawei Cloud RDS:** Dynamic, on-demand provisioning of isolated decoy SQL schemas (`users`, `transactions`, `leaked_credentials_backup`) when intrusion attempts are detected.
* **Huawei Cloud Redis:** Ultra-low-latency distributed memory bus for synchronizing `shared_beliefs` and the `q_table` across all 8 autonomous agents.
* **Huawei Cloud ECS & VPC:** Secure, isolated sandbox deployment for trapping attacker traffic away from production assets.
* **Huawei Cloud CodeArts:** Modular requirement tracking and collaborative build lifecycle management.

---

## 🚀 Quick Start (Local Simulation)
```bash
# 1. Clone the repository
git clone [https://github.com/YOUR_USERNAME/MirageGrid-Honeypot.git](https://github.com/YOUR_USERNAME/MirageGrid-Honeypot.git)
cd MirageGrid-Honeypot

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run the Multi-Agent pipeline
python smart_honeypot_mas.py
