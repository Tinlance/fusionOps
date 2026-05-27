# agents/remediation_agent.py — FusionOps Remediation Agent
# Takes a triage decision and produces specific remediation actions
# This is what separates FusionOps from a plain scanner
#
# Open-core tier: generates remediation plan + audit log entry
# Paid tier (future): executes actions automatically via integrations

from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from enum import Enum


class ActionStatus(str, Enum):
    SUGGESTED  = "SUGGESTED"    # Free tier — human must execute
    EXECUTED   = "EXECUTED"     # Paid tier — agent executed it
    SKIPPED    = "SKIPPED"      # Not applicable for this threat
    FAILED     = "FAILED"       # Execution attempted but failed


class ActionType(str, Enum):
    NETWORK    = "NETWORK"      # Block IP, isolate host, firewall rule
    PROCESS    = "PROCESS"      # Kill process, suspend service
    FILE       = "FILE"         # Quarantine file, remove artifact
    LOG        = "LOG"          # Log event, create audit trail
    ALERT      = "ALERT"        # Notify analyst, send alert
    ESCALATE   = "ESCALATE"     # Escalate to human / SIEM


@dataclass
class RemediationAction:
    """A single remediation step."""
    action_id: str
    action_type: ActionType
    status: ActionStatus
    title: str
    description: str
    command: Optional[str]          # Actual command to run (if applicable)
    auto_executable: bool           # True = safe to auto-run (paid tier)
    priority_order: int             # 1 = do first


@dataclass
class RemediationPlan:
    """Complete remediation plan for a single detection + triage event."""
    plan_id: str
    event_id: str
    created_at: str
    threat_category: str
    priority: str
    recommended_action: str
    actions: List[RemediationAction]
    audit_entry: str
    estimated_effort: str           # e.g. "5 minutes", "immediate"
    requires_human: bool
    open_core_note: str             # Honest note about what's free vs paid


class RemediationAgent:
    """
    FusionOps Remediation Agent.

    Takes a triage result and produces a structured remediation plan
    with specific, actionable steps ordered by priority.

    Free tier: generates the plan — human executes it.
    Paid tier (enterprise): executes NETWORK and LOG actions automatically.

    No LLM required — all logic is deterministic and auditable.
    """

    def remediate(self, triage: dict, detection: dict) -> RemediationPlan:
        """
        Main entry point.

        Args:
            triage:    dict output from triage_agent.run_triage()
            detection: dict output from ThreatFade detection

        Returns:
            RemediationPlan with ordered list of actions and audit entry
        """
        import uuid

        category   = triage.get("category", "UNKNOWN")
        priority   = triage.get("priority", "LOW")
        action     = triage.get("recommended_action", "LOG_AND_WATCH")
        event_id   = triage.get("event_id", detection.get("event_id", "unknown"))
        mitre      = triage.get("mitre_ttp") or detection.get("mitre_ttp", "")
        source     = detection.get("source", "unknown")
        z_score    = detection.get("z_outlier", 0)
        entropy    = detection.get("entropy", 0)
        severity   = detection.get("severity", "LOW")

        actions = self._build_actions(
            category=category,
            priority=priority,
            recommended_action=action,
            source=source,
            z_score=float(z_score),
            mitre=str(mitre),
            event_id=event_id,
        )

        audit_entry = self._build_audit_entry(
            event_id=event_id,
            category=category,
            priority=priority,
            action=action,
            mitre=mitre,
            z_score=float(z_score),
            entropy=float(entropy),
            severity=severity,
            source=source,
        )

        requires_human = priority in ["CRITICAL", "HIGH"] or action == "ESCALATE_TO_ANALYST"
        effort = self._estimate_effort(priority, action)

        return RemediationPlan(
            plan_id=str(uuid.uuid4()),
            event_id=event_id,
            created_at=datetime.utcnow().isoformat() + "Z",
            threat_category=category,
            priority=priority,
            recommended_action=action,
            actions=actions,
            audit_entry=audit_entry,
            estimated_effort=effort,
            requires_human=requires_human,
            open_core_note=(
                "Action suggestions generated. "
                "Auto-execution of NETWORK and PROCESS actions "
                "requires FusionOps Enterprise tier."
            ),
        )

    # ── Action builders ───────────────────────────────────────────────────────

    def _build_actions(
        self,
        category: str,
        priority: str,
        recommended_action: str,
        source: str,
        z_score: float,
        mitre: str,
        event_id: str,
    ) -> List[RemediationAction]:
        """Build ordered list of remediation actions based on threat profile."""

        import uuid
        actions = []
        order = 1

        # ── Always: create audit log entry ───────────────────────────────────
        actions.append(RemediationAction(
            action_id=str(uuid.uuid4()),
            action_type=ActionType.LOG,
            status=ActionStatus.EXECUTED,   # Always auto-executed (free tier)
            title="Create audit log entry",
            description=f"Log detection event {event_id} to audit trail with full context.",
            command=None,
            auto_executable=True,
            priority_order=order,
        ))
        order += 1

        # ── CRITICAL / HIGH: isolate or block ────────────────────────────────
        if priority in ["CRITICAL", "HIGH"]:

            if category in ["C2_EVASION", "LOTL_ATTACK"]:
                actions.append(RemediationAction(
                    action_id=str(uuid.uuid4()),
                    action_type=ActionType.NETWORK,
                    status=ActionStatus.SUGGESTED,
                    title="Isolate affected host from network",
                    description=(
                        f"Source '{source}' shows C2 evasion patterns (z-score {z_score:.2f}). "
                        "Immediately isolate this host to prevent lateral movement. "
                        "Apply firewall rule to block all outbound traffic except management."
                    ),
                    command="iptables -I OUTPUT -s {host_ip} -j DROP",
                    auto_executable=False,   # Requires paid tier
                    priority_order=order,
                ))
                order += 1

                actions.append(RemediationAction(
                    action_id=str(uuid.uuid4()),
                    action_type=ActionType.NETWORK,
                    status=ActionStatus.SUGGESTED,
                    title="Block C2 communication channel",
                    description=(
                        "Block the identified C2 communication path at the network perimeter. "
                        "Update firewall rules to drop traffic matching entropy signature."
                    ),
                    command="ufw deny out from any to {c2_ip}",
                    auto_executable=False,
                    priority_order=order,
                ))
                order += 1

            if category == "GNSS_JAMMING":
                actions.append(RemediationAction(
                    action_id=str(uuid.uuid4()),
                    action_type=ActionType.ALERT,
                    status=ActionStatus.SUGGESTED,
                    title="Alert physical security team",
                    description=(
                        "GNSS jamming pattern detected. "
                        "Notify physical security and operations teams immediately. "
                        "This may indicate a coordinated physical + cyber attack."
                    ),
                    command=None,
                    auto_executable=False,
                    priority_order=order,
                ))
                order += 1

        # ── All detections: capture forensic snapshot ─────────────────────────
        if priority in ["CRITICAL", "HIGH", "MEDIUM"]:
            actions.append(RemediationAction(
                action_id=str(uuid.uuid4()),
                action_type=ActionType.FILE,
                status=ActionStatus.SUGGESTED,
                title="Capture forensic memory snapshot",
                description=(
                    "Before taking any remediation action, capture a full memory "
                    "snapshot of the affected system for forensic analysis. "
                    "This preserves evidence for incident investigation."
                ),
                command="volatility -f {memory_dump} --profile={os_profile} pslist",
                auto_executable=False,
                priority_order=order,
            ))
            order += 1

        # ── CRITICAL / HIGH: escalate to analyst ─────────────────────────────
        if priority in ["CRITICAL", "HIGH"] or recommended_action == "ESCALATE_TO_ANALYST":
            mitre_ref = f" (MITRE {mitre})" if mitre else ""
            actions.append(RemediationAction(
                action_id=str(uuid.uuid4()),
                action_type=ActionType.ESCALATE,
                status=ActionStatus.SUGGESTED,
                title="Escalate to security analyst",
                description=(
                    f"Priority {priority} threat detected{mitre_ref}. "
                    "Assign to senior security analyst for manual investigation. "
                    "Include this FusionOps report and the raw detection data."
                ),
                command=None,
                auto_executable=False,
                priority_order=order,
            ))
            order += 1

        # ── MEDIUM: increase monitoring ───────────────────────────────────────
        if priority == "MEDIUM" or recommended_action == "INCREASE_MONITORING":
            actions.append(RemediationAction(
                action_id=str(uuid.uuid4()),
                action_type=ActionType.NETWORK,
                status=ActionStatus.SUGGESTED,
                title="Increase monitoring frequency",
                description=(
                    f"Anomalous signal from '{source}' (z-score {z_score:.2f}). "
                    "Increase detection scan frequency from every 60s to every 10s "
                    "for the next 24 hours. Set alert threshold to z-score > 1.5."
                ),
                command=None,
                auto_executable=False,
                priority_order=order,
            ))
            order += 1

        # ── LOW / INFO: log and watch ─────────────────────────────────────────
        if priority in ["LOW", "INFO"]:
            actions.append(RemediationAction(
                action_id=str(uuid.uuid4()),
                action_type=ActionType.LOG,
                status=ActionStatus.EXECUTED,
                title="Log event and continue monitoring",
                description=(
                    "Low-priority anomaly logged. "
                    "No immediate action required. "
                    "Continue baseline monitoring. "
                    "Review if pattern persists over next 6 hours."
                ),
                command=None,
                auto_executable=True,
                priority_order=order,
            ))
            order += 1

        # ── Always: update threat intelligence ───────────────────────────────
        actions.append(RemediationAction(
            action_id=str(uuid.uuid4()),
            action_type=ActionType.LOG,
            status=ActionStatus.EXECUTED,
            title="Update threat intelligence feed",
            description=(
                "Add detection signature to local threat intelligence database. "
                f"Category: {category}. Z-score: {z_score:.2f}. "
                "This improves future detection accuracy."
            ),
            command=None,
            auto_executable=True,
            priority_order=order,
        ))

        return sorted(actions, key=lambda a: a.priority_order)

    def _build_audit_entry(
        self, event_id, category, priority, action,
        mitre, z_score, entropy, severity, source
    ) -> str:
        """Generate a human-readable audit log entry."""
        ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        mitre_str = f" | MITRE: {mitre}" if mitre else ""
        return (
            f"[{ts}] FUSIONOPS REMEDIATION EVENT "
            f"| ID: {event_id} "
            f"| Source: {source} "
            f"| Category: {category} "
            f"| Priority: {priority} "
            f"| Severity: {severity} "
            f"| Z-Score: {z_score:.2f} "
            f"| Entropy: {entropy:.3f}"
            f"{mitre_str} "
            f"| Action: {action} "
            f"| Engine: FusionOps v0.3.0"
        )

    def _estimate_effort(self, priority: str, action: str) -> str:
        """Estimate human effort required to execute the remediation plan."""
        if priority == "CRITICAL":
            return "Immediate — act within 5 minutes"
        if priority == "HIGH":
            return "Urgent — act within 30 minutes"
        if priority == "MEDIUM":
            return "Standard — act within 4 hours"
        if action == "LOG_AND_WATCH":
            return "Minimal — automated, no human action needed"
        return "Low — review within 24 hours"


# ── Convenience function ──────────────────────────────────────────────────────

def run_remediation(triage: dict, detection: dict) -> dict:
    """
    Module-level convenience function.
    Returns RemediationPlan as a plain dict for API serialisation.
    """
    agent = RemediationAgent()
    plan  = agent.remediate(triage, detection)

    return {
        "plan_id":           plan.plan_id,
        "event_id":          plan.event_id,
        "created_at":        plan.created_at,
        "threat_category":   plan.threat_category,
        "priority":          plan.priority,
        "recommended_action": plan.recommended_action,
        "estimated_effort":  plan.estimated_effort,
        "requires_human":    plan.requires_human,
        "open_core_note":    plan.open_core_note,
        "audit_entry":       plan.audit_entry,
        "actions": [
            {
                "action_id":       a.action_id,
                "action_type":     a.action_type.value,
                "status":          a.status.value,
                "title":           a.title,
                "description":     a.description,
                "command":         a.command,
                "auto_executable": a.auto_executable,
                "priority_order":  a.priority_order,
            }
            for a in plan.actions
        ],
    }