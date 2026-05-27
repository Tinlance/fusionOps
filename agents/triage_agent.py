# agents/triage_agent.py — FusionOps Triage Agent
# Classifies and prioritises detection results from ThreatFade
# This is the first agentic component in the FusionOps pipeline

from dataclasses import dataclass
from typing import Optional
from datetime import datetime
from enum import Enum


class Priority(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class ThreatCategory(str, Enum):
    C2_EVASION        = "C2_EVASION"
    LOTL_ATTACK       = "LOTL_ATTACK"
    GNSS_JAMMING      = "GNSS_JAMMING"
    ANOMALOUS_ENTROPY = "ANOMALOUS_ENTROPY"
    AI_AGENT_ABUSE    = "AI_AGENT_ABUSE"
    FALSE_POSITIVE    = "FALSE_POSITIVE"
    UNKNOWN           = "UNKNOWN"


class RecommendedAction(str, Enum):
    BLOCK_IMMEDIATE      = "BLOCK_IMMEDIATE"
    ISOLATE_HOST         = "ISOLATE_HOST"
    ESCALATE_TO_ANALYST  = "ESCALATE_TO_ANALYST"
    INCREASE_MONITORING  = "INCREASE_MONITORING"
    LOG_AND_WATCH        = "LOG_AND_WATCH"
    DISMISS              = "DISMISS"


@dataclass
class TriageResult:
    """Output of the triage agent for a single detection event."""
    event_id: str
    triaged_at: str
    priority: Priority
    category: ThreatCategory
    recommended_action: RecommendedAction
    confidence: float           # 0.0 – 1.0
    reasoning: str
    mitre_ttp: Optional[str]
    escalate: bool
    auto_remediate: bool        # True = safe to remediate without human


class TriageAgent:
    """
    FusionOps Triage Agent.

    Takes a raw detection result from ThreatFade and outputs a
    structured triage decision — priority, category, recommended
    action, and whether to auto-remediate.

    Rules are deterministic for now (no LLM dependency).
    LLM-enhanced triage is the paid enterprise tier.
    """

    # Z-score thresholds (calibrated against ThreatFade validation data)
    Z_CRITICAL = 10.0    # Merlin QUIC baseline: 14.76
    Z_HIGH     = 5.0
    Z_MEDIUM   = 3.0
    Z_LOW      = 1.5

    # Entropy thresholds
    ENTROPY_HIGH_CIPHER   = 7.2   # Near-max entropy → encrypted C2
    ENTROPY_DROP_EVASION  = 2.0   # Very low entropy → C2 quieting

    def triage(self, detection: dict) -> TriageResult:
        """
        Main entry point. Pass in a DetectionResult dict from FusionOps API.

        Args:
            detection: dict with keys: event_id, detected, score,
                       entropy, drop_ratio, z_outlier, mitre_ttp, severity

        Returns:
            TriageResult with full classification and recommended action
        """
        if not detection.get("detected", False):
            return self._not_detected(detection)

        z      = float(detection.get("z_outlier", 0))
        ent    = float(detection.get("entropy", 0))
        score  = float(detection.get("score", 0))
        drop   = float(detection.get("drop_ratio", 0))
        mitre  = detection.get("mitre_ttp")
        ev_id  = detection.get("event_id", "unknown")

        category  = self._classify_category(z, ent, drop, mitre)
        priority  = self._assign_priority(z, score, category)
        action    = self._recommend_action(priority, category)
        confidence = self._compute_confidence(z, score, ent)
        reasoning  = self._build_reasoning(z, ent, drop, score, category, priority)

        return TriageResult(
            event_id=ev_id,
            triaged_at=datetime.utcnow().isoformat() + "Z",
            priority=priority,
            category=category,
            recommended_action=action,
            confidence=round(confidence, 3),
            reasoning=reasoning,
            mitre_ttp=mitre,
            escalate=(priority in [Priority.CRITICAL, Priority.HIGH]),
            auto_remediate=(
                priority == Priority.LOW and
                action == RecommendedAction.LOG_AND_WATCH
            ),
        )

    # ── Classification helpers ────────────────────────────────────────────────

    def _classify_category(
        self, z: float, ent: float, drop: float, mitre: Optional[str]
    ) -> ThreatCategory:
        """Classify the threat type from detection signals."""

        # C2 quieting: high z-score + significant entropy drop
        if z >= self.Z_HIGH and drop > 0.3:
            return ThreatCategory.C2_EVASION

        # High-entropy encrypted channel: classic C2 over QUIC/TLS
        if ent >= self.ENTROPY_HIGH_CIPHER and z >= self.Z_MEDIUM:
            return ThreatCategory.C2_EVASION

        # Very low entropy: C2 quieting / LOTL blending
        if ent <= self.ENTROPY_DROP_EVASION and z >= self.Z_LOW:
            return ThreatCategory.LOTL_ATTACK

        # MITRE T1027 = obfuscated C2
        if mitre and "T1027" in str(mitre):
            return ThreatCategory.C2_EVASION

        # MITRE T1499 = denial / GNSS-related patterns
        if mitre and "T1499" in str(mitre):
            return ThreatCategory.GNSS_JAMMING

        # Anomalous entropy without clear C2 signature
        if z >= self.Z_MEDIUM:
            return ThreatCategory.ANOMALOUS_ENTROPY

        return ThreatCategory.UNKNOWN

    def _assign_priority(
        self, z: float, score: float, category: ThreatCategory
    ) -> Priority:
        """Assign priority from z-score + score + category."""

        if z >= self.Z_CRITICAL or score >= 0.90:
            return Priority.CRITICAL

        if z >= self.Z_HIGH or score >= 0.70:
            return Priority.HIGH

        if category == ThreatCategory.C2_EVASION:
            return Priority.HIGH     # Always escalate known C2 patterns

        if z >= self.Z_MEDIUM or score >= 0.45:
            return Priority.MEDIUM

        if z >= self.Z_LOW or score >= 0.25:
            return Priority.LOW

        return Priority.INFO

    def _recommend_action(
        self, priority: Priority, category: ThreatCategory
    ) -> RecommendedAction:
        """Map priority + category to a recommended action."""

        if priority == Priority.CRITICAL:
            if category in [ThreatCategory.C2_EVASION, ThreatCategory.LOTL_ATTACK]:
                return RecommendedAction.ISOLATE_HOST
            return RecommendedAction.BLOCK_IMMEDIATE

        if priority == Priority.HIGH:
            return RecommendedAction.ESCALATE_TO_ANALYST

        if priority == Priority.MEDIUM:
            return RecommendedAction.INCREASE_MONITORING

        if priority == Priority.LOW:
            return RecommendedAction.LOG_AND_WATCH

        return RecommendedAction.DISMISS

    def _compute_confidence(self, z: float, score: float, ent: float) -> float:
        """
        Composite confidence score (0.0–1.0).
        Weights: z-score 50%, detection score 35%, entropy signal 15%.
        """
        z_norm    = min(z / self.Z_CRITICAL, 1.0)
        ent_norm  = abs(ent - 4.0) / 4.0    # 4.0 = neutral entropy
        ent_norm  = min(ent_norm, 1.0)

        return (z_norm * 0.50) + (score * 0.35) + (ent_norm * 0.15)

    def _build_reasoning(
        self, z: float, ent: float, drop: float,
        score: float, category: ThreatCategory, priority: Priority
    ) -> str:
        """Generate human-readable reasoning for the triage decision."""

        parts = [
            f"Z-score {z:.2f} ({self._z_label(z)}).",
            f"Detection score {score:.3f}.",
            f"Entropy {ent:.3f} ({self._ent_label(ent)}).",
        ]

        if drop > 0.2:
            parts.append(f"Drop ratio {drop:.2f} — possible C2 quieting pattern.")

        parts.append(f"Classified as {category.value}.")
        parts.append(f"Priority set to {priority.value}.")

        return " ".join(parts)

    def _z_label(self, z: float) -> str:
        if z >= self.Z_CRITICAL: return "CRITICAL — far above baseline"
        if z >= self.Z_HIGH:     return "HIGH anomaly"
        if z >= self.Z_MEDIUM:   return "MEDIUM anomaly"
        if z >= self.Z_LOW:      return "LOW anomaly"
        return "within normal range"

    def _ent_label(self, ent: float) -> str:
        if ent >= self.ENTROPY_HIGH_CIPHER: return "high — encrypted channel likely"
        if ent <= self.ENTROPY_DROP_EVASION: return "low — C2 quieting or LOTL"
        return "normal range"

    def _not_detected(self, detection: dict) -> TriageResult:
        """Return a clean INFO result for non-detection events."""
        return TriageResult(
            event_id=detection.get("event_id", "unknown"),
            triaged_at=datetime.utcnow().isoformat() + "Z",
            priority=Priority.INFO,
            category=ThreatCategory.FALSE_POSITIVE,
            recommended_action=RecommendedAction.DISMISS,
            confidence=0.0,
            reasoning="ThreatFade did not detect a threat in this signal.",
            mitre_ttp=None,
            escalate=False,
            auto_remediate=False,
        )


# ── Convenience function ──────────────────────────────────────────────────────

def run_triage(detection: dict) -> dict:
    """
    Module-level convenience function.
    Returns TriageResult as a plain dict for API serialisation.
    """
    agent = TriageAgent()
    result = agent.triage(detection)
    return {
        "event_id":           result.event_id,
        "triaged_at":         result.triaged_at,
        "priority":           result.priority.value,
        "category":           result.category.value,
        "recommended_action": result.recommended_action.value,
        "confidence":         result.confidence,
        "reasoning":          result.reasoning,
        "mitre_ttp":          result.mitre_ttp,
        "escalate":           result.escalate,
        "auto_remediate":     result.auto_remediate,
    }