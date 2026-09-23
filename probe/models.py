
from dataclasses import dataclass, asdict
from typing import Optional
from datetime import datetime , UTC 


@dataclass
class Finding:
    """
    Represents one security finding discovered by PROBE.
    """

    name: str
    severity: str
    category: str
    description: str

    target: Optional[str] = None
    evidence: Optional[str] = None

    discovered_at: str = ""

    def __post_init__(self):
        if not self.discovered_at:
            self.discovered_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        self.severity = self.severity.upper()

    def to_dict(self):
        return asdict(self)


def create_finding(
    name,
    severity,
    category,
    description,
    target=None,
    evidence=None,
):
    """
    Helper function for creating a Finding object.
    """

    return Finding(
        name=name,
        severity=severity,
        category=category,
        description=description,
        target=target,
        evidence=evidence,
    )
