from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Literal, Optional


Severity = Literal["critical", "high", "medium", "low"]
Stage = Literal["investigate", "triage", "fix", "verify", "report"]


@dataclass
class Finding:
	id: str
	file_path: str
	line_number: int
	severity: Severity
	issue_type: str
	raw_code: str
	plain_english_title: str
	attacker_impact: str
	is_real: Optional[bool] = None
	triage_reasoning: Optional[str] = None
	original_content: Optional[str] = None
	fixed_content: Optional[str] = None
	verification_proof: Optional[str] = None
	attempts: int = 0
	approved: bool = False
	rejected: bool = False

	def to_dict(self):
		return asdict(self)


@dataclass
class AgentEvent:
	timestamp: str
	stage: Stage
	event_type: str
	message: str
	details: Optional[dict[str, Any]] = None

	@classmethod
	def make(cls, stage: Stage, event_type: str, message: str, details=None):
		return cls(
			timestamp=datetime.now().isoformat(timespec="seconds"),
			stage=stage,
			event_type=event_type,
			message=message,
			details=details or {},
		)

	def to_dict(self):
		return asdict(self)
