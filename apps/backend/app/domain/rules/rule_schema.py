from pydantic import BaseModel, Field


class MitreMapping(BaseModel):
    tactic: str
    technique_id: str | None = None
    technique: str | None = None


class RuleOutput(BaseModel):
    severity: str = Field(pattern="^(low|medium|high|critical)$")
    confidence: str = Field(pattern="^(low|medium|high)$")
    risk_score: int = Field(ge=0, le=100)
    tags: list[str] = Field(default_factory=list)
    mitre: MitreMapping | None = None
    false_positives: list[str] = Field(default_factory=list)
    response_recommendations: list[str] = Field(default_factory=list)


class ThresholdCondition(BaseModel):
    type: str = Field(default="threshold", pattern="^threshold$")
    group_by: list[str] = Field(min_length=1)
    window: str = Field(description="e.g. 5m, 10m, 1h")
    count: int = Field(ge=1)
    cooldown: str | None = Field(default="10m")


class Rule(BaseModel):
    id: str = Field(min_length=1)
    name: str
    description: str
    enabled: bool = True

    # exact match keys for now
    match: dict[str, str] = Field(default_factory=dict)

    condition: ThresholdCondition

    output: RuleOutput
