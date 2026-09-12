"""The small JSON contract shared by Gmail and the backend."""
from typing import Annotated, Literal
from pydantic import BaseModel, ConfigDict, Field


class Attachment(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(max_length=1000)
    content_type: str = Field(max_length=200)


class EmailInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    sender: str = Field(max_length=2000)
    reply_to: str = Field(default="", max_length=2000)
    subject: str = Field(default="", max_length=4000)
    body: str = Field(default="", max_length=100000)
    urls: list[Annotated[str, Field(max_length=4096)]] = Field(default_factory=list, max_length=200)
    authentication_results: str = Field(default="", max_length=20000)
    attachments: list[Attachment] = Field(default_factory=list, max_length=100)


class Signal(BaseModel):
    id: str
    category: str
    points: int
    explanation: str


class AnalysisResult(BaseModel):
    reputation: dict = Field(default_factory=dict)
    score: int = Field(ge=0, le=100)
    verdict: Literal["Low Risk", "Moderate Risk", "Suspicious", "High Risk"]
    confidence: Literal["Low", "Medium", "High"]
    confidence_explanation: str
    category_scores: dict[str, int]
    signals: list[Signal]
    recommended_action: str
    limitations: list[str]
