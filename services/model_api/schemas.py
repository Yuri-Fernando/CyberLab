from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class PredictionRequest(StrictModel):
    features: list[float] = Field(min_length=1, max_length=64)
    client_id: str = Field(min_length=1, max_length=128)


class PredictionResponse(StrictModel):
    request_id: str
    model_version: str
    prediction: int
    confidence: float | None = None
    policy_action: str
