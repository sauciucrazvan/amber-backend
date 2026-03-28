from pydantic import BaseModel, Field, ConfigDict
from typing import Any, Literal, Optional


class WebRTCIceCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    candidate: str = Field(..., max_length=1024)
    sdpMLineIndex: Optional[int] = Field(None, ge=0, le=10)
    sdpMid: Optional[str] = Field(None, max_length=32)


class WebRTCOffer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    type: Literal["offer"] = "offer"
    sdp: str = Field(..., max_length=65536)  # Max 64KB for SDP


class WebRTCAnswer(BaseModel):
    """WebRTC answer with size validation."""
    
    model_config = ConfigDict(extra="forbid")
    
    type: Literal["answer"] = "answer"
    sdp: str = Field(..., max_length=65536)  # Max 64KB for SDP


class MediaStatePayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    
    audio_enabled: bool
    video_enabled: bool


def validate_webrtc_payload(payload: Any, payload_type: str) -> dict:
    if not payload:
        raise ValueError("Payload cannot be empty")
    
    if payload_type == "offer":
        return WebRTCOffer(**payload).model_dump()
    elif payload_type == "answer":
        return WebRTCAnswer(**payload).model_dump()
    elif payload_type == "ice-candidate":
        return WebRTCIceCandidate(**payload).model_dump()
    elif payload_type == "media-state":
        return MediaStatePayload(**payload).model_dump()
    else:
        raise ValueError(f"Unknown payload type: {payload_type}")
