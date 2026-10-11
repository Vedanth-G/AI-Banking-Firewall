"""
AI Banking Firewall — config.py
===============================
Centralized Pydantic BaseSettings for enterprise-grade configuration,
thread-safe caching, and performance optimizations.
"""

from __future__ import annotations

import os
from pydantic import Field
from pydantic_settings import BaseSettings


class FirewallConfig(BaseSettings):
    # API & Model Config
    gemini_api_key: str = Field(default_factory=lambda: os.getenv("GEMINI_API_KEY", ""))
    gemini_model: str = Field(default_factory=lambda: os.getenv("GEMINI_MODEL", "gemini-3.8-flash"))
    
    # Thresholds
    heuristic_block_threshold: float = Field(default=0.75, ge=0.0, le=1.0)
    block_threshold: float = Field(default=0.60, ge=0.0, le=1.0)
    challenge_threshold: float = Field(default=0.40, ge=0.0, le=1.0)
    
    # Financial Ceilings
    standard_transfer_ceiling: float = Field(default=10000.0, gt=0.0)
    high_risk_transfer_ceiling: float = Field(default=5000.0, gt=0.0)
    
    # Performance & Caching
    enable_lru_cache: bool = True
    lru_cache_size: int = 1024
    profiling_enabled: bool = True

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


config = FirewallConfig()
