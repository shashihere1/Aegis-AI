"""Shared enums and API schemas."""

from enum import StrEnum

from pydantic import BaseModel, Field


class AgentStatus(StrEnum):
    DISCOVERED = "discovered"
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    QUARANTINED = "quarantined"
    RETIRED = "retired"


# Allowed lifecycle transitions (plan §8.1).
LIFECYCLE: dict[AgentStatus, set[AgentStatus]] = {
    AgentStatus.DISCOVERED: {AgentStatus.DRAFT, AgentStatus.QUARANTINED},
    AgentStatus.QUARANTINED: {AgentStatus.DRAFT, AgentStatus.RETIRED},
    AgentStatus.DRAFT: {AgentStatus.PENDING_APPROVAL, AgentStatus.RETIRED},
    AgentStatus.PENDING_APPROVAL: {AgentStatus.ACTIVE, AgentStatus.DRAFT},
    AgentStatus.ACTIVE: {AgentStatus.PENDING_APPROVAL, AgentStatus.SUSPENDED, AgentStatus.RETIRED},
    AgentStatus.SUSPENDED: {AgentStatus.ACTIVE, AgentStatus.RETIRED},
    AgentStatus.RETIRED: set(),
}

DATA_CLASSES = ["public", "internal", "confidential", "restricted"]


def data_class_rank(value: str) -> int:
    return DATA_CLASSES.index(value) if value in DATA_CLASSES else len(DATA_CLASSES)


class Decision(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    RATE_LIMITED = "rate_limited"


class AgentCreate(BaseModel):
    name: str = Field(min_length=3, max_length=80)
    purpose: str = Field(min_length=10)
    intent_categories: list[str] = Field(min_length=1)
    owner: str
    sponsor: str
    business_unit: str = "Retail Banking"
    environment: str = "PRD"
    cloud: str = "azure"
    framework: str = "custom"
    autonomy: str = "L1"  # L0 suggest-only, L1 human-in-the-loop, L2 human-on-the-loop, L3 autonomous
    max_data_class: str = "internal"
    customer_facing: bool = False
    capabilities: list[str] = Field(default_factory=list)  # tool ids "server.tool"
    can_delegate_to: list[str] = Field(default_factory=list)
    can_receive_from: list[str] = Field(default_factory=list)
    max_depth: int = 2
    endpoint_url: str | None = None  # A2A endpoint, if the agent accepts delegations


class AgentPatch(BaseModel):
    """Fields that can change on an existing agent. Purpose, scope, tools or data class are 'material'."""

    description: str | None = None
    purpose: str | None = None
    intent_categories: list[str] | None = None
    capabilities: list[str] | None = None
    max_data_class: str | None = None
    can_delegate_to: list[str] | None = None
    can_receive_from: list[str] | None = None
    endpoint_url: str | None = None


MATERIAL_FIELDS = {"purpose", "intent_categories", "capabilities", "max_data_class", "can_delegate_to",
                   "can_receive_from"}


class ToolClassification(BaseModel):
    """Authoritative classification set by the tool owner. MCP annotations are only defaults."""

    intent_tags: list[str] = Field(default_factory=list)
    side_effect: str = "read"  # read | write | financial | destructive
    egress: str = "none"  # none | internal | external
    returns_data_class: str = "internal"
    rate_limit_per_min: int | None = None
    untrusted_content: bool = False  # output is attacker-controllable (web pages, uploaded documents)
    required_entitlement: str | None = None  # the initiating user must hold this
    fail_open: bool = False


class McpServerCreate(BaseModel):
    id: str = Field(pattern=r"^[a-z0-9-]+$")
    url: str
    owner: str
    vendor: str = "internal"
