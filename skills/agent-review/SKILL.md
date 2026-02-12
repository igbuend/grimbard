---
name: agent-review
description: Review AI agent implementations for best practices in architecture, folder structure, design patterns, error handling, and observability. Use when auditing agent codebases or designing new agent systems.
disable-model-invocation: true
aliases:
  - review-agent
  - agent-audit
  - agent-architecture
---

# Agent Implementation Review

Review AI agent implementations for architectural best practices.

**Target:** $ARGUMENTS (path to agent project or codebase)

## When to Use This Skill

- Auditing existing agent implementations
- Designing new agent architectures
- Reviewing agent code for production readiness
- Evaluating multi-agent system designs
- Assessing agent reliability and observability

## Review Process

1. **Discover** - Explore folder structure at $ARGUMENTS
2. **Analyze** - Check against architecture patterns
3. **Evaluate** - Score each category
4. **Report** - Generate findings with recommendations

## Folder Structure Best Practices

### Recommended Agent Project Structure

```
agent-project/
├── src/
│   ├── agents/              # Agent definitions
│   │   ├── base.py          # Base agent class
│   │   ├── planner.py       # Planning agent
│   │   └── executor.py      # Execution agent
│   ├── tools/               # Tool implementations
│   │   ├── __init__.py
│   │   ├── base.py          # Tool base class/interface
│   │   ├── search.py        # Search tool
│   │   └── code.py          # Code execution tool
│   ├── memory/              # Memory/state management
│   │   ├── short_term.py    # Conversation context
│   │   ├── long_term.py     # Persistent storage
│   │   └── vector_store.py  # Embeddings/RAG
│   ├── prompts/             # Prompt templates
│   │   ├── system.py        # System prompts
│   │   └── templates/       # Jinja/string templates
│   ├── orchestration/       # Multi-agent coordination
│   │   ├── router.py        # Request routing
│   │   └── workflow.py      # Agent workflows
│   ├── models/              # Data models/schemas
│   │   ├── messages.py      # Message types
│   │   └── state.py         # State schemas
│   └── utils/               # Shared utilities
│       ├── logging.py       # Structured logging
│       └── retry.py         # Retry logic
├── config/                  # Configuration
│   ├── default.yaml         # Default settings
│   └── prompts/             # External prompt files
├── tests/                   # Test suite
│   ├── unit/
│   ├── integration/
│   └── fixtures/            # Test data
└── scripts/                 # CLI/automation
```

### Structure Checklist

| Component | Required | Check |
|-----------|----------|-------|
| Agent definitions separated | Yes | [ ] |
| Tools in dedicated module | Yes | [ ] |
| Prompts externalized | Recommended | [ ] |
| Configuration separated | Yes | [ ] |
| Tests present | Yes | [ ] |
| Clear separation of concerns | Yes | [ ] |

## Design Pattern Checklist

### 1. Tool Design

**Required Patterns:**
- [ ] Tools have clear input/output schemas
- [ ] Tool errors return structured error responses
- [ ] Tools are stateless (no side effects on agent state)
- [ ] Tool timeouts are configured
- [ ] Tools validate inputs before execution

**BAD:**
```python
def search(query):
    return requests.get(f"https://api.com?q={query}").json()
```

**GOOD:**
```python
class SearchTool(BaseTool):
    name = "search"
    description = "Search the web for information"

    class InputSchema(BaseModel):
        query: str = Field(..., min_length=1, max_length=500)

    def execute(self, query: str) -> ToolResult:
        try:
            response = self.client.search(query, timeout=10)
            return ToolResult(success=True, data=response)
        except Timeout:
            return ToolResult(success=False, error="Search timed out")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
```

### 2. Agent Loop

**Required Patterns:**
- [ ] Clear think → act → observe cycle
- [ ] Maximum iteration limit
- [ ] Graceful termination conditions
- [ ] State preserved between iterations
- [ ] Interrupt/cancel capability

**GOOD:**
```python
class Agent:
    MAX_ITERATIONS = 10

    async def run(self, task: str) -> AgentResult:
        state = AgentState(task=task)

        for i in range(self.MAX_ITERATIONS):
            if self._should_stop(state):
                break

            # Think
            action = await self.plan(state)

            # Act
            result = await self.execute(action)

            # Observe
            state = self.update_state(state, result)

        return self.finalize(state)
```

### 3. Memory Management

**Required Patterns:**
- [ ] Conversation history with size limits
- [ ] Summarization for long conversations
- [ ] Clear memory lifecycle (create, read, update, delete)
- [ ] Persistent storage for long-term memory
- [ ] Vector store for semantic retrieval (if RAG)

**Memory Types:**

| Type | Purpose | Persistence |
|------|---------|-------------|
| Working | Current task context | Session |
| Short-term | Recent conversation | Session |
| Long-term | User preferences, facts | Persistent |
| Episodic | Past task summaries | Persistent |
| Semantic | Embeddings/RAG | Persistent |

### 4. Error Handling

**Required Patterns:**
- [ ] Structured error types (not generic exceptions)
- [ ] Retry with exponential backoff for transient errors
- [ ] Graceful degradation (fallback behaviors)
- [ ] Error context preserved for debugging
- [ ] User-friendly error messages

**Error Categories:**

| Category | Retry | Action |
|----------|-------|--------|
| Rate limit | Yes | Exponential backoff |
| Timeout | Yes | Retry with longer timeout |
| Auth failure | No | Fail with clear message |
| Invalid input | No | Return validation error |
| Tool failure | Maybe | Try alternative tool |
| Model error | Yes | Retry or fallback model |

**GOOD:**
```python
class AgentError(Exception):
    def __init__(self, message: str, code: str, recoverable: bool = False):
        self.message = message
        self.code = code
        self.recoverable = recoverable

@retry(
    retry=retry_if_exception_type(RateLimitError),
    wait=wait_exponential(multiplier=1, max=60),
    stop=stop_after_attempt(3)
)
async def call_model(self, messages: list) -> str:
    try:
        return await self.client.complete(messages)
    except RateLimitError:
        raise  # Let retry handle it
    except AuthError as e:
        raise AgentError("Authentication failed", "AUTH_ERROR", recoverable=False)
```

### 5. State Management

**Required Patterns:**
- [ ] Immutable state updates (new state object per update)
- [ ] State schema validation
- [ ] State serialization for persistence
- [ ] Clear state transitions
- [ ] State versioning for migrations

**GOOD:**
```python
@dataclass(frozen=True)
class AgentState:
    task: str
    messages: tuple[Message, ...]
    tool_results: tuple[ToolResult, ...]
    iteration: int = 0
    status: Literal["running", "completed", "failed"] = "running"

    def with_message(self, message: Message) -> "AgentState":
        return replace(self, messages=self.messages + (message,))

    def with_tool_result(self, result: ToolResult) -> "AgentState":
        return replace(self, tool_results=self.tool_results + (result,))
```

### 6. Multi-Agent Coordination

**Patterns (if applicable):**
- [ ] Clear agent roles and responsibilities
- [ ] Message passing protocol defined
- [ ] Conflict resolution strategy
- [ ] Supervisor/orchestrator pattern
- [ ] Shared state management

**Coordination Patterns:**

| Pattern | Use Case |
|---------|----------|
| **Supervisor** | One agent routes to specialists |
| **Pipeline** | Sequential agent processing |
| **Debate** | Multiple agents propose, one decides |
| **Swarm** | Autonomous agents, shared goals |
| **Hierarchical** | Manager → workers structure |

### 7. Prompt Management

**Required Patterns:**
- [ ] System prompts externalized (not hardcoded)
- [ ] Prompt versioning
- [ ] Variables/templating for dynamic content
- [ ] Prompt testing/validation
- [ ] Clear prompt documentation

**GOOD:**
```python
# prompts/system.yaml
agent_system_prompt:
  version: "1.2"
  template: |
    You are a helpful assistant with access to these tools:
    {% for tool in tools %}
    - {{ tool.name }}: {{ tool.description }}
    {% endfor %}

    Current date: {{ current_date }}
    User preferences: {{ user_prefs }}
```

### 8. Observability

**Required Patterns:**
- [ ] Structured logging (JSON format)
- [ ] Request/response tracing
- [ ] Token usage tracking
- [ ] Latency metrics
- [ ] Error rate monitoring

**Logging Checklist:**

| Event | Log Level | Required Fields |
|-------|-----------|-----------------|
| Agent start | INFO | task_id, user_id, task |
| Tool call | DEBUG | tool_name, inputs, duration |
| Model call | DEBUG | model, tokens_in, tokens_out, latency |
| Error | ERROR | error_code, message, stack_trace |
| Agent complete | INFO | task_id, status, total_duration, total_tokens |

**GOOD:**
```python
logger.info("agent_started", extra={
    "task_id": task_id,
    "user_id": user_id,
    "task_type": task.type,
})

logger.debug("tool_executed", extra={
    "task_id": task_id,
    "tool": tool.name,
    "duration_ms": duration,
    "success": result.success,
})
```

## Configuration Best Practices

### Required Configuration

| Setting | Type | Description |
|---------|------|-------------|
| `model` | string | Model identifier |
| `max_iterations` | int | Loop limit |
| `timeout_seconds` | int | Overall timeout |
| `tool_timeout` | int | Per-tool timeout |
| `max_tokens` | int | Response limit |
| `temperature` | float | Model temperature |
| `retry_attempts` | int | Retry count |

### Configuration Hierarchy

```
1. Environment variables (secrets, deployment-specific)
2. Config files (default.yaml, production.yaml)
3. Code defaults (fallbacks only)
```

**GOOD:**
```python
class AgentConfig(BaseSettings):
    model: str = "claude-3-sonnet"
    max_iterations: int = 10
    timeout_seconds: int = 300

    class Config:
        env_prefix = "AGENT_"
        env_file = ".env"
```

## Testing Patterns

### Test Categories

| Type | Coverage | Purpose |
|------|----------|---------|
| **Unit** | Tools, utilities | Isolated component tests |
| **Integration** | Agent + tools | End-to-end flows |
| **Snapshot** | Prompts | Detect prompt regressions |
| **Eval** | Agent responses | Quality benchmarks |

### Required Tests

- [ ] Tool input validation tests
- [ ] Tool error handling tests
- [ ] Agent termination condition tests
- [ ] State transition tests
- [ ] Prompt template rendering tests
- [ ] Configuration loading tests

**GOOD:**
```python
def test_search_tool_timeout():
    tool = SearchTool(timeout=0.001)
    result = tool.execute("test query")
    assert not result.success
    assert "timeout" in result.error.lower()

def test_agent_max_iterations():
    agent = Agent(max_iterations=3)
    # Mock tool that never completes
    agent.tools = [InfiniteLoopTool()]
    result = agent.run("impossible task")
    assert result.iterations == 3
    assert result.status == "max_iterations_reached"
```

## Review Output Format

```markdown
## Agent Review: [project-name]

### Summary
[1-2 sentence overview]

### Architecture Score

| Category | Score | Notes |
|----------|-------|-------|
| Folder Structure | X/5 | |
| Tool Design | X/5 | |
| Agent Loop | X/5 | |
| Memory Management | X/5 | |
| Error Handling | X/5 | |
| State Management | X/5 | |
| Observability | X/5 | |
| Testing | X/5 | |
| **Overall** | **X/5** | |

### Critical Issues
- [ ] [Issue] - Location: [file]

### Recommendations
- [ ] [Recommendation] - Priority: [High/Medium/Low]

### Strengths
- [What the implementation does well]
```

## Anti-Patterns to Flag

| Anti-Pattern | Problem | Fix |
|--------------|---------|-----|
| God Agent | Single agent does everything | Split by responsibility |
| Infinite Loop | No termination condition | Add max iterations |
| Silent Failures | Errors swallowed | Structured error handling |
| Hardcoded Prompts | Prompts in code | Externalize to files |
| No Observability | Can't debug production | Add structured logging |
| Mutable State | Race conditions, bugs | Immutable state updates |
| No Timeouts | Hanging requests | Configure all timeouts |
| Missing Validation | Invalid inputs accepted | Schema validation |

## References

- [Anthropic Agent SDK](https://github.com/anthropics/anthropic-sdk-python)
- [LangChain Architecture](https://python.langchain.com/docs/concepts/)
- [OpenAI Function Calling](https://platform.openai.com/docs/guides/function-calling)
- [Instructor (Structured Outputs)](https://github.com/jxnl/instructor)
- [Pydantic AI](https://ai.pydantic.dev/)
