"""
Assignment 11 — Defense-in-Depth Pipeline

Chains every safety layer together:

    User Input
        |
        v
    [1] Rate Limiter            (pipeline.rate_limiter.RateLimiter)
        |
        v
    [2] Input Guardrails        (guardrails.input_guardrails: detect_injection, topic_filter
        |                         + optional NeMo Colang rails)
        v
    [3] LLM (Gemini)             (agents.agent.create_protected_agent + chat_with_agent)
        |
        v
    [4] Output Guardrails        (guardrails.output_guardrails: content_filter, llm_safety_check)
        |
        v
    [5] Audit Log                (pipeline.audit_log.AuditLog)
        |
        v
    [Bonus] Session Anomaly       (pipeline.anomaly_detector.SessionAnomalyDetector)
        |
        v
    Response

Each layer is independent: if one misses an attack, the next one can still
catch it (defense-in-depth). Layer [6] (Monitoring) is not called inside
`process()` — it reads the AuditLog afterwards (see pipeline.monitoring).
"""
import time

from core.utils import chat_with_agent
from guardrails.input_guardrails import detect_injection, get_injection_match, topic_filter
from guardrails.output_guardrails import content_filter, llm_safety_check
from pipeline.audit_log import AuditLog
from pipeline.rate_limiter import RateLimiter
from pipeline.anomaly_detector import SessionAnomalyDetector


# Canned responses returned when a layer blocks the request. Keeping these
# as constants makes it easy for tests to recognize "this was blocked" and
# keeps the wording consistent across the pipeline.
RATE_LIMIT_MESSAGE = "You're sending requests too quickly. Please wait {wait:.0f} seconds and try again."
INJECTION_BLOCK_MESSAGE = "I cannot process that request. I'm here to help with banking questions only."
TOPIC_BLOCK_MESSAGE = (
    "I'm a VinBank assistant and can only help with banking-related questions, "
    "such as accounts, transactions, loans, or interest rates."
)
JUDGE_BLOCK_MESSAGE = (
    "I'm sorry, I can't provide that response. Please contact VinBank support "
    "for further assistance."
)
LLM_ERROR_MESSAGE = (
    "Sorry, I'm having trouble reaching our systems right now. Please try again "
    "in a moment."
)


class DefensePipeline:
    """Runs a single user message through all configured safety layers.

    Args:
        agent: ADK LlmAgent used to generate the response (layer 3).
        runner: ADK InMemoryRunner paired with `agent`.
        rate_limiter: RateLimiter instance (layer 1).
        audit_log: AuditLog instance (layer 5).
        anomaly_detector: SessionAnomalyDetector instance (bonus layer).
        use_llm_judge: whether to run the LLM-as-Judge check (layer 4b).
            Disable in tests to avoid extra API calls / latency.
        nemo_rails: optional NeMo `LLMRails` instance. If provided, it
            replaces the direct `chat_with_agent` call for layer 3, so the
            Colang rules from TODO 9 run as part of input/output checking.
    """

    def __init__(
        self,
        agent,
        runner,
        rate_limiter: RateLimiter | None = None,
        audit_log: AuditLog | None = None,
        anomaly_detector: SessionAnomalyDetector | None = None,
        use_llm_judge: bool = True,
        nemo_rails=None,
    ):
        self.agent = agent
        self.runner = runner
        self.rate_limiter = rate_limiter or RateLimiter()
        self.audit_log = audit_log or AuditLog()
        self.anomaly_detector = anomaly_detector or SessionAnomalyDetector()
        self.use_llm_judge = use_llm_judge
        self.nemo_rails = nemo_rails

    async def _generate_response(self, user_input: str) -> str:
        """Layer 3: call the LLM (via NeMo rails if configured, else ADK)."""
        if self.nemo_rails is not None:
            result = await self.nemo_rails.generate_async(
                messages=[{"role": "user", "content": user_input}]
            )
            if isinstance(result, dict):
                return result.get("content", str(result))
            return str(result)

        response_text, _ = await chat_with_agent(self.agent, self.runner, user_input)
        return response_text

    async def process(self, user_input: str, user_id: str = "default") -> str:
        """Run `user_input` through every layer and return the final response.

        Every call (blocked or not) is recorded in the audit log so the
        Monitoring layer can compute metrics afterwards.
        """
        start = time.perf_counter()
        layer_results: dict = {}
        blocked = False
        blocked_layer = None
        final_response = ""

        # --- Layer 1: Rate Limiter ---
        # Cheapest check — stops abusive users before any other layer runs.
        rl_result = self.rate_limiter.check(user_id)
        layer_results["rate_limiter"] = {
            "allowed": rl_result.allowed,
            "requests_in_window": rl_result.requests_in_window,
            "wait_seconds": rl_result.wait_seconds,
        }
        if not rl_result.allowed:
            blocked = True
            blocked_layer = "rate_limiter"
            final_response = RATE_LIMIT_MESSAGE.format(wait=rl_result.wait_seconds)

        # --- Layer 2: Input Guardrails ---
        # Catches prompt injection and off-topic/unsafe requests before the
        # LLM ever sees them.
        if not blocked:
            injection_detected = detect_injection(user_input)
            layer_results["input_injection"] = {
                "detected": injection_detected,
                "matched_pattern": get_injection_match(user_input),
            }
            if injection_detected:
                blocked = True
                blocked_layer = "input_injection"
                final_response = INJECTION_BLOCK_MESSAGE
            else:
                off_topic = topic_filter(user_input)
                layer_results["input_topic"] = {"blocked": off_topic}
                if off_topic:
                    blocked = True
                    blocked_layer = "input_topic"
                    final_response = TOPIC_BLOCK_MESSAGE

        # --- Layer 3 + 4: LLM + Output Guardrails ---
        if not blocked:
            try:
                response_text = await self._generate_response(user_input)
            except Exception as e:
                # The LLM call is the one external/network boundary in this
                # pipeline — fail closed with a generic message rather than
                # crashing or leaking the raw exception to the user.
                blocked = True
                blocked_layer = "llm_error"
                layer_results["llm_error"] = {"error": str(e)}
                final_response = LLM_ERROR_MESSAGE
                response_text = None

        if not blocked:
            # 4a. Content filter — redact PII/secrets regardless of judge verdict.
            filter_result = content_filter(response_text)
            layer_results["output_content_filter"] = {
                "safe": filter_result["safe"],
                "issues": filter_result["issues"],
            }
            response_text = filter_result["redacted"]

            # 4b. LLM-as-Judge — multi-criteria safety/relevance/accuracy/tone check.
            if self.use_llm_judge:
                judge_result = await llm_safety_check(response_text)
                layer_results["output_judge"] = judge_result
                if not judge_result["safe"]:
                    blocked = True
                    blocked_layer = "output_judge"
                    final_response = JUDGE_BLOCK_MESSAGE
                else:
                    final_response = response_text
            else:
                final_response = response_text

        # --- Bonus Layer: Session Anomaly Detector ---
        # Only meaningful for input-layer blocks — repeated injection
        # attempts from the same user are the anomalous pattern we watch for.
        if blocked and blocked_layer == "input_injection":
            anomaly = self.anomaly_detector.record_block(user_id, blocked_layer)
            layer_results["session_anomaly"] = {
                "flagged": anomaly.flagged,
                "injection_attempts": anomaly.injection_attempts,
            }
            if anomaly.flagged:
                final_response = anomaly.reason

        # --- Layer 5: Audit Log ---
        latency_ms = (time.perf_counter() - start) * 1000
        self.audit_log.record(
            user_id=user_id,
            user_input=user_input,
            final_response=final_response,
            blocked=blocked,
            blocked_layer=blocked_layer,
            layer_results=layer_results,
            latency_ms=latency_ms,
        )

        return final_response
