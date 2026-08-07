import type { ObserverEvent } from "./agentSessionTypes";
import { extractToolResult } from "./agentSessionTranscriptHelpers";
import { asRecord, asString } from "./agentSessionUtils";

export type ReplayStepStatus = "completed" | "failed" | "running" | "observed";

export type ReplayStep = {
  id: string;
  title: string;
  detail: string;
  timestamp: string;
  durationMs: number | null;
  status: ReplayStepStatus;
  repeatCount: number;
};

export type AgentRunReplay = {
  turnId: string | null;
  outcome: "failed" | "succeeded" | "in_progress";
  expected: string;
  actual: string;
  failedStepId: string | null;
  steps: ReplayStep[];
};

const SECRET_PATTERN =
  /\b(api[_-]?key|authorization|bearer|password|private[_-]?key|secret|token)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;}]+)/gi;

export function redactReplayText(value: string): string {
  return value
    .replace(
      /\bauthorization\b\s*[:=]\s*bearer\s+[^\s,;}]+/gi,
      "authorization=[REDACTED]",
    )
    .replace(SECRET_PATTERN, "$1=[REDACTED]");
}

function payload(event: ObserverEvent): Record<string, unknown> {
  return asRecord(event.payload);
}

function update(event: ObserverEvent): Record<string, unknown> {
  return asRecord(asRecord(payload(event).params).update);
}

function text(value: unknown): string | null {
  if (typeof value !== "string" || !value.trim()) return null;
  return redactReplayText(value.trim());
}

function latestTurn(events: readonly ObserverEvent[]): ObserverEvent[] {
  const last = [...events].reverse().find((event) => event.turnId);
  if (!last?.turnId) return [...events];
  return events.filter(
    (event) =>
      event.turnId === last.turnId &&
      (!last.sessionId || event.sessionId === last.sessionId),
  );
}

function eventStep(event: ObserverEvent): ReplayStep | null {
  const eventPayload = payload(event);
  const eventUpdate = update(event);
  const sessionUpdate = asString(eventUpdate.sessionUpdate);
  const status = asString(eventUpdate.status);

  if (sessionUpdate === "tool_call" || sessionUpdate === "tool_call_update") {
    const toolCallId = asString(eventUpdate.toolCallId) ?? `seq-${event.seq}`;
    const title =
      text(eventUpdate.title) ?? text(eventUpdate.name) ?? "Tool action";
    const detail =
      text(eventUpdate.result) ??
      text(eventUpdate.output) ??
      text(eventUpdate.content) ??
      text(extractToolResult(eventUpdate)) ??
      (status ? `Tool ${status}.` : "Tool activity observed.");
    return {
      id: `tool:${toolCallId}:${event.seq}`,
      title,
      detail,
      timestamp: event.timestamp,
      durationMs: null,
      status:
        status === "failed"
          ? "failed"
          : status === "completed"
            ? "completed"
            : "running",
      repeatCount: 1,
    };
  }

  if (event.kind === "turn_error") {
    return {
      id: `turn-error:${event.seq}`,
      title: "Run failed",
      detail:
        text(eventPayload.message) ??
        text(eventPayload.error) ??
        "The agent stopped without a diagnostic.",
      timestamp: event.timestamp,
      durationMs: null,
      status: "failed",
      repeatCount: 1,
    };
  }

  if (event.kind === "permission_decision") {
    const decision = text(eventPayload.decision) ?? "unknown";
    const denied = /reject|deny|cancel/i.test(decision);
    return {
      id: `permission:${event.seq}`,
      title: denied ? "Permission denied" : "Permission granted",
      detail: `Buzz recorded ${decision}.`,
      timestamp: event.timestamp,
      durationMs: null,
      status: denied ? "failed" : "completed",
      repeatCount: 1,
    };
  }

  if (event.kind === "host_operation") {
    return {
      id: `host:${event.seq}`,
      title: text(eventPayload.operation) ?? "Host operation",
      detail: text(eventPayload.target) ?? "Host-side activity observed.",
      timestamp: event.timestamp,
      durationMs: null,
      status: "observed",
      repeatCount: 1,
    };
  }

  return null;
}

function groupRepeatedSteps(steps: ReplayStep[]): ReplayStep[] {
  const grouped: ReplayStep[] = [];
  for (const step of steps) {
    const previous = grouped.at(-1);
    if (
      previous &&
      previous.title === step.title &&
      previous.detail === step.detail &&
      previous.status === step.status
    ) {
      previous.repeatCount += 1;
      continue;
    }
    grouped.push({ ...step });
  }
  return grouped;
}

export function buildAgentRunReplay(
  events: readonly ObserverEvent[],
): AgentRunReplay | null {
  const turnEvents = latestTurn(events);
  if (turnEvents.length === 0) return null;

  const rawSteps = turnEvents.flatMap((event) => {
    const step = eventStep(event);
    return step ? [step] : [];
  });
  const steps = groupRepeatedSteps(rawSteps);
  const failure = [...steps].reverse().find((step) => step.status === "failed");
  const completed = turnEvents.some((event) => event.kind === "turn_completed");
  const outcome = failure ? "failed" : completed ? "succeeded" : "in_progress";
  const started = turnEvents.find((event) => event.kind === "turn_started");
  const terminal = [...turnEvents]
    .reverse()
    .find(
      (event) => event.kind === "turn_completed" || event.kind === "turn_error",
    );
  if (started && terminal && steps.length > 0) {
    steps[steps.length - 1].durationMs = Math.max(
      0,
      Date.parse(terminal.timestamp) - Date.parse(started.timestamp),
    );
  }

  return {
    turnId: turnEvents.at(-1)?.turnId ?? null,
    outcome,
    expected: "Complete the requested turn and produce a verified result.",
    actual: failure
      ? failure.detail
      : outcome === "succeeded"
        ? "The turn completed without an observed failure."
        : "The turn is still running or its terminal event is missing.",
    failedStepId: failure?.id ?? null,
    steps,
  };
}
