import assert from "node:assert/strict";
import test from "node:test";

import { buildAgentRunReplay, redactReplayText } from "./agentRunReplay.ts";

const base = {
  agentIndex: 0,
  channelId: "channel-1",
  sessionId: "session-1",
  turnId: "turn-1",
};

test("builds a failed replay and groups a repeated failure loop", () => {
  const events = [
    {
      ...base,
      seq: 1,
      timestamp: "2026-08-07T12:00:00Z",
      kind: "turn_started",
      payload: {},
    },
    ...[2, 3, 4].map((seq) => ({
      ...base,
      seq,
      timestamp: `2026-08-07T12:00:0${seq}Z`,
      kind: "acp_read",
      payload: {
        params: {
          update: {
            sessionUpdate: "tool_call_update",
            toolCallId: `call-${seq}`,
            title: "Open dashboard",
            status: "failed",
            result: "Authentication required",
          },
        },
      },
    })),
    {
      ...base,
      seq: 5,
      timestamp: "2026-08-07T12:00:05Z",
      kind: "turn_error",
      payload: { error: "Authentication required" },
    },
  ];

  const replay = buildAgentRunReplay(events);
  assert.equal(replay.outcome, "failed");
  assert.equal(replay.steps[0].repeatCount, 3);
  assert.equal(replay.steps[0].title, "Open dashboard");
  assert.equal(replay.actual, "Authentication required");
  assert.equal(replay.steps.at(-1).durationMs, 5000);
});

test("scopes replay to the latest turn", () => {
  const replay = buildAgentRunReplay([
    {
      ...base,
      seq: 1,
      timestamp: "2026-08-07T12:00:00Z",
      kind: "turn_error",
      payload: { error: "old" },
    },
    {
      ...base,
      turnId: "turn-2",
      seq: 2,
      timestamp: "2026-08-07T12:01:00Z",
      kind: "turn_started",
      payload: {},
    },
    {
      ...base,
      turnId: "turn-2",
      seq: 3,
      timestamp: "2026-08-07T12:01:01Z",
      kind: "turn_completed",
      payload: {},
    },
  ]);
  assert.equal(replay.turnId, "turn-2");
  assert.equal(replay.outcome, "succeeded");
});

test("redacts credentials before replay rendering", () => {
  assert.equal(
    redactReplayText("authorization: Bearer abc123 token=super-secret"),
    "authorization=[REDACTED] token=[REDACTED]",
  );
});
