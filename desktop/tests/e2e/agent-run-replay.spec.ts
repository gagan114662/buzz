import { expect, test } from "@playwright/test";

import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";

const AGENT = TEST_IDENTITIES.tyler.pubkey;
const CHANNEL = "94a444a4-c0a3-5966-ab05-530c6ddc2301";

test("shows a redacted visual replay for the latest failed run", async ({
  page,
}) => {
  await installMockBridge(page, {
    managedAgents: [
      {
        pubkey: AGENT,
        name: "Observer Agent",
        status: "running",
        channelNames: ["agents"],
      },
    ],
  });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await page.waitForFunction(
    () => typeof window.__BUZZ_E2E_SEED_OBSERVER_EVENTS__ === "function",
  );
  await page.getByTestId("channel-agents").click();
  const messageRow = page
    .getByTestId("message-row")
    .filter({ has: page.getByText("Observer Agent", { exact: false }) })
    .first();
  await expect(messageRow).toBeVisible();
  await messageRow.getByRole("button").first().click();
  await page.getByTestId(`user-profile-view-activity-${AGENT}`).click();

  await page.evaluate(
    ({ agent, channel }) => {
      const base = {
        agentIndex: 0,
        channelId: channel,
        sessionId: "session-replay",
        turnId: "turn-replay",
      };
      window.__BUZZ_E2E_SEED_OBSERVER_EVENTS__?.({
        agentPubkey: agent,
        events: [
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
                  toolCallId: `browser-${seq}`,
                  title: "Open customer dashboard",
                  status: "failed",
                  result: "authorization: Bearer private-token login required",
                },
              },
            },
          })),
          {
            ...base,
            seq: 5,
            timestamp: "2026-08-07T12:00:05Z",
            kind: "turn_error",
            payload: { error: "Login required before the dashboard can open" },
          },
        ],
      });
    },
    { agent: AGENT, channel: CHANNEL },
  );

  const replay = page.getByTestId("agent-run-replay");
  await expect(replay).toBeVisible();
  await expect(replay).toContainText("Where this run broke");
  await expect(replay).toContainText("Repeated 3 times");
  await expect(replay).toContainText("authorization=[REDACTED]");
  await expect(replay).not.toContainText("private-token");
  await expect(
    replay.locator('[data-replay-step-status="failed"]'),
  ).toHaveCount(2);
});
