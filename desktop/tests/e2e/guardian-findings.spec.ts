import { expect, test } from "@playwright/test";

import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";

const AGENT = TEST_IDENTITIES.tyler.pubkey;
const CHANNEL = "94a444a4-c0a3-5966-ab05-530c6ddc2301";

test("renders three privacy-projected Guardian alerts", async ({ page }) => {
  await installMockBridge(page, {
    managedAgents: [
      {
        pubkey: AGENT,
        name: "Observer Agent",
        status: "running",
        channelNames: ["agents"],
      },
    ],
    numbatFindingBatch: {
      nextOffset: 512,
      reset: false,
      rejectedRecords: 0,
      health: {
        state: "active",
        detail: "Guardian callback execution is verified.",
      },
      findings: [
        {
          findingId: "finding-low",
          ruleId: "source.git_remote_tamper",
          title: "Git remote-routing change requested",
          severity: "low",
          detectedAt: "2026-07-31T18:00:00Z",
          sourceAgent: AGENT,
          sessionId: "session-guardian",
          channelId: CHANNEL,
          turnId: "turn-guardian",
          evidenceCount: 1,
        },
        {
          findingId: "finding-medium",
          ruleId: "secrets.agent_read_env",
          title: "Sensitive environment data accessed",
          severity: "medium",
          detectedAt: "2026-07-31T18:00:01Z",
          sourceAgent: AGENT,
          sessionId: "session-guardian",
          channelId: CHANNEL,
          turnId: "turn-guardian",
          evidenceCount: 1,
        },
        {
          findingId: "finding-high",
          ruleId: "chain.secret_read_then_egress",
          title: "Possible secret exfiltration",
          severity: "high",
          detectedAt: "2026-07-31T18:00:02Z",
          sourceAgent: AGENT,
          sessionId: "session-guardian",
          channelId: CHANNEL,
          turnId: "turn-guardian",
          evidenceCount: 2,
        },
      ],
    },
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

  const guardian = page.getByTestId("guardian-security-findings");
  await expect(guardian).toBeVisible();
  await expect(guardian).toContainText("active");
  await expect(guardian.locator("article")).toHaveCount(3);
  await expect(guardian).toContainText("LOW");
  await expect(guardian).toContainText("MEDIUM");
  await expect(guardian).toContainText("HIGH");
  await expect(guardian).not.toContainText("observed_command");
  await expect(guardian).not.toContainText("/private/");

  const highFinding = guardian.locator('[data-finding-id="finding-high"]');
  await highFinding.getByTestId("guardian-acknowledge-finding").click();
  await expect(
    highFinding.getByTestId("guardian-acknowledge-finding"),
  ).toHaveText("Acknowledged");

  await highFinding.getByTestId("guardian-create-case").click();
  await expect(highFinding.getByTestId("guardian-create-case")).toHaveText(
    "Case opened",
  );
  await expect(guardian.getByTestId("guardian-case-count")).toContainText(
    "1 local investigation case",
  );
  const caseList = guardian.getByTestId("guardian-case-list");
  await caseList.getByTestId("guardian-advance-case").click();
  await expect(caseList).toContainText("triaged");
  await caseList.getByTestId("guardian-export-redacted-case").click();

  await highFinding.getByTestId("guardian-suppress-finding").click();
  const suppressionForm = highFinding.getByTestId("guardian-suppression-form");
  await suppressionForm
    .getByLabel("Suppression reason")
    .fill("Known local test activity");
  await suppressionForm.getByRole("button", { name: "Suppress 24h" }).click();
  await expect(highFinding).toContainText("Suppressed");
  await highFinding.getByTestId("guardian-renew-suppression").click();
  await expect(highFinding).toContainText("Suppressed");
  await highFinding.getByTestId("guardian-cancel-suppression").click();
  await expect(highFinding.getByTestId("guardian-suppress-finding")).toHaveText(
    "Suppress",
  );

  const policyWorkspace = guardian.getByTestId("guardian-policy-workspace");
  await policyWorkspace.locator("summary").click();
  await policyWorkspace.getByTestId("guardian-create-deny-policy").click();
  const nextPolicyAction = policyWorkspace.getByTestId(
    "guardian-policy-next-action",
  );
  for (const label of [
    "simulate",
    "request approval",
    "approve",
    "stage local canary",
    "activate",
  ]) {
    await expect(nextPolicyAction).toHaveText(label);
    await nextPolicyAction.click();
  }
  await expect(policyWorkspace).toContainText("active");

  await guardian.getByTestId("guardian-import-case-input").setInputFiles({
    name: "guardian-case-redacted.zip",
    mimeType: "application/zip",
    buffer: Buffer.from("mock-verified-bundle"),
  });
});
