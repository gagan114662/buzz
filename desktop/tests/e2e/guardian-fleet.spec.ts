import { expect, test } from "@playwright/test";

import { installMockBridge } from "../helpers/bridge";
import { openSettings } from "../helpers/settings";

test("loads a synthetic fleet and exercises emergency stop", async ({
  page,
}) => {
  await installMockBridge(page);
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openSettings(page, "agents");

  const fleet = page.getByTestId("settings-guardian-fleet");
  await expect(fleet).toBeVisible();
  await fleet.getByTestId("guardian-seed-fleet-simulation").click();

  const dashboard = fleet.getByTestId("guardian-fleet-dashboard");
  await expect(dashboard).toContainText("Synthetic Acme Operations");
  await expect(dashboard).toContainText("Simulation");
  await expect(
    dashboard.getByTestId("guardian-fleet-endpoint-finance-01"),
  ).toContainText("healthy");
  await expect(
    dashboard.getByTestId("guardian-fleet-endpoint-support-01"),
  ).toContainText("drifted");
  await expect(
    dashboard.getByTestId("guardian-fleet-endpoint-offline-01"),
  ).toContainText("offline");

  const stop = dashboard.getByTestId("guardian-fleet-emergency-stop");
  await stop.click();
  await expect(dashboard).toContainText("Emergency stopped");
  await expect(stop).toHaveText("Resume fleet");
  await stop.click();
  await expect(stop).toHaveText("Emergency stop");
});

test("shows strong isolation as unavailable until trust is verified", async ({
  page,
}) => {
  await installMockBridge(page);
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openSettings(page, "agents");

  const sandbox = page.getByTestId("settings-guardian-sandbox");
  await expect(sandbox).toBeVisible();
  await expect(sandbox).toContainText("unconfigured");
  await expect(sandbox).not.toContainText("Strong isolation ready");
  await expect(
    sandbox.getByRole("button", { name: "Verify and save" }),
  ).toBeDisabled();
});

test("recovers a crashed durable task without duplicating delivery", async ({
  page,
}) => {
  await installMockBridge(page);
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await openSettings(page, "agents");

  const recovery = page.getByTestId("settings-guardian-durable-recovery");
  await recovery.getByTestId("guardian-seed-durable-recovery").click();
  await expect(recovery).toContainText("crashed effect unknown");
  await expect(recovery).toContainText("indeterminate");
  await expect(recovery).toContainText("Accepted with a new reviewer grant");

  const next = recovery.getByTestId("guardian-durable-next-action");
  await expect(next).toHaveText("Recover expired lease");
  await next.click();
  await expect(recovery).toContainText("Lease generation 2");
  await expect(next).toHaveText("Reconcile delivery receipt");
  await next.click();
  await expect(recovery).toContainText("observed");
  await expect(next).toHaveText("Complete verified delivery");
  await next.click();
  await expect(recovery).toContainText("complete");
  await expect(next).toHaveCount(0);
});
