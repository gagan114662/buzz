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
