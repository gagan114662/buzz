import { expect, test } from "@playwright/test";

import { installMockBridge, TEST_IDENTITIES } from "../helpers/bridge";

const HUDDLE_CHANNEL_ID = "11111111-1111-4111-8111-111111111111";
const HUDDLE_PARENT_ID = "9a1657ac-f7aa-5db0-b632-d8bbeb6dfb50";

async function setHuddleSnapshot(
  page: import("@playwright/test").Page,
  members: Array<{
    pubkey: string;
    role: "member" | "bot";
  }>,
  transcriptionEnabled: boolean,
) {
  await page.evaluate(
    ({ nextMembers, nextTranscriptionEnabled }) => {
      const setSnapshot = (
        window as Window & {
          __BUZZ_E2E_SET_MOCK_HUDDLE_SNAPSHOT__?: (input: {
            members: Array<{
              pubkey: string;
              role: "member" | "bot";
            }>;
            transcriptionEnabled: boolean;
          }) => void;
        }
      ).__BUZZ_E2E_SET_MOCK_HUDDLE_SNAPSHOT__;
      if (!setSnapshot) {
        throw new Error("Mock huddle snapshot control is not installed.");
      }
      setSnapshot({
        members: nextMembers,
        transcriptionEnabled: nextTranscriptionEnabled,
      });
    },
    { nextMembers: members, nextTranscriptionEnabled: transcriptionEnabled },
  );
}

test("renders authoritative huddle snapshots and sends explicit off once", async ({
  page,
}) => {
  await installMockBridge(page, {
    huddle: {
      parentChannelId: HUDDLE_PARENT_ID,
      ephemeralChannelId: HUDDLE_CHANNEL_ID,
      members: [
        { pubkey: TEST_IDENTITIES.tyler.pubkey, role: "member" },
        { pubkey: TEST_IDENTITIES.alice.pubkey, role: "bot" },
      ],
      transcriptionEnabled: true,
    },
  });

  await page.goto("/");

  const transcriptButton = page.getByRole("button", {
    name: "Stop transcript",
  });
  await expect(transcriptButton).toBeVisible();
  await expect(transcriptButton).toHaveAttribute("aria-pressed", "true");
  await page
    .getByRole("button", { name: "Show huddle participants (2)" })
    .click();
  await expect(
    page.getByRole("button", { name: /Remove .* from huddle/ }),
  ).toHaveCount(1);
  await page.keyboard.press("Escape");

  await setHuddleSnapshot(
    page,
    [{ pubkey: TEST_IDENTITIES.tyler.pubkey, role: "member" }],
    true,
  );
  await expect(
    page.getByRole("button", { name: "Show huddle participants (1)" }),
  ).toBeVisible();
  await expect(transcriptButton).toHaveAttribute("aria-pressed", "true");

  await setHuddleSnapshot(
    page,
    [
      { pubkey: TEST_IDENTITIES.tyler.pubkey, role: "member" },
      { pubkey: TEST_IDENTITIES.alice.pubkey, role: "bot" },
    ],
    true,
  );
  await expect(transcriptButton).toHaveAttribute("aria-pressed", "true");

  await transcriptButton.click();
  await expect(
    page.getByRole("button", { name: "Start transcript" }),
  ).toHaveAttribute("aria-pressed", "false");

  const explicitToggleCommands = await page.evaluate(() =>
    (window.__BUZZ_E2E_COMMAND_LOG__ ?? []).filter(
      (entry) => entry.command === "set_huddle_transcription_enabled",
    ),
  );
  expect(explicitToggleCommands).toEqual([
    {
      command: "set_huddle_transcription_enabled",
      payload: { enabled: false },
    },
  ]);

  await page.reload();
  await expect(
    page.getByRole("button", { name: "Start transcript" }),
  ).toHaveAttribute("aria-pressed", "false");
  await expect(
    page.getByRole("button", { name: "Show huddle participants (2)" }),
  ).toBeVisible();
  await expect
    .poll(() =>
      page.evaluate(
        () =>
          (window.__BUZZ_E2E_COMMAND_LOG__ ?? []).filter(
            (entry) => entry.command === "set_huddle_transcription_enabled",
          ).length,
      ),
    )
    .toBe(0);

  await setHuddleSnapshot(
    page,
    [{ pubkey: TEST_IDENTITIES.tyler.pubkey, role: "member" }],
    false,
  );
  await expect(
    page.getByRole("button", { name: "Show huddle participants (1)" }),
  ).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Start transcript" }),
  ).toHaveAttribute("aria-pressed", "false");
});
