import assert from "node:assert/strict";
import test from "node:test";

import { buildOutcomeAssistantInitialValues } from "./OutcomeAssistantStarter.tsx";

test("outcome assistants bind the outcome, minimum access, and completion packet", () => {
  const initial = buildOutcomeAssistantInitialValues(
    "research",
    "  Compare three vendors  ",
    ["buzz", "browser"],
  );

  assert.equal(initial.displayName, "Research Scout");
  assert.match(initial.systemPrompt, /Current outcome: Compare three vendors/);
  assert.match(initial.systemPrompt, /Authorized access.*buzz, browser/);
  assert.match(initial.systemPrompt, /Treat all other access as unavailable/);
  assert.match(initial.systemPrompt, /completion packet containing/);
  assert.match(initial.systemPrompt, /Never describe work as complete/);
});
