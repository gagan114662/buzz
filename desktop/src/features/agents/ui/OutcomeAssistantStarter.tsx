import * as React from "react";
import { BriefcaseBusiness, MailCheck, Search } from "lucide-react";

import type { CreatePersonaInput } from "@/shared/api/types";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";

type OutcomePreset = {
  id: string;
  name: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  routine: string;
};

const PRESETS: OutcomePreset[] = [
  {
    id: "follow-up",
    name: "Follow-up Captain",
    description: "Turn loose conversations into owned next steps and drafts.",
    icon: MailCheck,
    routine:
      "Review the supplied conversations, identify commitments and deadlines, prepare follow-up drafts, and ask before sending anything externally.",
  },
  {
    id: "research",
    name: "Research Scout",
    description:
      "Produce a sourced answer with uncertainty and open questions.",
    icon: Search,
    routine:
      "Research the requested question using approved sources, separate facts from inference, cite every material claim, and preserve unresolved uncertainty.",
  },
  {
    id: "project",
    name: "Project Captain",
    description: "Drive a concrete deliverable while keeping blockers visible.",
    icon: BriefcaseBusiness,
    routine:
      "Break the outcome into verifiable work, keep durable evidence of completed steps, stop for consequential approvals, and deliver the finished artifact with blockers.",
  },
];

export function buildOutcomeAssistantInitialValues(
  presetId: string,
  outcome: string,
  selectedAccess: string[],
): CreatePersonaInput {
  const preset = PRESETS.find((item) => item.id === presetId) ?? PRESETS[0];
  return {
    displayName: preset.name,
    avatarUrl: "",
    systemPrompt: `${preset.routine}\n\nCurrent outcome: ${outcome.trim()}\n\nAuthorized access requested by the owner: ${selectedAccess.join(", ")}. Treat all other access as unavailable and request approval before expanding scope.\n\nFinish with one completion packet containing: completed work, blockers, evidence, approvals used, and unresolved decisions. Never describe work as complete unless the evidence proves it.`,
  };
}

export function OutcomeAssistantStarter({
  onStart,
}: {
  onStart: (initialValues: CreatePersonaInput) => void;
}) {
  const [selected, setSelected] = React.useState(PRESETS[0].id);
  const [outcome, setOutcome] = React.useState("");
  const [access, setAccess] = React.useState({
    browser: false,
    files: false,
    buzz: true,
  });
  const preset = PRESETS.find((item) => item.id === selected) ?? PRESETS[0];
  const selectedAccess = Object.entries(access)
    .filter(([, enabled]) => enabled)
    .map(([name]) => name);

  return (
    <section
      aria-label="Start with an outcome"
      className="rounded-xl border border-border/70 bg-card p-4 shadow-xs"
      data-testid="outcome-assistant-starter"
    >
      <div className="max-w-2xl">
        <h2 className="text-base font-semibold">Start with an outcome</h2>
        <p className="mt-1 text-sm text-muted-foreground">
          Pick a job, describe what finished looks like, and grant only the
          access it needs. You can review the agent before it starts.
        </p>
      </div>
      <div className="mt-4 grid gap-2 md:grid-cols-3">
        {PRESETS.map((item) => {
          const Icon = item.icon;
          const active = item.id === selected;
          return (
            <button
              aria-pressed={active}
              className={`rounded-lg border p-3 text-left transition-colors ${
                active
                  ? "border-primary bg-primary/5"
                  : "border-border/70 hover:bg-muted/50"
              }`}
              data-testid={`outcome-preset-${item.id}`}
              key={item.id}
              onClick={() => setSelected(item.id)}
              type="button"
            >
              <Icon className="h-4 w-4" />
              <span className="mt-2 block text-sm font-medium">
                {item.name}
              </span>
              <span className="mt-1 block text-xs text-muted-foreground">
                {item.description}
              </span>
            </button>
          );
        })}
      </div>
      <Input
        aria-label="Desired outcome"
        className="mt-3"
        data-testid="outcome-request"
        maxLength={500}
        onChange={(event) => setOutcome(event.target.value)}
        placeholder="What should be finished?"
        value={outcome}
      />
      <fieldset className="mt-3">
        <legend className="text-xs font-medium">Minimum access</legend>
        <div className="mt-2 flex flex-wrap gap-4 text-xs">
          {(
            [
              ["buzz", "Buzz conversations"],
              ["browser", "Signed-in browser"],
              ["files", "Local files"],
            ] as const
          ).map(([key, label]) => (
            <label className="flex items-center gap-2" key={key}>
              <input
                checked={access[key]}
                onChange={(event) =>
                  setAccess((current) => ({
                    ...current,
                    [key]: event.target.checked,
                  }))
                }
                type="checkbox"
              />
              {label}
            </label>
          ))}
        </div>
      </fieldset>
      <Button
        className="mt-4"
        data-testid="review-outcome-assistant"
        disabled={outcome.trim().length < 3 || selectedAccess.length === 0}
        onClick={() =>
          onStart(
            buildOutcomeAssistantInitialValues(
              preset.id,
              outcome,
              selectedAccess,
            ),
          )
        }
        type="button"
      >
        Review assistant and access
      </Button>
    </section>
  );
}
