import {
  AlertTriangle,
  CheckCircle2,
  LoaderCircle,
  Repeat2,
} from "lucide-react";
import * as React from "react";

import { Badge } from "@/shared/ui/badge";
import { cn } from "@/shared/lib/cn";

import { buildAgentRunReplay } from "./agentRunReplay";
import type { ObserverEvent } from "./agentSessionTypes";

function durationLabel(durationMs: number | null): string | null {
  if (durationMs === null || !Number.isFinite(durationMs)) return null;
  if (durationMs < 1000) return `${durationMs} ms`;
  return `${(durationMs / 1000).toFixed(durationMs < 10_000 ? 1 : 0)} s`;
}

export function AgentFailureReplay({
  events,
}: {
  events: readonly ObserverEvent[];
}) {
  const replay = React.useMemo(() => buildAgentRunReplay(events), [events]);
  if (replay?.outcome !== "failed" || replay.steps.length === 0) {
    return null;
  }

  return (
    <section
      aria-label="Agent run replay"
      className="mb-3 overflow-hidden rounded-xl border border-destructive/30 bg-background"
      data-testid="agent-run-replay"
    >
      <div className="flex items-start justify-between gap-3 border-b border-border/60 p-4">
        <div>
          <p className="text-2xs font-semibold uppercase tracking-wide text-destructive">
            Visual failure replay
          </p>
          <h3 className="mt-1 text-sm font-semibold">Where this run broke</h3>
        </div>
        <Badge
          variant="outline"
          className="border-destructive/40 text-destructive"
        >
          Failed
        </Badge>
      </div>

      <ol className="flex gap-2 overflow-x-auto border-b border-border/60 p-4">
        {replay.steps.map((step, index) => {
          const failed = step.id === replay.failedStepId;
          const Icon = failed
            ? AlertTriangle
            : step.status === "running"
              ? LoaderCircle
              : CheckCircle2;
          return (
            <li
              className={cn(
                "relative min-w-48 flex-1 rounded-lg border p-3",
                failed
                  ? "border-destructive/50 bg-destructive/[0.04]"
                  : "border-border/70 bg-muted/20",
              )}
              data-replay-step-status={step.status}
              key={step.id}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Step {index + 1}
                </span>
                <Icon
                  aria-hidden
                  className={cn(
                    "h-4 w-4",
                    failed ? "text-destructive" : "text-emerald-600",
                  )}
                />
              </div>
              <p className="mt-2 text-xs font-semibold">{step.title}</p>
              <p className="mt-1 line-clamp-3 text-xs text-muted-foreground">
                {step.detail}
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-2xs text-muted-foreground">
                {step.repeatCount > 1 ? (
                  <span className="inline-flex items-center gap-1">
                    <Repeat2 aria-hidden className="h-3 w-3" />
                    Repeated {step.repeatCount} times
                  </span>
                ) : null}
                {durationLabel(step.durationMs) ? (
                  <span>{durationLabel(step.durationMs)}</span>
                ) : null}
              </div>
            </li>
          );
        })}
      </ol>

      <div className="grid gap-3 p-4 sm:grid-cols-2">
        <div className="rounded-lg bg-muted/25 p-3">
          <p className="text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
            Expected
          </p>
          <p className="mt-1 text-xs leading-5">{replay.expected}</p>
        </div>
        <div className="rounded-lg bg-destructive/[0.04] p-3">
          <p className="text-2xs font-semibold uppercase tracking-wide text-destructive">
            Actual
          </p>
          <p className="mt-1 text-xs leading-5">{replay.actual}</p>
        </div>
      </div>
      <p className="border-t border-border/60 px-4 py-3 text-xs text-muted-foreground">
        Review the failed step, add guidance in the channel, then mention the
        agent to resume safely.
      </p>
    </section>
  );
}
