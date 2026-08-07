import * as React from "react";
import { ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import {
  acknowledgeGuardianFinding,
  createGuardianCase,
  listGuardianCases,
  type GuardianCase,
  type NumbatFinding,
} from "@/shared/api/tauriNumbat";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { cn } from "@/shared/lib/cn";

export function NumbatSecurityFindings({
  agentPubkey,
  error,
  findings,
  health,
  onCancelTurn,
}: {
  agentPubkey: string;
  error: string | null;
  findings: NumbatFinding[];
  health: {
    state: "active" | "configured" | "disconnected" | "unsupported" | "stale";
    detail: string;
  } | null;
  onCancelTurn?: () => void;
}) {
  const [acknowledged, setAcknowledged] = React.useState<Set<string>>(
    () => new Set(),
  );
  const [cases, setCases] = React.useState<GuardianCase[]>([]);
  const [pendingFinding, setPendingFinding] = React.useState<string | null>(
    null,
  );

  const refreshCases = React.useCallback(() => {
    void listGuardianCases(agentPubkey)
      .then(setCases)
      .catch(() => undefined);
  }, [agentPubkey]);

  React.useEffect(refreshCases, [refreshCases]);

  if (findings.length === 0 && !error && !health) return null;

  return (
    <section
      aria-label="Guardian security findings"
      className="mb-3 space-y-2"
      data-testid="guardian-security-findings"
    >
      {health ? (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Badge variant="outline">{health.state}</Badge>
          <span>{health.detail}</span>
        </div>
      ) : null}
      {cases.length > 0 ? (
        <p
          className="text-xs text-muted-foreground"
          data-testid="guardian-case-count"
        >
          {cases.length} local investigation case{cases.length === 1 ? "" : "s"}
        </p>
      ) : null}
      {findings
        .slice()
        .reverse()
        .map((finding) => {
          return (
            <article
              className={cn(
                "rounded-lg border px-3 py-3",
                finding.severity === "critical"
                  ? "border-destructive/50 bg-destructive/10"
                  : finding.severity === "high"
                    ? "border-amber-500/40 bg-amber-500/10"
                    : "border-border/70 bg-muted/35",
              )}
              data-finding-id={finding.findingId}
              key={finding.findingId}
            >
              <div className="flex items-start gap-3">
                <ShieldAlert
                  aria-hidden="true"
                  className="mt-0.5 h-4 w-4 shrink-0 text-amber-600"
                />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <Badge variant="outline">
                      {finding.severity.toUpperCase()}
                    </Badge>
                    <span className="text-sm font-semibold">
                      {finding.title}
                    </span>
                  </div>
                  <p className="mt-1 text-xs text-muted-foreground">
                    {finding.evidenceCount} correlated evidence event
                    {finding.evidenceCount === 1 ? "" : "s"}
                    {finding.sessionId
                      ? " · Session correlated"
                      : " · Local finding"}
                  </p>
                  <p className="mt-1 font-mono text-xs text-muted-foreground">
                    {finding.ruleId}
                  </p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    <Button
                      data-testid="guardian-acknowledge-finding"
                      disabled={
                        pendingFinding === finding.findingId ||
                        acknowledged.has(finding.findingId)
                      }
                      onClick={() => {
                        setPendingFinding(finding.findingId);
                        void acknowledgeGuardianFinding(
                          agentPubkey,
                          finding.findingId,
                        )
                          .then(() => {
                            setAcknowledged((current) =>
                              new Set(current).add(finding.findingId),
                            );
                            toast.success("Finding acknowledged");
                          })
                          .catch((cause: unknown) =>
                            toast.error(
                              cause instanceof Error
                                ? cause.message
                                : "Could not acknowledge finding",
                            ),
                          )
                          .finally(() => setPendingFinding(null));
                      }}
                      size="xs"
                      type="button"
                      variant="outline"
                    >
                      {acknowledged.has(finding.findingId)
                        ? "Acknowledged"
                        : "Acknowledge"}
                    </Button>
                    <Button
                      data-testid="guardian-create-case"
                      disabled={
                        pendingFinding === finding.findingId ||
                        cases.some((item) =>
                          item.findingIds.includes(finding.findingId),
                        )
                      }
                      onClick={() => {
                        setPendingFinding(finding.findingId);
                        void createGuardianCase(
                          agentPubkey,
                          [finding.findingId],
                          finding.title,
                        )
                          .then((created) => {
                            setCases((current) => [created, ...current]);
                            toast.success("Investigation case opened");
                          })
                          .catch((cause: unknown) =>
                            toast.error(
                              cause instanceof Error
                                ? cause.message
                                : "Could not open case",
                            ),
                          )
                          .finally(() => setPendingFinding(null));
                      }}
                      size="xs"
                      type="button"
                      variant="outline"
                    >
                      {cases.some((item) =>
                        item.findingIds.includes(finding.findingId),
                      )
                        ? "Case opened"
                        : "Open case"}
                    </Button>
                  </div>
                  {(finding.severity === "high" ||
                    finding.severity === "critical") &&
                  onCancelTurn ? (
                    <Button
                      className="mt-2"
                      data-testid="guardian-cancel-turn"
                      onClick={onCancelTurn}
                      size="xs"
                      type="button"
                      variant="destructive"
                    >
                      Stop this turn
                    </Button>
                  ) : null}
                </div>
              </div>
            </article>
          );
        })}
      {error ? (
        <p className="text-xs text-muted-foreground">
          Guardian is temporarily unavailable: {error}
        </p>
      ) : null}
    </section>
  );
}
