import * as React from "react";
import { ShieldAlert } from "lucide-react";
import { toast } from "sonner";

import {
  acknowledgeGuardianFinding,
  createGuardianCase,
  createGuardianSuppression,
  listGuardianCases,
  listGuardianSuppressions,
  type GuardianCase,
  type GuardianSuppression,
  type NumbatFinding,
  updateGuardianCaseStatus,
} from "@/shared/api/tauriNumbat";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
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
  const [suppressions, setSuppressions] = React.useState<GuardianSuppression[]>(
    [],
  );
  const [suppressionDraft, setSuppressionDraft] = React.useState<string | null>(
    null,
  );
  const [suppressionReason, setSuppressionReason] = React.useState("");

  const refreshCases = React.useCallback(() => {
    void listGuardianCases(agentPubkey)
      .then(setCases)
      .catch(() => undefined);
  }, [agentPubkey]);

  React.useEffect(refreshCases, [refreshCases]);

  React.useEffect(() => {
    void listGuardianSuppressions(agentPubkey)
      .then(setSuppressions)
      .catch(() => undefined);
  }, [agentPubkey]);

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
        <div className="space-y-2" data-testid="guardian-case-list">
          <p
            className="text-xs text-muted-foreground"
            data-testid="guardian-case-count"
          >
            {cases.length} local investigation case
            {cases.length === 1 ? "" : "s"}
          </p>
          {cases.map((item) => {
            const nextStatus =
              item.status === "new"
                ? "triaged"
                : item.status === "triaged" || item.status === "reopened"
                  ? "investigating"
                  : item.status === "investigating"
                    ? "resolved"
                    : item.status === "resolved"
                      ? "closed"
                      : item.status === "closed"
                        ? "reopened"
                        : null;
            return (
              <div
                className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border/70 px-3 py-2"
                data-case-id={item.caseId}
                key={item.caseId}
              >
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium">{item.title}</p>
                  <p className="text-xs text-muted-foreground">
                    {item.status.replaceAll("_", " ")} ·{" "}
                    {item.findingIds.length} finding
                    {item.findingIds.length === 1 ? "" : "s"}
                  </p>
                </div>
                {nextStatus ? (
                  <Button
                    data-testid="guardian-advance-case"
                    onClick={() => {
                      void updateGuardianCaseStatus(item.caseId, nextStatus)
                        .then((updated) => {
                          setCases((current) =>
                            current.map((candidate) =>
                              candidate.caseId === updated.caseId
                                ? updated
                                : candidate,
                            ),
                          );
                          toast.success(
                            `Case moved to ${updated.status.replaceAll("_", " ")}`,
                          );
                        })
                        .catch((cause: unknown) =>
                          toast.error(
                            cause instanceof Error
                              ? cause.message
                              : "Could not update case",
                          ),
                        );
                    }}
                    size="xs"
                    type="button"
                    variant="outline"
                  >
                    {nextStatus === "reopened"
                      ? "Reopen"
                      : `Mark ${nextStatus.replaceAll("_", " ")}`}
                  </Button>
                ) : null}
              </div>
            );
          })}
        </div>
      ) : null}
      {findings
        .slice()
        .reverse()
        .map((finding) => {
          const activeSuppression = suppressions.find(
            (item) =>
              item.findingId === finding.findingId && item.status === "active",
          );
          return (
            <article
              className={cn(
                "rounded-lg border px-3 py-3",
                finding.severity === "critical"
                  ? "border-destructive/50 bg-destructive/10"
                  : finding.severity === "high"
                    ? "border-amber-500/40 bg-amber-500/10"
                    : "border-border/70 bg-muted/35",
                activeSuppression && "opacity-70",
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
                    {activeSuppression ? (
                      <Badge variant="outline">Suppressed</Badge>
                    ) : null}
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
                    <Button
                      data-testid="guardian-suppress-finding"
                      disabled={Boolean(activeSuppression)}
                      onClick={() => {
                        setSuppressionDraft(finding.findingId);
                        setSuppressionReason("");
                      }}
                      size="xs"
                      type="button"
                      variant="outline"
                    >
                      {activeSuppression ? "Suppressed" : "Suppress"}
                    </Button>
                  </div>
                  {suppressionDraft === finding.findingId ? (
                    <div
                      className="mt-2 flex items-center gap-2"
                      data-testid="guardian-suppression-form"
                    >
                      <Input
                        aria-label="Suppression reason"
                        maxLength={240}
                        onChange={(event) =>
                          setSuppressionReason(event.target.value)
                        }
                        placeholder="Reason for suppressing this alert"
                        value={suppressionReason}
                      />
                      <Button
                        disabled={suppressionReason.trim().length < 3}
                        onClick={() => {
                          setPendingFinding(finding.findingId);
                          const expiresAt = new Date(
                            Date.now() + 24 * 60 * 60 * 1000,
                          ).toISOString();
                          void createGuardianSuppression(
                            agentPubkey,
                            finding.findingId,
                            suppressionReason.trim(),
                            expiresAt,
                          )
                            .then((created) => {
                              setSuppressions((current) => [
                                created,
                                ...current,
                              ]);
                              setSuppressionDraft(null);
                              setSuppressionReason("");
                              toast.success("Alert suppressed for 24 hours");
                            })
                            .catch((cause: unknown) =>
                              toast.error(
                                cause instanceof Error
                                  ? cause.message
                                  : "Could not suppress finding",
                              ),
                            )
                            .finally(() => setPendingFinding(null));
                        }}
                        size="xs"
                        type="button"
                      >
                        Suppress 24h
                      </Button>
                      <Button
                        onClick={() => setSuppressionDraft(null)}
                        size="xs"
                        type="button"
                        variant="ghost"
                      >
                        Cancel
                      </Button>
                    </div>
                  ) : null}
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
