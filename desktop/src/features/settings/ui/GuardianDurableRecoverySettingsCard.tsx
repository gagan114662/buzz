import * as React from "react";

import {
  completeGuardianDurableSimulation,
  getGuardianDurableRecoverySimulation,
  reconcileGuardianDurableSimulation,
  recoverGuardianDurableSimulation,
  seedGuardianDurableRecoverySimulation,
  type DurableRecoveryView,
} from "@/shared/api/tauriGuardianDurable";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { SettingsOptionGroup, SettingsOptionRow } from "./SettingsOptionGroup";
import { SettingsSectionHeader } from "./SettingsSectionHeader";

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

export function GuardianDurableRecoverySettingsCard() {
  const [view, setView] = React.useState<DurableRecoveryView | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const run = React.useCallback(
    async (operation: () => Promise<DurableRecoveryView>) => {
      setBusy(true);
      setError(null);
      try {
        setView(await operation());
      } catch (cause) {
        setError(message(cause));
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  React.useEffect(() => {
    void getGuardianDurableRecoverySimulation()
      .then(setView)
      .catch(() => undefined);
  }, []);

  const next = view
    ? view.recoveryState === "crashed_effect_unknown"
      ? {
          label: "Recover expired lease",
          action: recoverGuardianDurableSimulation,
        }
      : view.recoveryState === "recovered_needs_reconciliation"
        ? {
            label: "Reconcile delivery receipt",
            action: reconcileGuardianDurableSimulation,
          }
        : view.recoveryState === "ready_for_delivery"
          ? {
              label: "Complete verified delivery",
              action: completeGuardianDurableSimulation,
            }
          : null
    : null;

  return (
    <section
      className="min-w-0"
      data-testid="settings-guardian-durable-recovery"
    >
      <SettingsSectionHeader
        description="Resume work after a crash without repeating an uncertain external action. Lease generations fence stale workers, handoffs bind new authority, and delivery waits for an independent pass and receipt."
        title="Durable task recovery"
      />
      <SettingsOptionGroup>
        <SettingsOptionRow className="items-start">
          <div className="min-w-0 space-y-1">
            <div className="font-medium">Synthetic monthly close</div>
            <p className="text-xs text-muted-foreground">
              Recreates an expired worker lease and a delivery whose outcome is
              unknown after a crash. No real message or file is delivered.
            </p>
          </div>
          <Button
            data-testid="guardian-seed-durable-recovery"
            disabled={busy}
            onClick={() => void run(seedGuardianDurableRecoverySimulation)}
          >
            Reset simulation
          </Button>
        </SettingsOptionRow>

        {view ? (
          <>
            <SettingsOptionRow className="border-t border-border/50">
              <div>
                <div className="font-medium">
                  Task revision {view.task.revision}
                </div>
                <div className="text-xs text-muted-foreground">
                  Lease generation {view.lease?.generation ?? "none"} · actor{" "}
                  {view.task.actor_pubkey.slice(0, 10)}…
                </div>
              </div>
              <Badge>{view.recoveryState.replaceAll("_", " ")}</Badge>
            </SettingsOptionRow>
            <SettingsOptionRow className="border-t border-border/50">
              <div>
                <div className="font-medium">External delivery effect</div>
                <div className="text-xs text-muted-foreground">
                  Receipt{" "}
                  {view.effect.receipt_hash?.slice(0, 10) ?? "not proven"}
                </div>
              </div>
              <Badge
                variant={
                  view.effect.state === "indeterminate"
                    ? "destructive"
                    : "secondary"
                }
              >
                {view.effect.state}
              </Badge>
            </SettingsOptionRow>
            <SettingsOptionRow className="border-t border-border/50">
              <div>
                <div className="font-medium">Authority handoff</div>
                <div className="text-xs text-muted-foreground">
                  {view.handoffs[0]?.accepted_revision_hash
                    ? "Accepted with a new reviewer grant"
                    : "No accepted handoff"}
                </div>
              </div>
              {next ? (
                <Button
                  data-testid="guardian-durable-next-action"
                  disabled={busy}
                  onClick={() => void run(next.action)}
                >
                  {next.label}
                </Button>
              ) : null}
            </SettingsOptionRow>
          </>
        ) : null}
      </SettingsOptionGroup>
      {error ? (
        <p className="mt-3 text-sm text-destructive" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
