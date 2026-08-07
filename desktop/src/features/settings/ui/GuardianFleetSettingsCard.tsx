import * as React from "react";

import {
  configureGuardianFleet,
  getGuardianFleet,
  seedGuardianFleetSimulation,
  setGuardianFleetEmergencyStop,
  type GuardianFleet,
} from "@/shared/api/tauriGuardianFleet";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { SettingsOptionGroup, SettingsOptionRow } from "./SettingsOptionGroup";
import { SettingsSectionHeader } from "./SettingsSectionHeader";

const SAVED_ORGANIZATION_KEY = "buzz.guardian-fleet.organization";

function errorMessage(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

export function GuardianFleetSettingsCard({
  currentPubkey,
}: {
  currentPubkey?: string;
}) {
  const [fleet, setFleet] = React.useState<GuardianFleet | null>(null);
  const [organizationId, setOrganizationId] = React.useState(
    () => window.localStorage.getItem(SAVED_ORGANIZATION_KEY) ?? "",
  );
  const [name, setName] = React.useState("");
  const [securityApprover, setSecurityApprover] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const remember = (next: GuardianFleet) => {
    setFleet(next);
    setOrganizationId(next.organizationId);
    window.localStorage.setItem(SAVED_ORGANIZATION_KEY, next.organizationId);
  };

  const run = async (operation: () => Promise<GuardianFleet>) => {
    setBusy(true);
    setError(null);
    try {
      remember(await operation());
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(false);
    }
  };

  React.useEffect(() => {
    if (!organizationId) return;
    void run(() => getGuardianFleet(organizationId));
    // Load the last selected organization only once on entry.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <section className="min-w-0" data-testid="settings-guardian-fleet">
      <SettingsSectionHeader
        description="Stage a signed policy across company endpoints, require owner and security approval, see drift or offline machines, and stop rollout activity immediately."
        title="Guardian fleet control"
      />
      <SettingsOptionGroup>
        <SettingsOptionRow className="items-start gap-4">
          <div className="min-w-0 flex-1 space-y-1">
            <div className="font-medium">Safe test company</div>
            <p className="text-xs text-muted-foreground">
              Creates clearly labeled synthetic endpoints: one healthy, one
              drifted, and one offline. No real agent or company is contacted.
            </p>
          </div>
          <Button
            data-testid="guardian-seed-fleet-simulation"
            disabled={busy || !currentPubkey}
            onClick={() => void run(seedGuardianFleetSimulation)}
          >
            Load simulation
          </Button>
        </SettingsOptionRow>

        <SettingsOptionRow className="block space-y-3 border-t border-border/50">
          <div className="font-medium">Open or create an organization</div>
          <div className="grid gap-2 md:grid-cols-2">
            <Input
              aria-label="Organization ID"
              onChange={(event) => setOrganizationId(event.target.value)}
              placeholder="organization-id"
              value={organizationId}
            />
            <Input
              aria-label="Organization name"
              onChange={(event) => setName(event.target.value)}
              placeholder="Organization name"
              value={name}
            />
          </div>
          <Input
            aria-label="Security approver public key"
            onChange={(event) => setSecurityApprover(event.target.value)}
            placeholder="64-character security approver public key"
            value={securityApprover}
          />
          <div className="flex flex-wrap justify-end gap-2">
            <Button
              disabled={busy || !organizationId}
              onClick={() => void run(() => getGuardianFleet(organizationId))}
              variant="outline"
            >
              Open
            </Button>
            <Button
              disabled={
                busy ||
                !currentPubkey ||
                !organizationId ||
                !name ||
                securityApprover.length !== 64
              }
              onClick={() =>
                void run(() =>
                  configureGuardianFleet({
                    organizationId,
                    name,
                    ownerPubkey: currentPubkey ?? "",
                    securityApproverPubkey: securityApprover,
                  }),
                )
              }
            >
              Create or update
            </Button>
          </div>
        </SettingsOptionRow>
      </SettingsOptionGroup>

      {fleet ? (
        <div className="mt-4 space-y-3" data-testid="guardian-fleet-dashboard">
          <SettingsOptionGroup>
            <SettingsOptionRow className="items-start">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2 font-medium">
                  {fleet.name}
                  {fleet.simulation ? <Badge>Simulation</Badge> : null}
                  {fleet.emergencyStopped ? (
                    <Badge variant="destructive">Emergency stopped</Badge>
                  ) : null}
                </div>
                <div className="mt-1 break-all text-xs text-muted-foreground">
                  {fleet.organizationId} · {fleet.endpoints.length} endpoints ·{" "}
                  {fleet.rollouts.length} rollouts
                </div>
              </div>
              <Button
                data-testid="guardian-fleet-emergency-stop"
                disabled={busy}
                onClick={() =>
                  void run(() =>
                    setGuardianFleetEmergencyStop(
                      fleet.organizationId,
                      !fleet.emergencyStopped,
                    ),
                  )
                }
                variant={fleet.emergencyStopped ? "outline" : "destructive"}
              >
                {fleet.emergencyStopped ? "Resume fleet" : "Emergency stop"}
              </Button>
            </SettingsOptionRow>
            {fleet.endpoints.map((endpoint) => (
              <SettingsOptionRow
                className="border-t border-border/50"
                data-testid={`guardian-fleet-endpoint-${endpoint.endpointId}`}
                key={endpoint.endpointId}
              >
                <div className="min-w-0">
                  <div className="font-medium">{endpoint.endpointId}</div>
                  <div className="text-xs text-muted-foreground">
                    Expected policy{" "}
                    {endpoint.expectedPolicyHash?.slice(0, 10) ?? "none"}…
                  </div>
                </div>
                <Badge
                  variant={
                    endpoint.status === "healthy"
                      ? "secondary"
                      : endpoint.status === "drifted" ||
                          endpoint.status === "failed"
                        ? "destructive"
                        : "outline"
                  }
                >
                  {endpoint.status}
                </Badge>
              </SettingsOptionRow>
            ))}
          </SettingsOptionGroup>
        </div>
      ) : null}

      {!currentPubkey ? (
        <p className="mt-3 text-sm text-muted-foreground">
          Sign in before configuring fleet authority.
        </p>
      ) : null}
      {error ? (
        <p className="mt-3 text-sm text-destructive" role="alert">
          {error}
        </p>
      ) : null}
    </section>
  );
}
