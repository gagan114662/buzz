import * as React from "react";

import {
  configureGuardianMacVmSandbox,
  getGuardianSandboxStatus,
  validateGuardianSandboxProfile,
  type GuardianSandboxStatus,
} from "@/shared/api/tauriGuardianSandbox";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { SettingsOptionGroup, SettingsOptionRow } from "./SettingsOptionGroup";
import { SettingsSectionHeader } from "./SettingsSectionHeader";

function message(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

export function GuardianSandboxSettingsCard() {
  const [status, setStatus] = React.useState<GuardianSandboxStatus | null>(
    null,
  );
  const [helperPath, setHelperPath] = React.useState("");
  const [helperSha256, setHelperSha256] = React.useState("");
  const [vmImagePath, setVmImagePath] = React.useState("");
  const [vmImageSha256, setVmImageSha256] = React.useState("");
  const [teamIdentifier, setTeamIdentifier] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const run = React.useCallback(
    async (operation: () => Promise<GuardianSandboxStatus>) => {
      setBusy(true);
      setError(null);
      try {
        setStatus(await operation());
      } catch (cause) {
        setError(message(cause));
      } finally {
        setBusy(false);
      }
    },
    [],
  );

  React.useEffect(() => {
    void run(getGuardianSandboxStatus);
  }, [run]);

  const ready = status?.state === "ready";

  return (
    <section className="min-w-0" data-testid="settings-guardian-sandbox">
      <SettingsSectionHeader
        description="Strong Mac isolation uses an Apple-signed Buzz helper and a pinned disposable virtual-machine image. Buzz refuses protected launches when trust or required capabilities cannot be proved."
        title="Guardian execution sandbox"
      />
      <SettingsOptionGroup>
        <SettingsOptionRow className="items-start">
          <div className="min-w-0 space-y-1">
            <div className="flex items-center gap-2 font-medium capitalize">
              {status?.state ?? "checking"}
              {ready ? <Badge>Strong isolation ready</Badge> : null}
            </div>
            <p className="text-xs text-muted-foreground">
              {status?.detail ?? "Checking the local isolation boundary…"}
            </p>
            {status?.teamIdentifier ? (
              <p className="text-xs text-muted-foreground">
                Apple team {status.teamIdentifier} · {status.backend}
              </p>
            ) : null}
          </div>
          <Button
            disabled={busy}
            onClick={() => void run(getGuardianSandboxStatus)}
            variant="outline"
          >
            Refresh
          </Button>
        </SettingsOptionRow>

        {!ready ? (
          <SettingsOptionRow className="block space-y-2 border-t border-border/50">
            <div className="font-medium">Configure verified Mac backend</div>
            <Input
              aria-label="Signed sandbox helper path"
              onChange={(event) => setHelperPath(event.target.value)}
              placeholder="Absolute path to signed helper"
              value={helperPath}
            />
            <Input
              aria-label="Sandbox helper SHA-256"
              onChange={(event) => setHelperSha256(event.target.value)}
              placeholder="Helper SHA-256"
              value={helperSha256}
            />
            <Input
              aria-label="Virtual machine image path"
              onChange={(event) => setVmImagePath(event.target.value)}
              placeholder="Absolute path to VM image"
              value={vmImagePath}
            />
            <Input
              aria-label="Virtual machine image SHA-256"
              onChange={(event) => setVmImageSha256(event.target.value)}
              placeholder="VM image SHA-256"
              value={vmImageSha256}
            />
            <Input
              aria-label="Apple team identifier"
              onChange={(event) => setTeamIdentifier(event.target.value)}
              placeholder="10-character Apple team identifier"
              value={teamIdentifier}
            />
            <div className="flex justify-end">
              <Button
                disabled={
                  busy ||
                  !helperPath ||
                  helperSha256.length !== 64 ||
                  !vmImagePath ||
                  vmImageSha256.length !== 64 ||
                  teamIdentifier.length !== 10
                }
                onClick={() =>
                  void run(() =>
                    configureGuardianMacVmSandbox({
                      helperPath,
                      helperSha256,
                      vmImagePath,
                      vmImageSha256,
                      expectedTeamIdentifier: teamIdentifier,
                    }),
                  )
                }
              >
                Verify and save
              </Button>
            </div>
          </SettingsOptionRow>
        ) : (
          <SettingsOptionRow className="border-t border-border/50">
            <div>
              <div className="font-medium">Protected agent profile</div>
              <p className="text-xs text-muted-foreground">
                Workspace write, network denied, whole process tree contained,
                CPU/memory/disk limits, and disposable reset.
              </p>
            </div>
            <Button
              data-testid="guardian-validate-sandbox-profile"
              disabled={busy}
              onClick={() => void run(validateGuardianSandboxProfile)}
              variant="outline"
            >
              Validate profile
            </Button>
          </SettingsOptionRow>
        )}
      </SettingsOptionGroup>
      {error ? (
        <p className="mt-3 text-sm text-destructive" role="alert">
          Refused: {error}
        </p>
      ) : null}
    </section>
  );
}
