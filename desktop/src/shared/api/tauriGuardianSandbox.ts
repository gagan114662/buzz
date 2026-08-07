import { invokeTauri } from "./tauri";

export type GuardianSandboxCapabilities = {
  protocol: string;
  backend: string;
  virtualizationAvailable: boolean;
  filesystemIsolation: boolean;
  networkDeny: boolean;
  networkAllowlist: boolean;
  processTreeIsolation: boolean;
  cpuLimit: boolean;
  memoryLimit: boolean;
  diskQuota: boolean;
  disposableReset: boolean;
};

export type GuardianSandboxStatus = {
  schemaVersion: string;
  backend: string;
  state: "unconfigured" | "refused" | "ready";
  detail: string;
  helperPath: string | null;
  vmImagePath: string | null;
  helperVerified: boolean;
  imageVerified: boolean;
  signatureVerified: boolean;
  teamIdentifier: string | null;
  capabilities: GuardianSandboxCapabilities | null;
};

export function getGuardianSandboxStatus(): Promise<GuardianSandboxStatus> {
  return invokeTauri<GuardianSandboxStatus>("get_guardian_sandbox_status");
}

export function configureGuardianMacVmSandbox(input: {
  helperPath: string;
  helperSha256: string;
  vmImagePath: string;
  vmImageSha256: string;
  expectedTeamIdentifier: string;
}): Promise<GuardianSandboxStatus> {
  return invokeTauri<GuardianSandboxStatus>(
    "configure_guardian_macos_vm_sandbox",
    { input },
  );
}

export function validateGuardianSandboxProfile(): Promise<GuardianSandboxStatus> {
  return invokeTauri<GuardianSandboxStatus>(
    "validate_guardian_sandbox_profile",
    {
      profile: {
        filesystem: "workspace_write",
        network: "deny",
        processTree: true,
        cpuLimit: true,
        memoryLimit: true,
        diskQuota: true,
        disposableReset: true,
      },
    },
  );
}
