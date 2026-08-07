import { invokeTauri } from "./tauri";

export type GuardianPolicyRule = {
  operation: string;
  decision: "allow" | "deny";
};

export type GuardianPolicyState =
  | "draft"
  | "simulated"
  | "awaiting_approval"
  | "approved"
  | "staged"
  | "active"
  | "paused"
  | "rolled_back"
  | "abandoned";

export type GuardianPolicyVersion = {
  policyHash: string;
  schemaVersion: string;
  agentPubkey: string;
  name: string;
  mode: "monitor" | "deny";
  rules: GuardianPolicyRule[];
  state: GuardianPolicyState;
  corpusVersion: string | null;
  simulationHash: string | null;
  createdAt: string;
  updatedAt: string;
};

export type GuardianPolicySimulation = {
  policyHash: string;
  corpusVersion: string;
  simulationHash: string;
  passed: boolean;
  allowCount: number;
  denyCount: number;
  unsupportedCount: number;
  partitions: string[];
};

export function createGuardianPolicyDraft(
  agentPubkey: string,
  name: string,
  mode: "monitor" | "deny",
  rules: GuardianPolicyRule[],
): Promise<GuardianPolicyVersion> {
  return invokeTauri<GuardianPolicyVersion>("create_guardian_policy_draft", {
    input: { agentPubkey, name, mode, rules },
  });
}

export function listGuardianPolicyVersions(
  agentPubkey: string,
): Promise<GuardianPolicyVersion[]> {
  return invokeTauri<GuardianPolicyVersion[]>("list_guardian_policy_versions", {
    agentPubkey,
  });
}

export function simulateGuardianPolicy(
  policyHash: string,
): Promise<GuardianPolicySimulation> {
  return invokeTauri<GuardianPolicySimulation>("simulate_guardian_policy", {
    policyHash,
  });
}

export function transitionGuardianPolicy(
  policyHash: string,
  action:
    | "request_approval"
    | "approve"
    | "stage_local_canary"
    | "activate"
    | "pause"
    | "rollback"
    | "abandon",
  approval?: { targetAgentPubkey: string; expiresAt: string },
  rollbackTargetHash?: string,
): Promise<GuardianPolicyVersion> {
  return invokeTauri<GuardianPolicyVersion>("transition_guardian_policy", {
    input: {
      policyHash,
      action,
      targetAgentPubkey: approval?.targetAgentPubkey,
      approvalExpiresAt: approval?.expiresAt,
      rollbackTargetHash,
    },
  });
}
