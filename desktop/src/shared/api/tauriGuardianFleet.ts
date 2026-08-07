import { invokeTauri } from "./tauri";

export type GuardianFleetEndpoint = {
  endpointId: string;
  agentPubkey: string;
  expectedPolicyHash: string | null;
  observedPolicyHash: string | null;
  status: "offline" | "pending" | "healthy" | "failed" | "drifted";
  lastSeenAt: string | null;
};

export type GuardianFleetRollout = {
  rolloutId: string;
  policyHash: string;
  state: string;
  endpointIds: string[];
  waveSize: number;
  nextIndex: number;
  ownerApprovedAt: string | null;
  securityApprovedAt: string | null;
  createdAt: string;
};

export type GuardianFleet = {
  organizationId: string;
  name: string;
  ownerPubkey: string;
  securityApproverPubkey: string;
  emergencyStopped: boolean;
  simulation: boolean;
  endpoints: GuardianFleetEndpoint[];
  rollouts: GuardianFleetRollout[];
};

export function configureGuardianFleet(input: {
  organizationId: string;
  name: string;
  ownerPubkey: string;
  securityApproverPubkey: string;
}): Promise<GuardianFleet> {
  return invokeTauri<GuardianFleet>("configure_guardian_fleet", { input });
}

export function getGuardianFleet(
  organizationId: string,
): Promise<GuardianFleet> {
  return invokeTauri<GuardianFleet>("get_guardian_fleet", { organizationId });
}

export function seedGuardianFleetSimulation(): Promise<GuardianFleet> {
  return invokeTauri<GuardianFleet>("seed_guardian_fleet_simulation");
}

export function setGuardianFleetEmergencyStop(
  organizationId: string,
  stopped: boolean,
): Promise<GuardianFleet> {
  return invokeTauri<GuardianFleet>("set_guardian_fleet_emergency_stop", {
    input: { organizationId, stopped },
  });
}
