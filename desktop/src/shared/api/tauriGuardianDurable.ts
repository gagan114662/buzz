import { invokeTauri } from "./tauri";

export type DurableRecoveryView = {
  task: {
    schema_version: string;
    task_id: string;
    revision: number;
    status: string;
    owner_pubkey: string;
    actor_pubkey: string;
    budget: {
      token_limit: number | null;
      cost_limit_microusd: number | null;
      consumed_tokens: number;
      consumed_microusd: number;
    };
    artifact_hashes: string[];
    unresolved_blocking_decisions: string[];
  };
  revisionHash: string;
  effect: {
    effect_key: string;
    payload_hash: string;
    state: "prepared" | "pending" | "observed" | "indeterminate";
    receipt_hash: string | null;
  };
  lease: {
    task_id: string;
    holder: string;
    generation: number;
    expires_at: string;
  } | null;
  handoffs: Array<{
    handoff_id: string;
    from_actor: string;
    to_actor: string;
    next_permitted_step: string;
    accepted_revision_hash: string | null;
  }>;
  recoveryState: string;
  synthetic: boolean;
};

export function seedGuardianDurableRecoverySimulation(): Promise<DurableRecoveryView> {
  return invokeTauri<DurableRecoveryView>(
    "seed_guardian_durable_recovery_simulation",
  );
}

export function getGuardianDurableRecoverySimulation(): Promise<DurableRecoveryView> {
  return invokeTauri<DurableRecoveryView>(
    "get_guardian_durable_recovery_simulation",
  );
}

export function recoverGuardianDurableSimulation(): Promise<DurableRecoveryView> {
  return invokeTauri<DurableRecoveryView>(
    "recover_guardian_durable_simulation",
  );
}

export function reconcileGuardianDurableSimulation(): Promise<DurableRecoveryView> {
  return invokeTauri<DurableRecoveryView>(
    "reconcile_guardian_durable_simulation",
  );
}

export function completeGuardianDurableSimulation(): Promise<DurableRecoveryView> {
  return invokeTauri<DurableRecoveryView>(
    "complete_guardian_durable_simulation",
  );
}
