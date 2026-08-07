import { invokeTauri } from "./tauri";

export type NumbatFindingSeverity = "low" | "medium" | "high" | "critical";

export type NumbatFinding = {
  findingId: string;
  ruleId: string;
  title: string;
  severity: NumbatFindingSeverity;
  detectedAt: string;
  sourceAgent: string;
  sessionId: string | null;
  channelId: string | null;
  turnId: string | null;
  evidenceCount: number;
};

export type NumbatFindingBatch = {
  nextOffset: number;
  reset: boolean;
  rejectedRecords: number;
  health: {
    state: "active" | "configured" | "disconnected" | "unsupported" | "stale";
    detail: string;
  };
  findings: NumbatFinding[];
};

export type GuardianNumbatStatus = {
  state: "not_active" | "active" | "tampered" | "error";
  provenance: "none" | "external_unmanaged" | "buzz_managed";
  version: string | null;
  digestSuffix: string | null;
  rollbackAvailable: boolean;
  target: string;
  detail: string;
};

export type GuardianCase = {
  caseId: string;
  title: string;
  status: string;
  severity: NumbatFindingSeverity;
  findingIds: string[];
  openedAt: string;
  updatedAt: string;
};

export type GuardianSuppression = {
  suppressionId: string;
  findingId: string;
  reason: string;
  startsAt: string;
  expiresAt: string;
  status: "active" | "expired" | "cancelled";
};

export type GuardianCaseImportPreview = {
  schemaVersion: string;
  profile: "redacted" | "regression" | "full";
  caseId: string;
  fileCount: number;
  verified: boolean;
};

export function getGuardianNumbatStatus(): Promise<GuardianNumbatStatus> {
  return invokeTauri<GuardianNumbatStatus>("get_guardian_numbat_status");
}

export function activateGuardianNumbat(): Promise<GuardianNumbatStatus> {
  return invokeTauri<GuardianNumbatStatus>("activate_guardian_numbat");
}

export function installGuardianNumbat(): Promise<GuardianNumbatStatus> {
  return invokeTauri<GuardianNumbatStatus>("install_guardian_numbat");
}

export function cancelGuardianNumbatInstall(): Promise<boolean> {
  return invokeTauri<boolean>("cancel_guardian_numbat_install");
}

export function deactivateGuardianNumbat(): Promise<GuardianNumbatStatus> {
  return invokeTauri<GuardianNumbatStatus>("deactivate_guardian_numbat");
}

export function rollbackGuardianNumbat(): Promise<GuardianNumbatStatus> {
  return invokeTauri<GuardianNumbatStatus>("rollback_guardian_numbat");
}

export function uninstallGuardianNumbat(): Promise<GuardianNumbatStatus> {
  return invokeTauri<GuardianNumbatStatus>("uninstall_guardian_numbat");
}

export function readNumbatFindings(
  agentPubkey: string,
  offset: number,
  sessionId: string | null,
  channelId: string | null,
  turnId: string | null,
): Promise<NumbatFindingBatch> {
  return invokeTauri<NumbatFindingBatch>("read_numbat_findings", {
    agentPubkey,
    offset,
    sessionId,
    channelId,
    turnId,
  });
}

export function acknowledgeGuardianFinding(
  agentPubkey: string,
  findingId: string,
): Promise<string> {
  return invokeTauri<string>("acknowledge_guardian_finding", {
    agentPubkey,
    findingId,
  });
}

export function createGuardianCase(
  agentPubkey: string,
  findingIds: string[],
  title: string,
): Promise<GuardianCase> {
  return invokeTauri<GuardianCase>("create_guardian_case", {
    input: { agentPubkey, findingIds, title },
  });
}

export function listGuardianCases(
  agentPubkey: string,
): Promise<GuardianCase[]> {
  return invokeTauri<GuardianCase[]>("list_guardian_cases", { agentPubkey });
}

export function updateGuardianCaseStatus(
  caseId: string,
  status: string,
): Promise<GuardianCase> {
  return invokeTauri<GuardianCase>("update_guardian_case_status", {
    input: { caseId, status },
  });
}

export function createGuardianSuppression(
  agentPubkey: string,
  findingId: string,
  reason: string,
  expiresAt: string,
): Promise<GuardianSuppression> {
  return invokeTauri<GuardianSuppression>("create_guardian_suppression", {
    input: { agentPubkey, findingId, reason, expiresAt },
  });
}

export function listGuardianSuppressions(
  agentPubkey: string,
): Promise<GuardianSuppression[]> {
  return invokeTauri<GuardianSuppression[]>("list_guardian_suppressions", {
    agentPubkey,
  });
}

export function cancelGuardianSuppression(
  suppressionId: string,
  reason: string,
): Promise<GuardianSuppression> {
  return invokeTauri<GuardianSuppression>("cancel_guardian_suppression", {
    input: { suppressionId, reason },
  });
}

export function saveGuardianCaseBundle(
  caseId: string,
  profile: "redacted" | "regression" | "full",
  confirmation?: {
    destinationLabel: string;
    ownerConfirmedSecrets: boolean;
  },
): Promise<boolean> {
  return invokeTauri<boolean>("save_guardian_case_bundle", {
    input: {
      caseId,
      profile,
      destinationLabel: confirmation?.destinationLabel,
      ownerConfirmedSecrets: confirmation?.ownerConfirmedSecrets,
    },
  });
}

export function importGuardianCaseBundle(
  bytes: number[],
): Promise<GuardianCaseImportPreview> {
  return invokeTauri<GuardianCaseImportPreview>("import_guardian_case_bundle", {
    input: { bytes },
  });
}
