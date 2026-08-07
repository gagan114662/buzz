import { CheckCircle2, CircleAlert } from "lucide-react";

import type { TranscriptItem } from "./agentSessionTypes";

export type CompletionPacket = {
  completed: string[];
  blockers: string[];
  evidence: string[];
  approvals: string[];
  unresolvedDecisions: string[];
};

const PACKET_PATTERN = /```buzz-completion-packet\s*([\s\S]*?)```/i;

function stringList(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > 100) return null;
  const list = value.filter(
    (item): item is string =>
      typeof item === "string" && item.trim().length > 0 && item.length <= 1000,
  );
  return list.length === value.length ? list : null;
}

export function parseCompletionPacket(text: string): CompletionPacket | null {
  const match = text.match(PACKET_PATTERN);
  if (!match) return null;
  let value: unknown;
  try {
    value = JSON.parse(match[1]);
  } catch {
    return null;
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    "completed",
    "blockers",
    "evidence",
    "approvals",
    "unresolvedDecisions",
  ]);
  if (Object.keys(record).some((key) => !allowed.has(key))) return null;
  const completed = stringList(record.completed);
  const blockers = stringList(record.blockers);
  const evidence = stringList(record.evidence);
  const approvals = stringList(record.approvals);
  const unresolvedDecisions = stringList(record.unresolvedDecisions);
  if (
    !completed ||
    !blockers ||
    !evidence ||
    !approvals ||
    !unresolvedDecisions
  ) {
    return null;
  }
  return { completed, blockers, evidence, approvals, unresolvedDecisions };
}

export function latestCompletionPacket(
  items: TranscriptItem[],
): CompletionPacket | null {
  for (let index = items.length - 1; index >= 0; index -= 1) {
    const item = items[index];
    if (item.type === "message" && item.role === "assistant") {
      const packet = parseCompletionPacket(item.text);
      if (packet) return packet;
    }
  }
  return null;
}

function PacketList({
  empty,
  items,
  title,
}: {
  empty: string;
  items: string[];
  title: string;
}) {
  return (
    <div>
      <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {title}
      </h4>
      {items.length > 0 ? (
        <ul className="mt-1 space-y-1 text-sm">
          {items.map((item) => (
            <li className="break-words" key={item}>
              {item}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-1 text-sm text-muted-foreground">{empty}</p>
      )}
    </div>
  );
}

export function CompletionPacketCard({ packet }: { packet: CompletionPacket }) {
  const ready =
    packet.blockers.length === 0 && packet.unresolvedDecisions.length === 0;
  return (
    <section
      aria-label="Completion packet"
      className="mb-4 rounded-lg border border-border/70 bg-card p-4"
      data-testid="completion-packet"
    >
      <div className="flex items-center gap-2">
        {ready ? (
          <CheckCircle2 className="h-4 w-4 text-emerald-600" />
        ) : (
          <CircleAlert className="h-4 w-4 text-amber-600" />
        )}
        <h3 className="text-sm font-semibold">
          {ready ? "Ready for review" : "Review needed"}
        </h3>
      </div>
      <div className="mt-3 grid gap-4 md:grid-cols-2">
        <PacketList
          empty="Nothing claimed complete."
          items={packet.completed}
          title="Completed"
        />
        <PacketList
          empty="No blockers reported."
          items={packet.blockers}
          title="Blockers"
        />
        <PacketList
          empty="No evidence supplied."
          items={packet.evidence}
          title="Evidence"
        />
        <PacketList
          empty="No approvals used."
          items={packet.approvals}
          title="Approvals"
        />
        <PacketList
          empty="No unresolved decisions."
          items={packet.unresolvedDecisions}
          title="Unresolved decisions"
        />
      </div>
    </section>
  );
}
