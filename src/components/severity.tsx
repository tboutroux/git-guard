import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  Info,
  CircleHelp,
  type LucideIcon,
} from "lucide-react";
import type { Severity } from "@/lib/types";

export interface SeverityStyle {
  label: string;
  color: string; // hex from the status palette
  icon: LucideIcon;
}

export const SEVERITY: Record<Severity | "unknown", SeverityStyle> = {
  critical: { label: "Critical", color: "#d03b3b", icon: ShieldAlert },
  high: { label: "High", color: "#ec835a", icon: Flame },
  medium: { label: "Medium", color: "#fab219", icon: AlertTriangle },
  low: { label: "Low", color: "#3987e5", icon: Info },
  info: { label: "Info", color: "#898781", icon: Info },
  unknown: { label: "Unrated", color: "#898781", icon: CircleHelp },
};

export const SEVERITY_KEYS: (Severity | "unknown")[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/** Severity chip — icon + label + color, so meaning never rides on color alone. */
export function SeverityBadge({ severity }: { severity: Severity | "unknown" }) {
  const s = SEVERITY[severity];
  const Icon = s.icon;
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-semibold"
      style={{
        color: s.color,
        borderColor: `${s.color}55`,
        backgroundColor: `${s.color}18`,
      }}
    >
      <Icon className="h-3 w-3" aria-hidden />
      {s.label}
    </span>
  );
}
