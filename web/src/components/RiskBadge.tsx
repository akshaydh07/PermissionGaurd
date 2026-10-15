import { AlertCircle, CheckCircle2, CircleAlert } from "lucide-react";
import type { RiskLevel } from "../types";

const icons = {
  Low: CheckCircle2,
  Medium: CircleAlert,
  High: AlertCircle,
};

export function RiskBadge({
  level,
  score,
  small = false,
}: {
  level: RiskLevel;
  score?: number;
  small?: boolean;
}) {
  const Icon = icons[level];
  return (
    <span className={`risk-badge risk-${level.toLowerCase()}${small ? " risk-badge--small" : ""}`}>
      <Icon size={small ? 13 : 15} aria-hidden="true" />
      {score === undefined ? level : `${level} · ${score}`}
    </span>
  );
}
