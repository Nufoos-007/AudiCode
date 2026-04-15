import { Severity } from "../types/audit";

interface SeverityPillProps {
  severity: Severity;
  count: number;
}

const severityStyles: Record<Severity, string> = {
  critical: "bg-severity-critical-dim text-severity-critical border-severity-critical/30",
  high: "bg-severity-high-dim text-severity-high border-severity-high/30",
  medium: "bg-severity-medium-dim text-severity-medium border-severity-medium/30",
  low: "bg-severity-low-dim text-severity-low border-severity-low/30",
};

const SeverityPill = ({ severity, count }: SeverityPillProps) => {
  return (
    <span
      className={`px-2.5 py-1 rounded-full font-mono text-[11px] font-medium border ${severityStyles[severity]}`}
    >
      {count} {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
};

export default SeverityPill;
