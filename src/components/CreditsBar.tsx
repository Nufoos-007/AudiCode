interface CreditsBarProps {
  used: number;
  total: number;
}

const CreditsBar = ({ used, total }: CreditsBarProps) => {
  const remaining = total - used;
  const percentage = (remaining / total) * 100;

  return (
    <div className="bg-surface border border-border rounded-[10px] p-4 px-5 flex items-center gap-4">
      <span className="font-mono text-[11px] text-muted-foreground whitespace-nowrap uppercase tracking-wider">
        Credits
      </span>
      <div className="flex-1 h-1.5 bg-surface-2 rounded-full overflow-hidden">
        <div
          className="h-full bg-primary rounded-full transition-all duration-600"
          style={{ width: `${percentage}%` }}
        />
      </div>
      <span className="font-mono text-[13px] font-medium whitespace-nowrap">
        <span className="text-primary">{remaining}</span> / {total} remaining
      </span>
    </div>
  );
};

export default CreditsBar;
