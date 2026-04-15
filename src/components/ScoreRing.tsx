import { useEffect, useState } from "react";

interface ScoreRingProps {
  score: number;
  grade: string;
}

const ScoreRing = ({ score, grade }: ScoreRingProps) => {
  const [animatedScore, setAnimatedScore] = useState(0);
  const circumference = 2 * Math.PI * 26;
  const offset = circumference - (animatedScore / 100) * circumference;

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedScore(score), 100);
    return () => clearTimeout(timer);
  }, [score]);

  const getColor = () => {
    if (score <= 30) return "hsl(var(--destructive))";
    if (score <= 50) return "#f97316";
    if (score <= 70) return "#eab308";
    return "hsl(var(--primary))";
  };

  const getTextColor = () => {
    if (score <= 30) return "text-destructive";
    if (score <= 50) return "text-orange-500";
    if (score <= 70) return "text-yellow-500";
    return "text-primary";
  };

  return (
    <div className="flex items-center gap-4 p-5 border-b border-border bg-surface-2">
      <div className="relative w-16 h-16">
        <svg width="64" height="64" viewBox="0 0 64 64" className="-rotate-90">
          <circle cx="32" cy="32" r="26" fill="none" stroke="hsl(var(--border))" strokeWidth="6" />
          <circle
            cx="32"
            cy="32"
            r="26"
            fill="none"
            stroke={getColor()}
            strokeWidth="6"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-700"
          />
        </svg>
        <div className={`absolute inset-0 flex items-center justify-center text-base font-extrabold ${getTextColor()}`}>
          {grade}
        </div>
      </div>
      <div>
        <h3 className="text-base font-bold">Security Score: {score}/100</h3>
        <p className="font-mono text-[11px] text-muted-foreground mt-1">
          {score <= 30
            ? "// Critical vulnerabilities detected. Immediate action recommended."
            : score <= 70
            ? "// Issues found. Review recommended."
            : "// Looking good. Minor improvements possible."}
        </p>
      </div>
    </div>
  );
};

export default ScoreRing;