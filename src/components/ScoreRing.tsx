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
    // Animate from 0 to actual score
    const duration = 1500;
    const startTime = Date.now();
    const startScore = 0;
    
    const animate = () => {
      const elapsed = Date.now() - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimatedScore(Math.round(startScore + (score - startScore) * eased));
      
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    
    const timeout = setTimeout(() => requestAnimationFrame(animate), 300);
    return () => clearTimeout(timeout);
  }, [score]);

  const getColor = () => {
    if (animatedScore <= 30) return "hsl(var(--destructive))";
    if (animatedScore <= 50) return "#f97316";
    if (animatedScore <= 70) return "#eab308";
    return "hsl(var(--primary))";
  };

  const getTextColor = () => {
    if (animatedScore <= 30) return "text-destructive";
    if (animatedScore <= 50) return "text-orange-500";
    if (animatedScore <= 70) return "text-yellow-500";
    return "text-primary";
  };

  const getMessage = () => {
    if (animatedScore <= 30) return {
      emoji: "🚨",
      text: "Critical issues detected. Immediate action required.",
    };
    if (animatedScore <= 50) return {
      emoji: "⚠️",
      text: "Security concerns found. Review recommended.",
    };
    if (animatedScore <= 70) return {
      emoji: "🔧",
      text: "Minor issues found. Some improvements possible.",
    };
    if (animatedScore <= 85) return {
      emoji: "✨",
      text: "Almost clean! A few tweaks recommended.",
    };
    return {
      emoji: "🛡️",
      text: "Looking secure! Great job maintained.",
    };
  };

  const msg = getMessage();

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
        <h3 className="text-base font-bold">Security Score: {animatedScore}/100</h3>
        <p className="font-mono text-[11px] text-muted-foreground mt-1">
          <span className="mr-1">{msg.emoji}</span>
          {msg.text}
        </p>
      </div>
    </div>
  );
};

export default ScoreRing;