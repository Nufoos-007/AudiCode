import { Link } from "react-router-dom";
import { Zap, MessageSquare, AlertTriangle, Wand2, Github, CreditCard } from "lucide-react";
import FeatureCard from "../components/FeatureCard";

const features = [
  { icon: Zap, title: "Instant Repo Audit", description: "Paste a GitHub URL and scan your entire project in seconds." },
  { icon: MessageSquare, title: "Human-Readable Insights", description: "Understand vulnerabilities without security jargon." },
  { icon: AlertTriangle, title: "Severity Scoring", description: "Know what matters first with clear priority levels." },
  { icon: Wand2, title: "AI Fix Suggestions", description: "Get safe, minimal code changes with explanations." },
  { icon: Github, title: "GitHub Integration", description: "Connect your repo and fix issues via pull requests." },
  { icon: CreditCard, title: "Flexible Usage", description: "Free audits, pay-as-you-go, or use your own API key." },
];

const Features = () => {
  return (
    <section className="min-h-screen pt-[100px] pb-20 px-6 md:px-10">
      <div className="max-w-[1100px] mx-auto">
        {/* Header */}
        <div className="text-center mb-16">
          <h1 className="text-4xl sm:text-5xl md:text-6xl font-extrabold tracking-tight mb-4">
            Security reviews that
            <br />
            <span className="text-primary">actually make sense</span>
          </h1>
          <p className="text-muted-foreground font-mono text-sm max-w-[420px] mx-auto">
            Not logs. Not noise. Just clear insights and fixes.
          </p>
        </div>

        {/* Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-20">
          {features.map((feature) => (
            <FeatureCard key={feature.title} {...feature} />
          ))}
        </div>

        {/* CTA */}
        <div className="text-center py-12 border-t border-border">
          <p className="font-mono text-xs text-muted-foreground mb-4">Run your first audit in seconds</p>
          <Link
            to="/"
            className="inline-flex items-center gap-2 bg-primary text-primary-foreground px-6 py-3 rounded-lg font-semibold text-sm hover:opacity-85 transition-opacity"
          >
            Audit a Repo →
          </Link>
        </div>
      </div>
    </section>
  );
};

export default Features;