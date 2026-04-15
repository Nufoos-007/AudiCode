import { Link } from "react-router-dom";
import HeroInput from "../components/HeroInput";
import FeatureCard from "../components/FeatureCard";
import { Zap, MessageSquare, AlertTriangle, Wand2, Github, CreditCard } from "lucide-react";

const features = [
  { icon: Zap, title: "Instant Repo Audit", description: "Paste a GitHub URL and scan your entire project in seconds." },
  { icon: MessageSquare, title: "Human-Readable Insights", description: "Understand vulnerabilities without security jargon." },
  { icon: AlertTriangle, title: "Severity Scoring", description: "Know what matters first with clear priority levels." },
  { icon: Wand2, title: "AI Fix Suggestions", description: "Get safe, minimal code changes with explanations." },
  { icon: Github, title: "GitHub Integration", description: "Connect your repo and fix issues via pull requests." },
  { icon: CreditCard, title: "Flexible Usage", description: "Free audits, pay-as-you-go, or use your own API key." },
];

const Landing = () => {
  return (
    <>
      {/* Hero Section */}
      <section className="min-h-screen flex flex-col items-center justify-center px-6 md:px-10 pt-[120px] pb-20 relative text-center overflow-hidden">
        {/* Grid background */}
        <div
          className="absolute inset-0 opacity-40 pointer-events-none"
          style={{
            backgroundImage: "linear-gradient(hsl(var(--border))) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--border)) 1px, transparent 1px)",
            backgroundSize: "40px 40px",
            maskImage: "radial-gradient(ellipse 80% 60% at 50% 50%, black 30%, transparent 100%)",
            WebkitMaskImage: "radial-gradient(ellipse 80% 60% at 50% 50%, black 30%, transparent 100%)",
          }}
        />

        {/* Glow */}
        <div className="absolute top-[30%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-[radial-gradient(ellipse,_hsl(var(--primary)/0.06)_0%,_transparent_70%)] pointer-events-none" />

        {/* Badge */}
        <div className="relative z-10 inline-flex items-center gap-2 px-3.5 py-1.5 bg-primary/10 border border-primary/20 rounded-full font-mono text-[11px] text-primary mb-8">
          <div className="w-1.5 h-1.5 bg-primary rounded-full animate-pulse" />
          AI-powered security analysis
        </div>

        {/* Heading */}
        <h1 className="relative z-10 text-5xl sm:text-7xl md:text-8xl lg:text-[96px] font-extrabold leading-[0.95] tracking-tighter">
          Your code.
          <br />
          <span className="text-primary">Exposed.</span>
          <br />
          <span className="text-muted-foreground">Then fixed.</span>
        </h1>

        {/* Subtitle */}
        <p className="relative z-10 mt-6 font-mono text-sm text-muted-foreground max-w-[480px] leading-relaxed">
          Paste a GitHub repo URL. Get a plain-English vulnerability report in seconds. No jargon. No false confidence.
        </p>

        {/* Input */}
        <div className="relative z-10 mt-12 w-full flex justify-center">
          <HeroInput />
        </div>

        {/* Stats */}
        <div className="relative z-10 mt-16 flex gap-12">
          {[
            { value: "2×", label: "free audits", highlight: "2" },
            { value: "~30s", label: "avg scan time", highlight: "30" },
            { value: "∞", label: "with your API key", highlight: null },
          ].map((stat) => (
            <div key={stat.label} className="text-left">
              <div className="text-[28px] font-extrabold tracking-tight">
                {stat.highlight ? (
                  <>
                    <span className="text-primary">{stat.value.replace(stat.highlight, "")}</span>
                    <span className="text-primary">{stat.highlight}</span>
                  </>
                ) : (
                  <span className="text-primary">{stat.value}</span>
                )}
              </div>
              <div className="font-mono text-[11px] text-muted-foreground mt-0.5">{stat.label}</div>
            </div>
          ))}
        </div>
      </section>

      {/* Features Section */}
      <section id="features" className="py-20 px-6 md:px-10 border-t border-border">
        <div className="max-w-[1100px] mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl md:text-4xl font-extrabold tracking-tight">
              Security reviews that <span className="text-primary">actually make sense</span>
            </h2>
            <p className="font-mono text-sm text-muted-foreground mt-2">Not logs. Not noise. Just clear insights and fixes.</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {features.map((feature) => (
              <FeatureCard key={feature.title} {...feature} />
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 px-6 md:px-10 bg-card border-t border-border">
        <div className="max-w-[600px] mx-auto text-center">
          <p className="font-mono text-xs text-muted-foreground mb-4">Run your first audit in seconds</p>
          <Link
            to="/"
            className="inline-flex items-center gap-2 bg-primary text-primary-foreground px-6 py-3 rounded-lg font-semibold text-sm hover:opacity-85 transition-opacity"
          >
            Audit a Repo →
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 px-6 md:px-10 border-t border-border">
        <div className="max-w-[1100px] mx-auto flex flex-col md:flex-row items-center justify-between gap-4">
          <p className="font-mono text-xs text-muted-foreground">AudiCode © 2026</p>
          <div className="flex items-center gap-6">
            <Link to="/docs" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors">Docs</Link>
            <Link to="/features" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors">Features</Link>
          </div>
        </div>
      </footer>
    </>
  );
};

export default Landing;