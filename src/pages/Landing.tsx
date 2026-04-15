import HeroInput from "../components/HeroInput";

const Landing = () => {
  return (
    <section className="min-h-screen flex flex-col items-center justify-center px-6 md:px-10 pt-[120px] pb-20 relative text-center">
      {/* Grid background */}
      <div
        className="absolute inset-0 opacity-40 pointer-events-none"
        style={{
          backgroundImage:
            "linear-gradient(hsl(var(--border)) 1px, transparent 1px), linear-gradient(90deg, hsl(var(--border)) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
          maskImage: "radial-gradient(ellipse 80% 60% at 50% 50%, black 30%, transparent 100%)",
          WebkitMaskImage: "radial-gradient(ellipse 80% 60% at 50% 50%, black 30%, transparent 100%)",
        }}
      />

      {/* Glow */}
      <div className="absolute top-[30%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[300px] bg-[radial-gradient(ellipse,_hsl(var(--primary)/0.06)_0%,_transparent_70%)] pointer-events-none" />

      {/* Badge */}
      <div className="animate-fade-up relative z-10 inline-flex items-center gap-2 px-3.5 py-1.5 bg-primary/10 border border-primary/20 rounded-full font-mono text-[11px] text-primary mb-8">
        <div className="w-1.5 h-1.5 bg-primary rounded-full" style={{ animation: "pulse-dot 2s infinite" }} />
        AI-powered security analysis
      </div>

      {/* Heading */}
      <h1 className="animate-fade-up-1 relative z-10 text-5xl sm:text-7xl md:text-8xl lg:text-[96px] font-extrabold leading-[0.95] tracking-tighter">
        Your code.
        <br />
        <span className="text-primary">Exposed.</span>
        <br />
        <span className="text-muted-foreground">Then fixed.</span>
      </h1>

      {/* Subtitle */}
      <p className="animate-fade-up-2 relative z-10 mt-6 font-mono text-sm text-muted-foreground max-w-[480px] leading-relaxed">
        Paste a GitHub repo URL. Get a plain-English vulnerability report in seconds. No jargon. No false confidence.
      </p>

      {/* Input */}
      <div className="relative z-10 mt-12 w-full flex justify-center">
        <HeroInput />
      </div>

      {/* Stats */}
      <div className="animate-fade-up-4 relative z-10 mt-16 flex gap-12">
        <div className="text-left">
          <div className="text-[28px] font-extrabold tracking-tight">
            2<span className="text-primary">×</span>
          </div>
          <div className="font-mono text-[11px] text-muted-foreground mt-0.5">free audits</div>
        </div>
        <div className="text-left">
          <div className="text-[28px] font-extrabold tracking-tight">
            ~<span className="text-primary">30</span>s
          </div>
          <div className="font-mono text-[11px] text-muted-foreground mt-0.5">avg scan time</div>
        </div>
        <div className="text-left">
          <div className="text-[28px] font-extrabold tracking-tight">
            <span className="text-primary">∞</span>
          </div>
          <div className="font-mono text-[11px] text-muted-foreground mt-0.5">with your API key</div>
        </div>
      </div>
    </section>
  );
};

export default Landing;
