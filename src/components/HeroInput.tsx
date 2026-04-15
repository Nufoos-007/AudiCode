import { useState } from "react";
import { useNavigate } from "react-router-dom";

const HeroInput = () => {
  const [repoUrl, setRepoUrl] = useState("");
  const navigate = useNavigate();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    // In production: POST to /api/audit
    navigate("/dashboard");
  };

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-[560px] animate-fade-up-3">
      <input
        type="text"
        value={repoUrl}
        onChange={(e) => setRepoUrl(e.target.value)}
        placeholder="github.com/username/your-repo"
        className="flex-1 bg-surface border border-border-bright border-r-0 rounded-l-lg px-4 py-3.5 font-mono text-sm text-foreground placeholder:text-text-dim outline-none focus:border-primary transition-colors"
      />
      <button
        type="submit"
        className="bg-primary text-primary-foreground border-none rounded-r-lg px-6 py-3.5 font-sans text-sm font-bold whitespace-nowrap hover:opacity-85 transition-opacity cursor-pointer"
      >
        Audit Now →
      </button>
    </form>
  );
};

export default HeroInput;
