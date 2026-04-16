import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import { parseRepoUrl, fetchRepoInfo } from "../lib/github";
import { getCurrentUser, supabase } from "../lib/supabase";

const HeroInput = () => {
  const [repoUrl, setRepoUrl] = useState("");
  const [isFocused, setIsFocused] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState("");
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const checkAuth = async () => {
      const user = await getCurrentUser();
      setIsLoggedIn(!!user);
    };
    checkAuth();
    
    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setIsLoggedIn(!!session?.user);
    });
    
    return () => subscription.unsubscribe();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!repoUrl.trim()) return;
    
    if (!isLoggedIn) {
      navigate("/auth?redirect=" + encodeURIComponent("/dashboard?audit=" + encodeURIComponent(repoUrl)));
      return;
    }
    
    setIsLoading(true);
    setError("");

    try {
      const repo = parseRepoUrl(repoUrl);
      if (!repo) {
        setError("Invalid GitHub URL");
        setIsLoading(false);
        return;
      }

      const repoInfo = await fetchRepoInfo(repo);
      sessionStorage.setItem("auditRepo", JSON.stringify(repoInfo));
      navigate("/dashboard");
    } catch (err: any) {
      setError(err.message || "Failed to fetch repo");
      setIsLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div
        className="flex w-full"
        style={{
          boxShadow: isFocused ? "0 0 0 2px rgba(16, 185, 129, 0.3), 0 0 20px rgba(16, 185, 129, 0.1)" : "none"
        }}
      >
        <div className="relative flex-1">
          <input
            type="text"
            value={repoUrl}
            onChange={(e) => setRepoUrl(e.target.value)}
            onFocus={() => setIsFocused(true)}
            onBlur={() => setIsFocused(false)}
            placeholder="github.com/username/your-repo"
            className="w-full bg-surface border rounded-l-lg px-4 py-3.5 font-mono text-sm text-foreground placeholder:text-text-dim outline-none transition-colors"
            style={{ borderColor: isFocused ? "hsl(var(--primary))" : "hsl(var(--border))" }}
          />
        </div>
        <button
          type="submit"
          disabled={isLoading || !repoUrl.trim()}
          className="bg-primary text-primary-foreground border-none rounded-r-lg px-6 py-3.5 font-sans text-sm font-bold whitespace-nowrap hover:opacity-85 transition-opacity disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 active:scale-[0.98]"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            "Audit Now →"
          )}
        </button>
      </div>
      {error && (
        <p className="text-xs text-destructive mt-2 text-left">{error}</p>
      )}
    </form>
  );
};

export default HeroInput;