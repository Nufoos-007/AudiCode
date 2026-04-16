import { useState, useEffect } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Menu, X, Github, Loader2 } from "lucide-react";
import { supabase, getCurrentUser } from "../lib/supabase";

const Navbar = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const isDashboard = location.pathname === "/dashboard";
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const checkAuth = async () => {
      const currentUser = await getCurrentUser();
      setUser(currentUser);
      setLoading(false);
    };
    checkAuth();

    const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user || null);
    });

    return () => subscription.unsubscribe();
  }, []);

  const handleSignOut = async () => {
    await supabase.auth.signOut();
    sessionStorage.removeItem("auditRepo");
    sessionStorage.removeItem("github_repos");
    navigate("/");
  };

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 h-[60px] flex items-center justify-between px-4 md:px-10 bg-background/80 backdrop-blur-xl border-b border-border">
      <Link to="/" className="flex items-center gap-2">
        <div className="w-7 h-7 bg-primary rounded-md flex items-center justify-center">
          <svg viewBox="0 0 16 16" fill="none" className="w-4 h-4">
            <path d="M8 2L14 5V11L8 14L2 11V5L8 2Z" stroke="hsl(var(--primary-foreground))" strokeWidth="1.5" strokeLinejoin="round" />
            <path d="M8 6V10M6 8H10" stroke="hsl(var(--primary-foreground))" strokeWidth="1.5" strokeLinecap="round" />
          </svg>
        </div>
        <span className="text-lg font-extrabold tracking-tight">
          Audi<span className="text-primary">Code</span>
        </span>
      </Link>

      {/* Desktop Menu */}
      <ul className="hidden md:flex items-center gap-8 list-none">
        {/* Always show nav links if logged in, or if not on dashboard */}
        {user ? (
          <>
            <li>
              <Link to="/pricing" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors tracking-wide">
                Pricing
              </Link>
            </li>
            <li>
              <Link to="/features" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors tracking-wide">
                Features
              </Link>
            </li>
            <li>
              <Link to="/docs" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors tracking-wide">
                Docs
              </Link>
            </li>
            <li>
              <button
                onClick={handleSignOut}
                className="font-mono text-xs font-semibold bg-primary text-primary-foreground px-4 py-2 rounded-md hover:opacity-85 transition-opacity"
              >
                Sign Out
              </button>
            </li>
          </>
        ) : (
          <>
            {!isDashboard && (
              <>
                <li>
                  <Link to="/pricing" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors tracking-wide">
                    Pricing
                  </Link>
                </li>
                <li>
                  <Link to="/features" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors tracking-wide">
                    Features
                  </Link>
                </li>
                <li>
                  <Link to="/docs" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors tracking-wide">
                    Docs
                  </Link>
                </li>
              </>
            )}
            <li>
              <Link
                to="/auth"
                className="font-mono text-xs font-semibold bg-primary text-primary-foreground px-4 py-2 rounded-md hover:opacity-85 transition-opacity"
              >
                Get Started
              </Link>
            </li>
          </>
        )}
      </ul>

      {/* Mobile Menu Button */}
      <button 
        className="md:hidden p-2"
        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
      >
        {mobileMenuOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
      </button>

      {/* Mobile Menu Dropdown */}
      {mobileMenuOpen && !loading && (
        <div className="absolute top-[60px] left-0 right-0 bg-background border-b border-border p-4 md:hidden">
          <ul className="flex flex-col gap-4 list-none">
            {user ? (
              <>
                <li>
                  <Link 
                    to="/pricing" 
                    className="block font-mono text-sm text-muted-foreground hover:text-foreground"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    Pricing
                  </Link>
                </li>
                <li>
                  <Link 
                    to="/features" 
                    className="block font-mono text-sm text-muted-foreground hover:text-foreground"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    Features
                  </Link>
                </li>
                <li>
                  <Link 
                    to="/docs" 
                    className="block font-mono text-sm text-muted-foreground hover:text-foreground"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    Docs
                  </Link>
                </li>
                <li>
                  <button
                    onClick={() => { handleSignOut(); setMobileMenuOpen(false); }}
                    className="block w-full text-left font-mono text-sm font-semibold bg-primary text-primary-foreground px-4 py-2 rounded-md text-center"
                  >
                    Sign Out
                  </button>
                </li>
              </>
            ) : (
              <>
                {!isDashboard && (
                  <>
                    <li>
                      <Link 
                        to="/pricing" 
                        className="block font-mono text-sm text-muted-foreground hover:text-foreground"
                        onClick={() => setMobileMenuOpen(false)}
                      >
                        Pricing
                      </Link>
                    </li>
                    <li>
                      <Link 
                        to="/features" 
                        className="block font-mono text-sm text-muted-foreground hover:text-foreground"
                        onClick={() => setMobileMenuOpen(false)}
                      >
                        Features
                      </Link>
                    </li>
                    <li>
                      <Link 
                        to="/docs" 
                        className="block font-mono text-sm text-muted-foreground hover:text-foreground"
                        onClick={() => setMobileMenuOpen(false)}
                      >
                        Docs
                      </Link>
                    </li>
                  </>
                )}
                <li>
                  <Link
                    to="/auth"
                    className="block font-mono text-sm font-semibold bg-primary text-primary-foreground px-4 py-2 rounded-md text-center"
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    Get Started
                  </Link>
                </li>
              </>
            )}
          </ul>
        </div>
      )}
    </nav>
  );
};

export default Navbar;