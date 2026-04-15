import { Link, useLocation } from "react-router-dom";

const Navbar = () => {
  const location = useLocation();
  const isDashboard = location.pathname === "/dashboard";

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 h-[60px] flex items-center justify-between px-6 md:px-10 bg-background/80 backdrop-blur-xl border-b border-border">
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

      <ul className="hidden md:flex items-center gap-8 list-none">
        {!isDashboard && (
          <>
            <li>
              <Link to="/pricing" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors tracking-wide">
                Pricing
              </Link>
            </li>
            <li>
              <a href="#features" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors tracking-wide">
                Features
              </a>
            </li>
            <li>
              <a href="#" className="font-mono text-xs text-muted-foreground hover:text-foreground transition-colors tracking-wide">
                Docs
              </a>
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
      </ul>
    </nav>
  );
};

export default Navbar;
