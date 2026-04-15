import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { 
  BookOpen, 
  Search, 
  FileCheck, 
  Wand2, 
  Github, 
  CreditCard, 
  AlertTriangle,
  HelpCircle,
  ChevronRight,
  ExternalLink,
  Info,
  AlertOctagon
} from "lucide-react";

const sections = [
  { id: "getting-started", label: "Getting Started", icon: BookOpen },
  { id: "how-audits-work", label: "How Audits Work", icon: Search },
  { id: "understanding-results", label: "Understanding Results", icon: FileCheck },
  { id: "fixing-issues", label: "Fixing Issues", icon: Wand2 },
  { id: "github-integration", label: "GitHub Integration", icon: Github },
  { id: "credits-billing", label: "Credits & Billing", icon: CreditCard },
  { id: "limitations", label: "Limitations", icon: AlertTriangle },
  { id: "faq", label: "FAQ", icon: HelpCircle },
];

const Docs = () => {
  const location = useLocation();
  const [activeSection, setActiveSection] = useState("getting-started");

  useEffect(() => {
    const handleScroll = () => {
      const scrollPosition = window.scrollY + 100;
      for (const section of sections) {
        const element = document.getElementById(section.id);
        if (element) {
          const offsetTop = element.offsetTop;
          const offsetBottom = offsetTop + element.offsetHeight;
          if (scrollPosition >= offsetTop && scrollPosition < offsetBottom) {
            setActiveSection(section.id);
            break;
          }
        }
      }
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, []);

  const scrollToSection = (id: string) => {
    const element = document.getElementById(id);
    if (element) {
      window.scrollTo({ top: element.offsetTop - 80, behavior: "smooth" });
    }
  };

  return (
    <div className="min-h-screen pt-[60px] flex">
      {/* Sidebar */}
      <aside className="fixed left-0 top-[60px] w-[260px] h-[calc(100vh-60px)] overflow-y-auto border-r border-border bg-background p-4 hidden lg:block">
        <nav className="space-y-1">
          {sections.map((section) => (
            <button
              key={section.id}
              onClick={() => scrollToSection(section.id)}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-mono text-left transition-colors ${
                activeSection === section.id
                  ? "bg-primary/10 text-primary border border-primary/20"
                  : "text-muted-foreground hover:text-foreground hover:bg-muted"
              }`}
            >
              <section.icon className="w-4 h-4" />
              {section.label}
            </button>
          ))}
        </nav>
      </aside>

      {/* Mobile nav */}
      <div className="lg:hidden fixed bottom-0 left-0 right-0 z-50 bg-background border-t border-border p-2 overflow-x-auto">
        <div className="flex gap-2 px-2">
          {sections.map((section) => (
            <button
              key={section.id}
              onClick={() => scrollToSection(section.id)}
              className={`flex-shrink-0 px-3 py-2 rounded-lg text-xs font-mono ${
                activeSection === section.id
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted text-muted-foreground"
              }`}
            >
              {section.label}
            </button>
          ))}
        </div>
      </div>

      {/* Content */}
      <main className="flex-1 lg:ml-[260px] p-6 md:p-10 pb-32 lg:pb-20">
        <div className="max-w-[720px]">
          {/* Getting Started */}
          <section id="getting-started" className="mb-16 scroll-mt-24">
            <h2 className="text-2xl font-bold mb-4">Getting Started</h2>
            <div className="space-y-6 text-sm text-muted-foreground">
              <div>
                <h3 className="text-foreground font-semibold mb-2">What is AudiCode</h3>
                <p>AudiCode is an AI-powered code security auditor that analyzes GitHub repositories for vulnerabilities, bugs, and insecure coding patterns. It translates technical findings into plain English with actionable fixes.</p>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">How to run your first audit</h3>
                <ol className="list-decimal list-inside space-y-2">
                  <li>Paste a GitHub repository URL in the input field</li>
                  <li>Click "Audit Now" to start scanning</li>
                  <li>Wait for the scan to complete (~30 seconds)</li>
                  <li>Review the security report</li>
                </ol>
              </div>
              <div className="flex items-start gap-3 p-4 bg-primary/5 border border-primary/20 rounded-lg">
                <Info className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                <p className="text-xs">New users get 2 free audits. After that, you can purchase credits or bring your own API key.</p>
              </div>
            </div>
          </section>

          {/* How Audits Work */}
          <section id="how-audits-work" className="mb-16 scroll-mt-24">
            <h2 className="text-2xl font-bold mb-4">How Audits Work</h2>
            <div className="space-y-4 text-sm text-muted-foreground">
              <p>AudiCode uses a multi-stage pipeline to analyze your code:</p>
              <div className="space-y-3">
                <div className="flex gap-3">
                  <div className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs font-bold flex-shrink-0">1</div>
                  <div>
                    <h4 className="text-foreground font-semibold">Repository Cloning</h4>
                    <p>We clone your repository securely using git. Only public repos are scanned in the free tier.</p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <div className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs font-bold flex-shrink-0">2</div>
                  <div>
                    <h4 className="text-foreground font-semibold">Static Analysis</h4>
                    <p>We run Semgrep and Bandit to detect common vulnerabilities and insecure patterns.</p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <div className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs font-bold flex-shrink-0">3</div>
                  <div>
                    <h4 className="text-foreground font-semibold">AI Explanation</h4>
                    <p>Our AI processes findings and generates human-readable explanations with severity levels.</p>
                  </div>
                </div>
                <div className="flex gap-3">
                  <div className="w-6 h-6 rounded-full bg-primary/20 text-primary flex items-center justify-center text-xs font-bold flex-shrink-0">4</div>
                  <div>
                    <h4 className="text-foreground font-semibold">Result Generation</h4>
                    <p>You receive a detailed report with file paths, code snippets, and fix suggestions.</p>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* Understanding Results */}
          <section id="understanding-results" className="mb-16 scroll-mt-24">
            <h2 className="text-2xl font-bold mb-4">Understanding Results</h2>
            <div className="space-y-4 text-sm text-muted-foreground">
              <div>
                <h3 className="text-foreground font-semibold mb-2">Severity Levels</h3>
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-red-500/20 text-red-400 text-xs rounded">Critical</span>
                    <span>Immediate security risk — fix now</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 text-xs rounded">High</span>
                    <span>Significant risk — fix soon</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-yellow-500/20 text-yellow-400 text-xs rounded">Medium</span>
                    <span>Moderate risk — plan to fix</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">Low</span>
                    <span>Minor issue — consider fixing</span>
                  </div>
                </div>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">Security Score</h3>
                <p>Your repository receives a score from 0-100 based on the number and severity of vulnerabilities found. Higher is better.</p>
              </div>
              <div className="flex items-start gap-3 p-4 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
                <AlertOctagon className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                <p className="text-xs">False positives are possible. Always review before applying fixes. AI suggestions should be validated by a human.</p>
              </div>
            </div>
          </section>

          {/* Fixing Issues */}
          <section id="fixing-issues" className="mb-16 scroll-mt-24">
            <h2 className="text-2xl font-bold mb-4">Fixing Issues</h2>
            <div className="space-y-4 text-sm text-muted-foreground">
              <div>
                <h3 className="text-foreground font-semibold mb-2">How AI Suggestions Work</h3>
                <p>For each vulnerability, we provide a suggested code fix. The AI analyzes the context and generates a minimal, safe change.</p>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">When to Trust vs Review</h3>
                <ul className="list-disc list-inside space-y-1">
                  <li>✅ Safe: Simple patterns (e.g., adding input validation)</li>
                  <li>⚠️ Review: Complex logic changes</li>
                  <li>⚠️ Review: Authentication/authorization fixes</li>
                </ul>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">Pull Request Workflow</h3>
                <p>Connect your GitHub account to create pull requests directly from the dashboard.</p>
              </div>
            </div>
          </section>

          {/* GitHub Integration */}
          <section id="github-integration" className="mb-16 scroll-mt-24">
            <h2 className="text-2xl font-bold mb-4">GitHub Integration</h2>
            <div className="space-y-4 text-sm text-muted-foreground">
              <div>
                <h3 className="text-foreground font-semibold mb-2">Why Permissions Are Needed</h3>
                <p>GitHub OAuth is required to:</p>
                <ul className="list-disc list-inside space-y-1 mt-2">
                  <li>Read repository contents for scanning</li>
                  <li>Create pull requests for fixes</li>
                  <li>Check repository access permissions</li>
                </ul>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">What Access Is Used</h3>
                <p>We only request read access to repositories you authorize. We never write code without your explicit action (creating a PR).</p>
              </div>
              <div className="flex items-start gap-3 p-4 bg-primary/5 border border-primary/20 rounded-lg">
                <Info className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                <p className="text-xs">Your code is processed temporarily for analysis and is not stored on our servers.</p>
              </div>
            </div>
          </section>

          {/* Credits & Billing */}
          <section id="credits-billing" className="mb-16 scroll-mt-24">
            <h2 className="text-2xl font-bold mb-4">Credits & Billing</h2>
            <div className="space-y-4 text-sm text-muted-foreground">
              <div>
                <h3 className="text-foreground font-semibold mb-2">What Is a Credit</h3>
                <p>One credit = one complete repository audit. Credits are consumed regardless of the number of vulnerabilities found.</p>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">What Consumes Credits</h3>
                <ul className="list-disc list-inside space-y-1">
                  <li>Running an audit (1 credit)</li>
                  <li>Generating fix suggestions (1 credit)</li>
                  <li>Creating a pull request (free)</li>
                </ul>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">BYOK (Bring Your Own Key)</h3>
                <p>Skip credits entirely by providing your own OpenAI or Anthropic API key. Pay directly to the AI provider with no middleman markup.</p>
              </div>
              <div className="flex items-start gap-3 p-4 bg-primary/5 border border-primary/20 rounded-lg">
                <Info className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                <p className="text-xs">Your API key is stored encrypted and never shared. We only use it to call the AI on your behalf.</p>
              </div>
            </div>
          </section>

          {/* Limitations */}
          <section id="limitations" className="mb-16 scroll-mt-24">
            <h2 className="text-2xl font-bold mb-4">Limitations</h2>
            <div className="space-y-4 text-sm text-muted-foreground">
              <div className="flex items-start gap-3 p-4 bg-yellow-500/5 border border-yellow-500/20 rounded-lg">
                <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                <div>
                  <h4 className="text-foreground font-semibold mb-1">AI Is Not Perfect</h4>
                  <p className="text-xs">AI can miss vulnerabilities or suggest incorrect fixes. Always review before applying changes to production code.</p>
                </div>
              </div>
              <ul className="space-y-2">
                <li>• May miss context-specific vulnerabilities</li>
                <li>• Occasionally suggests breaking changes</li>
                <li>• Cannot detect business logic flaws</li>
                <li>• Limited to static analysis only</li>
              </ul>
            </div>
          </section>

          {/* FAQ */}
          <section id="faq" className="mb-16 scroll-mt-24">
            <h2 className="text-2xl font-bold mb-4">FAQ</h2>
            <div className="space-y-4 text-sm text-muted-foreground">
              <div>
                <h3 className="text-foreground font-semibold mb-2">Does it support private repos?</h3>
                <p>Not yet. Private repository support is planned for a future release.</p>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">Is my code stored?</h3>
                <p>No. Your code is processed temporarily for analysis and deleted immediately after. We do not store your code.</p>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">Why false positives?</h3>
                <p>Static analysis tools are conservative — they flag anything that could potentially be a risk. Our AI filters some, but not all, false positives.</p>
              </div>
              <div>
                <h3 className="text-foreground font-semibold mb-2">Is it safe?</h3>
                <p>Yes. We use sandboxed environments for analysis. Your API keys are encrypted. We never execute arbitrary code from the repository.</p>
              </div>
            </div>
          </section>
        </div>
      </main>
    </div>
  );
};

export default Docs;