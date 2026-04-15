import PricingCard from "../components/PricingCard";

const pricingPlans = [
  {
    name: "Free",
    price: "Free",
    period: "forever",
    features: [
      { text: "2 audits total", included: true },
      { text: "Public repos only", included: true },
      { text: "Plain-English report", included: true },
      { text: "AI fix", included: false },
      { text: "Private repos", included: false },
    ],
    buttonText: "Get Started",
    featured: false,
  },
  {
    name: "Starter",
    price: "$9",
    period: "20 credits · one-time",
    features: [
      { text: "20 audit credits", included: true },
      { text: "Public + private repos", included: true },
      { text: "Plain-English report", included: true },
      { text: "AI fix (costs 1 credit)", included: true },
      { text: "Priority scans", included: false },
    ],
    buttonText: "Buy Credits",
    featured: true,
  },
  {
    name: "BYOK",
    price: "Free",
    period: "bring your own Gemini key",
    features: [
      { text: "Unlimited audits", included: true },
      { text: "Public + private repos", included: true },
      { text: "Plain-English report", included: true },
      { text: "AI fix", included: true },
      { text: "You pay Gemini directly", included: true },
    ],
    buttonText: "Add API Key",
    featured: false,
  },
];

const Pricing = () => {
  return (
    <div className="min-h-screen pt-[100px] pb-20 px-6 md:px-10">
      <div className="max-w-[1100px] mx-auto">
        <div className="text-center mb-12">
          <h1 className="text-4xl md:text-5xl font-extrabold tracking-tighter">
            Simple, transparent <span className="text-primary">pricing</span>
          </h1>
          <p className="font-mono text-sm text-muted-foreground mt-4 max-w-md mx-auto">
            Start free. Scale when you need to.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {pricingPlans.map((plan) => (
            <PricingCard key={plan.name} {...plan} />
          ))}
        </div>
      </div>
    </div>
  );
};

export default Pricing;
