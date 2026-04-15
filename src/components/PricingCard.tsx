interface PricingCardProps {
  name: string;
  price: string;
  period: string;
  features: { text: string; included: boolean }[];
  buttonText: string;
  featured?: boolean;
  onAction?: () => void;
}

const PricingCard = ({ name, price, period, features, buttonText, featured, onAction }: PricingCardProps) => {
  return (
    <div
      className={`relative bg-surface border rounded-xl p-6 transition-all duration-200 hover:-translate-y-0.5 ${
        featured
          ? "border-primary/20 bg-gradient-to-br from-surface to-primary/[0.03]"
          : "border-border hover:border-border-bright"
      }`}
    >
      {featured && (
        <div className="absolute -top-px left-1/2 -translate-x-1/2 bg-primary text-primary-foreground font-mono text-[10px] font-semibold px-3 py-0.5 rounded-b-md tracking-wide">
          POPULAR
        </div>
      )}

      <div className="font-mono text-[11px] text-muted-foreground tracking-widest uppercase">{name}</div>

      <div className="text-4xl font-extrabold tracking-tight mt-2">
        {price === "Free" ? (
          <span className="text-primary">Free</span>
        ) : (
          <>
            <sup className="text-lg font-semibold align-super">$</sup>
            {price.replace("$", "")}
          </>
        )}
      </div>

      <div className="font-mono text-[11px] text-muted-foreground mt-1">{period}</div>

      <div className="h-px bg-border my-5" />

      <ul className="flex flex-col gap-2.5 list-none">
        {features.map((feat, i) => (
          <li key={i} className="flex items-center gap-2.5 font-mono text-xs text-muted-foreground">
            <span className={feat.included ? "text-primary text-sm" : "text-text-dim text-sm"}>
              {feat.included ? "✓" : "✗"}
            </span>
            {feat.text}
          </li>
        ))}
      </ul>

      <button
        onClick={onAction}
        className={`w-full mt-6 py-3 rounded-lg font-sans text-sm font-bold cursor-pointer transition-opacity hover:opacity-80 ${
          featured
            ? "bg-primary text-primary-foreground border-none"
            : "bg-transparent border border-border-bright text-foreground"
        }`}
      >
        {buttonText}
      </button>
    </div>
  );
};

export default PricingCard;
