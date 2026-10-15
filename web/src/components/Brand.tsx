import { ShieldCheck } from "lucide-react";

type BrandProps = { compact?: boolean };

export function Brand({ compact = false }: BrandProps) {
  return (
    <span className={`brand-lockup${compact ? " brand-lockup--compact" : ""}`}>
      <span className="brand-mark" aria-hidden="true">
        <ShieldCheck size={20} strokeWidth={1.8} />
      </span>
      <span className="brand-wordmark">
        permission<span>guard</span>
      </span>
    </span>
  );
}
