import type { ProtectedApp } from "../types";

export function AppIcon({ app, size = "regular" }: { app: ProtectedApp; size?: "regular" | "large" }) {
  return (
    <span
      className={`app-icon app-icon--${app.tint} app-icon--${size}`}
      aria-hidden="true"
    >
      {app.initials}
    </span>
  );
}
