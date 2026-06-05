import React from "react";
import type { Metadata } from "next";
import "../index.css";

export const metadata: Metadata = {
  title: "AudiCode - Your vibe code Auditor",
  description: "High-performance deterministic security scanner for GitHub repositories with semantic taint tracking.",
  icons: {
    icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke-width='2.5'><path d='M16 18l6-6-6-6M8 6l-6 6 6 6' stroke='%2300FF88' stroke-linecap='round' stroke-linejoin='round' /><path d='M12 2v20' stroke='%2300F0FF' stroke-linecap='round' /><circle cx='12' cy='12' r='3' fill='%2300FF88' /></svg>"
  }
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <div id="root">
          {children}
        </div>
      </body>
    </html>
  );
}
