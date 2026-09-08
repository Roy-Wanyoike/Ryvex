import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Ryvex Console",
  description:
    "Ryvex — the programmable operating system for infrastructure. Control surface for the Ryvex cloud control plane.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
