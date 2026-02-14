import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

const siteUrl = process.env.NEXT_PUBLIC_SITE_URL || "http://localhost:3000";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title: "Stegosaurust - Secure Steganography Application",
  description: "Hide your secrets in plain sight. Encrypt messages with seed words and embed them securely into images using advanced steganography techniques.",
  keywords: ["steganography", "encryption", "AES-256", "security", "privacy", "hidden messages", "QR code"],
  authors: [{ name: "Appsjuragan" }],
  icons: {
    icon: "/logo.png",
  },
  openGraph: {
    title: "Stegosaurust",
    description: "Secure steganography application with AES-256 encryption",
    url: siteUrl,
    siteName: "Stegosaurust",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning className="dark">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
