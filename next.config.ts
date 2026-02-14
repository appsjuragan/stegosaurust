/** @type {import('next').NextConfig} */
/**
 * Stegosaurust - Built by Appsjuragan
 */
import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  output: "standalone",
  /* config options here */
  typescript: {
    ignoreBuildErrors: true,
  },
  reactStrictMode: false,
};

export default nextConfig;
