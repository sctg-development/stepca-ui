/** @type {import('next').NextConfig} */
// Static export: the Go backend serves ./out itself (same origin, single image).
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: { unoptimized: true },
}

module.exports = nextConfig
