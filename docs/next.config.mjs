import { createMDX } from 'fumadocs-mdx/next'

const withMDX = createMDX()

const isProd = process.env.NODE_ENV === 'production'
const repo = 'signet'

/** @type {import('next').NextConfig} */
const config = {
  output: 'export',
  reactStrictMode: true,
  trailingSlash: true,
  images: { unoptimized: true },
  basePath: isProd ? `/${repo}` : '',
  assetPrefix: isProd ? `https://nirapod-labs.github.io/${repo}/` : '',
}

export default withMDX(config)
