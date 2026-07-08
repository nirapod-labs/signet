import Link from 'next/link'

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center px-4 py-24 text-center">
      <h1 className="mb-4 text-4xl font-bold tracking-tight sm:text-5xl">Signet</h1>
      <p className="mb-2 max-w-2xl text-lg text-fd-muted-foreground">
        Hardware-backed P-256 signing keys for Flutter, React Native, and Kotlin Multiplatform, over
        the Apple Secure Enclave and Android Keystore, with a normalized security-tier report and
        attestation.
      </p>
      <p className="mb-8 max-w-2xl text-sm text-fd-muted-foreground">
        The private key is generated in hardware and never leaves it. Signet reports the tier it
        actually achieved; it never assumes one.
      </p>
      <div className="flex flex-wrap items-center justify-center gap-3">
        <Link
          href="/docs"
          className="rounded-lg bg-fd-primary px-5 py-2.5 text-sm font-medium text-fd-primary-foreground"
        >
          Read the docs
        </Link>
        <a
          href="https://github.com/nirapod-labs/signet"
          className="rounded-lg border px-5 py-2.5 text-sm font-medium"
        >
          GitHub
        </a>
      </div>
      <p className="mt-10 text-xs text-fd-muted-foreground">
        Pre-1.0 and in active development. Not yet published to any registry.
      </p>
    </main>
  )
}
