export const metadata = { title: "Trust & Security — is ChatGPT citing you?" };

export default function TrustPage() {
  return (
    <main style={{ fontFamily: "system-ui", maxWidth: 760, margin: "3rem auto", padding: "0 1rem", lineHeight: 1.5 }}>
      <h1>Trust &amp; Security</h1>
      <p>
        We are a pipeline. We forward your AI-crawler traffic to your own analytics and keep
        none of it. The few things we must hold are protected as described below.
      </p>

      <h2>We don&apos;t store your traffic</h2>
      <p>
        Page-view events are classified in memory, forwarded to your destination, and discarded.
        We never persist a path, user-agent, or referrer. The only data at rest is your account,
        your <em>encrypted</em> destination credential, and usage counters.
      </p>

      <h2>How your credentials are protected</h2>
      <ul>
        <li>Envelope encryption: a KMS root key wraps a per-tenant key, which encrypts each secret (AES-256-GCM), bound to your tenant so a ciphertext can&apos;t be reused across tenants.</li>
        <li>We prefer write-only destination keys — a stolen key can at most write junk, not read your analytics.</li>
        <li>Decryption happens just-in-time and the key material is wiped from memory after use.</li>
        <li>Deleting your organization is <strong>crypto-shredding</strong>: the per-tenant key is destroyed, making every stored ciphertext — including backups — permanently undecryptable.</li>
      </ul>

      <h2>Isolation</h2>
      <p>
        Every tenant table is protected by Postgres row-level security (forced), keyed on the
        authenticated org. A missing context returns zero rows — it fails closed. Hosted mode
        refuses to boot unless this and the key-management posture are verified.
      </p>

      <h2>Outbound safety</h2>
      <p>
        We only connect to destinations over HTTPS, validate and pin the resolved IP (rejecting
        internal/metadata ranges), and never follow redirects — so a misconfigured or hostile
        destination can&apos;t be used to reach internal systems.
      </p>

      <h2>Accountability</h2>
      <p>
        Sensitive actions are recorded in a tamper-evident, hash-chained audit log (identifiers
        and action types only — never secret values).
      </p>

      <p style={{ color: "#666", marginTop: "2rem" }}>
        Questions or a security report? Email security@ischatgptcitingyou.com.
      </p>
    </main>
  );
}
