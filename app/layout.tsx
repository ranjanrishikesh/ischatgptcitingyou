export const metadata = {
  title: "is ChatGPT citing you?",
  description:
    "Pipeline that forwards AI-crawler page-view traffic from your site to your analytics. Stores no traffic data.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
