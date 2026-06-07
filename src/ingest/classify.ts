/**
 * User-agent classification — the reusable core ported and hardened from the
 * original vercel-log-drain. Decides whether a request is bot/AI page-view
 * traffic worth forwarding, and which AI vendor it is.
 *
 * Routing logic:
 *   1. drop non-GET (telemetry/API, not page loads)
 *   2. drop status 410 (gone-page noise)
 *   3. drop static assets + infra paths
 *   4. drop explicitly ignored bots (noisy/low-value)
 *   5. AI UA  -> KEEP, bucket "ai"   (forward to analytics as LLM pageview)
 *      known bot -> KEEP, bucket "other", client "bot"
 *      known browser (and not AI/bot) -> DROP
 *      UNKNOWN (not browser, not known bot) -> KEEP, client "unknown"
 *         (could be a brand-new AI crawler; keep on purpose)
 *
 * SECURITY: every regex here is a flat alternation of literal tokens — NO nested
 * quantifiers, NO backreferences — so matching is linear-time (ReDoS-safe).
 * Customer-supplied regex is NEVER accepted; this list is curated and fixed.
 */

// AI assistants + answer engines. High-signal — routed to the analytics dest.
const AI_TOKENS = [
  // OpenAI
  "GPTBot", "ChatGPT-User", "OAI-SearchBot", "ChatGPT-Agent",
  // Anthropic
  "ClaudeBot", "Claude-Web", "Claude-SearchBot", "Claude-User", "Claude-Code", "anthropic-ai",
  // Perplexity
  "PerplexityBot", "Perplexity-User",
  // Google AI surfaces (NOT base Googlebot — that's a traditional crawler)
  "Google-Extended", "Google-NotebookLM", "NotebookLM",
  "Gemini-Deep-Research", "GeminiiOS", "Google-CloudVertexBot", "CloudVertexBot",
  "Google-Agent", "GoogleAgent-Mariner", "Google-Firebase", "Google-Gemini-CLI",
  // Meta AI
  "Meta-ExternalAgent", "meta-externalagent", "meta-externalfetcher", "Meta-ExternalFetcher", "meta-webindexer",
  // Apple Intelligence
  "Applebot-Extended", "Applebot",
  // Amazon AI
  "amazon-kendra", "AmazonBuyForMe", "Amzn-SearchBot", "Amzn-User", "bedrockbot", "NovaAct",
  // Huawei
  "PanguBot",
  // Chinese AI
  "DeepSeekBot", "ChatGLM-Spider", "iaskspider", "iAskBot",
  // xAI / Grok
  "GrokBot", "xAI-Grok", "Grok-DeepSearch", "xAI-SearchBot",
  // Mistral
  "MistralAI-User",
  // AI search engines
  "DuckAssistBot", "Bravebot", "Kagibot", "kagi-fetcher",
  "PhindBot", "Andibot", "YouBot", "ExaBot", "TavilyBot",
  // Training-data / dataset crawlers feeding AI corpora
  "CCBot", "AI2Bot", "AI2Bot-Dolma", "AI2Bot-DeepResearchEval",
  "Webzio-Extended", "ImagesiftBot", "Timpibot",
  "cohere-ai", "cohere-training-data-crawler", "LAIONDownloader",
  "ClueWeb-Crawler",
  // RAG / agent / scrape stacks
  "FirecrawlAgent", "Crawl4AI", "Crawlspace", "ApifyBot", "ApifyWebsiteContentCrawler",
  "LinerBot", "Manus-User", "BuddyBot", "WRTNBot",
  // Misc AI tooling
  "Diffbot", "QuillBot",
  "Cloudflare-AutoRAG", "AzureAI-SearchBot", "KlaviyoAIBot", "SBIntuitionsBot",
  "Brightbot", "FriendlyCrawler", "VelenPublicWebCrawler", "ICC-Crawler",
  "ISSCyberRiskCrawler", "aiHitBot", "EchoboxBot",
  "AIWebIndex", "ArenaUnfurlBot", "Shap-User", "MatchboxBot", "AdaptaBot",
  "qodercli", "web-researcher-mcp", "fAImous", "Anthill",
];

const AI_RE = new RegExp(AI_TOKENS.join("|"), "i");

// Catch-all bot regex. AI tokens also match here — AI is checked FIRST.
const BOT_RE = new RegExp(
  [
    ...AI_TOKENS,
    // Non-AI bots
    "Googlebot", "Googlebot-Image", "GoogleOther",
    "FacebookBot", "facebookexternalhit",
    "bingbot", "Amazonbot",
    "Bytespider", "TikTokSpider",
    "DuckDuckBot",
    "YandexBot", "YandexAdditional", "YandexAdditionalBot", "Baiduspider",
    "omgili", "omgilibot",
    "SemrushBot-OCOB", "SemrushBot-SWA",
    "Twitterbot", "LinkedInBot", "Slackbot", "Discordbot", "TelegramBot", "WhatsApp",
    "Barkrowler", "SpiderLing", "HanaleiBot",
    "Sogou", "coccocbot-web", "Qwantbot",
    // Generic client tokens. Require a LEADING boundary on "bot" too (\bbot\b),
    // else device brands like "CUBOT"/"Abbot" inside a real browser UA match and
    // get kept/billed as bots. Explicit bots (Googlebot etc.) are listed above.
    "\\bbot\\b", "crawler", "spider", "scraper", "HeadlessChrome",
    "python-requests", "curl\\/", "wget\\/", "Bun\\/", "node-fetch", "Go-http-client", "Java\\/", "okhttp",
  ].join("|"),
  "i",
);

// Confirmed browsers. NB: "Mozilla/5.0" is meaningless (every browser AND most
// bots send it) — never add it here.
const BROWSER_RE =
  /(Chrome\/\d|CriOS\/\d|Firefox\/\d|FxiOS\/\d|Edg\/\d|Edge\/\d|OPR\/\d|Opera\/\d|SamsungBrowser\/\d|Safari\/\d|MicroMessenger|FBAV|FBAN|Instagram|Line\/|MiuiBrowser)/i;

// Noisy / low-value bots we drop entirely.
const IGNORE_BOTS_RE =
  /(PetalBot|Bytespider|Baiduspider|meta-externalagent|Meta-ExternalAgent|meta-webindexer|Amazonbot|vercel-cron|Prefetch Proxy|DotBot|LinkedInBot|Palo Alto Networks|paloaltonetworks|360Spider|MJ12bot|RatumCorpusScan|AdsBot-Google|SeznamBot|TikTokSpider|SaaSHub|facebookexternalhit|Facebot|Twitterbot|Slackbot-LinkExpanding|Bun\/|Dalvik|wp-admin\/install\.php|SemrushBot|LinkupBot|AhrefsSiteAudit|AhrefsBot|SiteAuditBot|HubSpot Crawler|HubSeedsBot|MixrankBot)/i;

// UA -> vendor label. First match wins. Order matters.
const LLM_MAP: ReadonlyArray<readonly [RegExp, string]> = [
  [/GPTBot|ChatGPT-User|OAI-SearchBot|ChatGPT-Agent/i, "ChatGPT"],
  [/ClaudeBot|Claude-Web|Claude-SearchBot|Claude-User|Claude-Code|anthropic-ai/i, "Claude"],
  [/PerplexityBot|Perplexity-User/i, "Perplexity"],
  [/Google-Extended|Google-NotebookLM|NotebookLM|Gemini-Deep-Research|GeminiiOS|Google-CloudVertexBot|CloudVertexBot|Google-Agent|GoogleAgent-Mariner|Google-Firebase|Google-Gemini-CLI/i, "Gemini"],
  [/Meta-ExternalAgent|meta-externalagent|meta-externalfetcher|Meta-ExternalFetcher|meta-webindexer/i, "Meta AI"],
  [/Applebot-Extended|Applebot/i, "Apple Intelligence"],
  [/amazon-kendra|AmazonBuyForMe|Amzn-SearchBot|Amzn-User|bedrockbot|NovaAct/i, "Amazon"],
  [/GrokBot|xAI-Grok|Grok-DeepSearch|xAI-SearchBot/i, "Grok"],
  [/DeepSeekBot/i, "DeepSeek"],
  [/MistralAI-User/i, "Mistral"],
];

const ASSET_RE = /\.(js|css|map|png|jpe?g|gif|svg|ico|woff2?|ttf|webp|avif|mp4|txt|xml|json)$/i;
const INFRA_PATH_RE = /^\/?(_next|ga|ph|api|watch|wp-admin|wp-login|wp-content|wp-includes)\//i;

export type Bucket = "ai" | "other";
export type ClientKind = "ai" | "bot" | "unknown";

export interface ClassifyInput {
  method: string;
  pathname: string; // path without query string
  statusCode: number | string;
  userAgent: string;
}

export type ClassifyResult =
  | { keep: false; reason: string }
  | { keep: true; bucket: Bucket; client: ClientKind; llm: string | null };

/** Resolve an AI UA to a vendor label, falling back to the matched token. */
export function vendorFor(ua: string): string {
  for (const [re, label] of LLM_MAP) if (re.test(ua)) return label;
  const m = ua.match(AI_RE);
  return m ? m[0] : "Unknown AI";
}

/** Classify a single normalized request. Pure; no I/O. */
export function classify(input: ClassifyInput): ClassifyResult {
  const { method, pathname, userAgent: ua } = input;
  if (!pathname) return { keep: false, reason: "no-path" };
  if (method !== "GET") return { keep: false, reason: "method" };
  if (Number(input.statusCode) === 410) return { keep: false, reason: "status-410" };
  if (INFRA_PATH_RE.test(pathname) || /wp-admin/i.test(pathname)) {
    return { keep: false, reason: "infra-path" };
  }
  if (ASSET_RE.test(pathname)) return { keep: false, reason: "asset" };
  if (!ua) return { keep: false, reason: "no-ua" };
  if (/^https?:\/\//i.test(ua)) return { keep: false, reason: "url-as-ua" };
  if (IGNORE_BOTS_RE.test(ua)) return { keep: false, reason: "ignored-bot" };

  const isAI = AI_RE.test(ua);
  if (isAI) return { keep: true, bucket: "ai", client: "ai", llm: vendorFor(ua) };

  const isBot = BOT_RE.test(ua);
  if (isBot) return { keep: true, bucket: "other", client: "bot", llm: null };

  if (BROWSER_RE.test(ua)) return { keep: false, reason: "browser" };

  // Not a browser, not a known bot — keep as unknown (possible new AI crawler).
  return { keep: true, bucket: "other", client: "unknown", llm: null };
}
