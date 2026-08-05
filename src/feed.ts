import { NewsItem } from './types';

const NVD_WINDOW_DAYS = 7;

function nvdUrl(): string {
  const end = new Date();
  const start = new Date(end.getTime() - NVD_WINDOW_DAYS * 24 * 3600 * 1000);
  const fmt = (d: Date) => d.toISOString().slice(0, 19) + '.000';
  return (
    'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=15&noRejected' +
    `&pubStartDate=${fmt(start)}&pubEndDate=${fmt(end)}`
  );
}

/** Récupère les CVE les plus récentes depuis l'API NVD (gratuite, sans clé). */
async function fetchNvd(): Promise<NewsItem[]> {
  const res = await fetch(nvdUrl(), { headers: { 'User-Agent': 'nodock-vscode' } });
  if (!res.ok) throw new Error(`NVD a répondu ${res.status}`);
  const data = (await res.json()) as {
    vulnerabilities: Array<{
      cve: {
        id: string;
        published: string;
        descriptions: Array<{ lang: string; value: string }>;
      };
    }>;
  };
  return data.vulnerabilities.map((v) => {
    const desc =
      v.cve.descriptions.find((d) => d.lang === 'fr')?.value ??
      v.cve.descriptions.find((d) => d.lang === 'en')?.value ??
      '';
    return {
      title: v.cve.id,
      url: `https://nvd.nist.gov/vuln/detail/${v.cve.id}`,
      source: 'NVD',
      date: v.cve.published.slice(0, 10),
      summary: desc.slice(0, 300),
    };
  });
}

/** Parse minimaliste d'un flux RSS/Atom sans dépendance. */
function parseRss(xml: string, source: string): NewsItem[] {
  const items: NewsItem[] = [];
  const entries = xml.match(/<item[\s\S]*?<\/item>/g) ?? xml.match(/<entry[\s\S]*?<\/entry>/g) ?? [];
  const clean = (s: string) =>
    s.replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1').replace(/<[^>]+>/g, '').trim();

  for (const entry of entries.slice(0, 15)) {
    const title = clean(entry.match(/<title[^>]*>([\s\S]*?)<\/title>/)?.[1] ?? '');
    const link =
      entry.match(/<link[^>]*href="([^"]+)"/)?.[1] ??
      clean(entry.match(/<link[^>]*>([\s\S]*?)<\/link>/)?.[1] ?? '');
    const date = clean(
      entry.match(/<pubDate[^>]*>([\s\S]*?)<\/pubDate>/)?.[1] ??
        entry.match(/<updated[^>]*>([\s\S]*?)<\/updated>/)?.[1] ??
        entry.match(/<published[^>]*>([\s\S]*?)<\/published>/)?.[1] ??
        ''
    );
    const summary = clean(
      entry.match(/<description[^>]*>([\s\S]*?)<\/description>/)?.[1] ??
        entry.match(/<summary[^>]*>([\s\S]*?)<\/summary>/)?.[1] ??
        ''
    ).slice(0, 300);
    if (title && link) {
      items.push({
        title,
        url: link,
        source,
        date: date ? new Date(date).toISOString().slice(0, 10) : '',
        summary,
      });
    }
  }
  return items;
}

async function fetchRss(url: string): Promise<NewsItem[]> {
  const res = await fetch(url, { headers: { 'User-Agent': 'nodock-vscode' } });
  if (!res.ok) throw new Error(`RSS ${res.status}`);
  const xml = await res.text();
  const host = new URL(url).hostname.replace('feeds.feedburner.com', 'The Hacker News');
  return parseRss(xml, host);
}

/** Agrège NVD + tous les flux RSS configurés. */
export async function fetchNews(feeds: string[]): Promise<{ items: NewsItem[]; errors: string[] }> {
  const errors: string[] = [];
  const results = await Promise.allSettled([
    fetchNvd(),
    ...feeds.map((f) => fetchRss(f)),
  ]);

  const items: NewsItem[] = [];
  for (const r of results) {
    if (r.status === 'fulfilled') {
      items.push(...r.value);
    } else {
      errors.push(String(r.reason?.message ?? r.reason));
    }
  }
  items.sort((a, b) => b.date.localeCompare(a.date));
  return { items, errors };
}
