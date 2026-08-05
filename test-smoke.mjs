// Test de fumée Nodock — valide les appels API et la logique de détection
(async () => {
  // Test 1 : API OSV avec lodash 4.17.20 (vulnérable connu)
  const res = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ queries: [{ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' }] })
  });
  const data = await res.json();
  const vulns = data.results[0].vulns || [];
  console.log('OSV    : ' + vulns.length + ' vulnérabilité(s) pour lodash@4.17.20');
  if (vulns[0]) console.log('         ex: ' + (vulns[0].aliases?.find(a => a.startsWith('CVE')) || vulns[0].id) + ' — ' + (vulns[0].summary || '').slice(0, 70));

  // Test 2 : API NVD
  const nvd = await fetch('https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=3&noRejected', { headers: { 'User-Agent': 'nodock-vscode' } });
  const nvdData = await nvd.json();
  console.log('NVD    : ' + nvdData.vulnerabilities.length + ' CVE récupérées, ex: ' + nvdData.vulnerabilities[0].cve.id);

  // Test 3 : détection de secrets
  const fake = 'const key = "AKIAIOSFODNN7EXAMPLE";';
  console.log('Secrets: ' + (/AKIA[0-9A-Z]{16}/.test(fake) ? 'clé AWS détectée OK' : 'ÉCHEC'));

  // Test 4 : flux RSS
  const rss = await fetch('https://feeds.feedburner.com/TheHackersNews', { headers: { 'User-Agent': 'nodock-vscode' } });
  const xml = await rss.text();
  const items = xml.match(/<item[\s\S]*?<\/item>/g) || [];
  console.log('RSS    : ' + items.length + ' articles The Hacker News');
})().catch(e => { console.error('ERREUR:', e.message); process.exit(1); });
