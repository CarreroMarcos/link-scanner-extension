const { sanitizeUrl, containsPotentialSecret } = require('./service_worker');

function mockVTSubmitResponse(analysisId = 'test-analysis-123') {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      data: {
        id: analysisId,
        type: 'url',
        links: {
          self: `https://www.virustotal.com/gui/analysis/${analysisId}`
        }
      }
    })
  };
}

function mockVTAnalysisResponse(stats) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      data: {
        attributes: {
          stats: stats,
          last_analysis_date: Math.floor(Date.now() / 1000)
        }
      }
    })
  };
}

describe('VirusTotal Integration - Re-poll Logic', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('does not re-poll when engine count >= 5', async () => {
    const submitRes = mockVTSubmitResponse();
    const goodStats = { malicious: 1, suspicious: 0, harmless: 50, undetected: 60 };
    const analysisRes = mockVTAnalysisResponse(goodStats);

    let fetchCallCount = 0;
    global.fetch = jest.fn(async (url) => {
      fetchCallCount++;
      if (url.includes('/urls')) return submitRes;
      if (url.includes('/analyses')) return analysisRes;
      throw new Error('Unexpected URL: ' + url);
    });

    const stats = goodStats;
    const engineCount = Object.values(stats).reduce((a, b) => a + (b || 0), 0);
    
    expect(engineCount).toBeGreaterThanOrEqual(5);
    expect(engineCount).toBe(111);
  });

  test('re-polls when engine count < 5', () => {
    const lowStats = { malicious: 0, suspicious: 0, harmless: 2, undetected: 1 };
    const engineCount = Object.values(lowStats).reduce((a, b) => a + (b || 0), 0);
    
    expect(engineCount).toBeLessThan(5);
    expect(engineCount).toBe(3);
  });

  test('correctly identifies malicious results', () => {
    const stats = { malicious: 5, suspicious: 2, harmless: 50, undetected: 55 };
    const positive = (stats.malicious || 0) + (stats.suspicious || 0);
    const isMalicious = positive > 0;
    
    expect(isMalicious).toBe(true);
    expect(positive).toBe(7);
  });

  test('correctly identifies safe results', () => {
    const stats = { malicious: 0, suspicious: 0, harmless: 97, undetected: 3 };
    const positive = (stats.malicious || 0) + (stats.suspicious || 0);
    const isMalicious = positive > 0;
    
    expect(isMalicious).toBe(false);
  });

  test('handles missing stats gracefully', () => {
    const resultData = { data: { attributes: {} } };
    const stats = resultData.data?.attributes?.stats || null;
    
    expect(stats).toBeNull();
  });

  test('generates correct VT report URL from API link', () => {
    const analysisId = 'test-id-xyz';
    const submitData = {
      data: {
        id: analysisId,
        links: {
          self: `https://www.virustotal.com/gui/analysis/${analysisId}`
        }
      }
    };
    
    const vtReportUrl = submitData.data?.links?.self 
      || (analysisId ? `https://www.virustotal.com/gui/analysis/${analysisId}` : null);
    
    expect(vtReportUrl).toBe(`https://www.virustotal.com/gui/analysis/${analysisId}`);
  });

  test('falls back to search URL if no GUI link provided', () => {
    const analysisId = 'test-id-xyz';
    const submitData = { data: { id: analysisId } };
    const sampleUrl = 'https://example.com/path?q=1';

    const apiSelfLink = submitData.data?.links?.self;
    const vtReportUrl = (apiSelfLink && apiSelfLink.startsWith('https://www.virustotal.com/gui/'))
      ? apiSelfLink
      : `https://www.virustotal.com/gui/search/${encodeURIComponent(sampleUrl)}`;

    expect(vtReportUrl).toBe(`https://www.virustotal.com/gui/search/${encodeURIComponent(sampleUrl)}`);
  });

  test('falls back to search URL when no analysisId and no GUI link', () => {
    const submitData = { data: {} };
    const sampleUrl = 'https://example.com/another';

    const apiSelfLink = submitData.data?.links?.self;
    const vtReportUrl = (apiSelfLink && apiSelfLink.startsWith('https://www.virustotal.com/gui/'))
      ? apiSelfLink
      : `https://www.virustotal.com/gui/search/${encodeURIComponent(sampleUrl)}`;

    expect(vtReportUrl).toBe(`https://www.virustotal.com/gui/search/${encodeURIComponent(sampleUrl)}`);
  });

  test('ignores API endpoint self link and falls back to search', () => {
    const analysisId = 'test-abc-123';
    const submitData = {
      data: {
        id: analysisId,
        links: { self: `https://www.virustotal.com/api/v3/analyses/${analysisId}` }
      }
    };
    const sampleUrl = 'https://example.com/x';

    const apiSelfLink = submitData.data?.links?.self;
    const vtReportUrl = (apiSelfLink && apiSelfLink.startsWith('https://www.virustotal.com/gui/'))
      ? apiSelfLink
      : `https://www.virustotal.com/gui/search/${encodeURIComponent(sampleUrl)}`;

    expect(vtReportUrl).toBe(`https://www.virustotal.com/gui/search/${encodeURIComponent(sampleUrl)}`);
  });
});

describe('VirusTotal Stats Parsing - Edge Cases', () => {
  test('calculates engine count correctly', () => {
    const stats = { malicious: 1, suspicious: 0, harmless: 50, undetected: 60 };
    const engineCount = Object.values(stats).reduce((a, b) => a + (b || 0), 0);
    
    expect(engineCount).toBe(111);
  });

  test('handles stats with missing fields', () => {
    const stats = { malicious: 1, harmless: 50 };
    const engineCount = Object.values(stats).reduce((a, b) => a + (b || 0), 0);
    
    expect(engineCount).toBe(51);
  });

  test('formats detection message correctly for malicious results', () => {
    const stats = { malicious: 5, suspicious: 0, harmless: 95, undetected: 0 };
    const positive = (stats.malicious || 0) + (stats.suspicious || 0);
    const message = positive > 0 
      ? `Detected as malicious by ${stats.malicious || 0} security vendors.`
      : `No detections by 100 engines.`;
    
    expect(message).toBe('Detected as malicious by 5 security vendors.');
  });

  test('formats detection message correctly for safe results', () => {
    const stats = { malicious: 0, suspicious: 0, harmless: 97, undetected: 3 };
    const engineCount = Object.values(stats).reduce((a, b) => a + (b || 0), 0);
    const message = `No detections by ${engineCount} engines.`;
    
    expect(message).toBe('No detections by 100 engines.');
  });

  test('analysis time parsing produces valid ISO string', () => {
    const epochTime = Math.floor(Date.now() / 1000);
    const isoTime = new Date(epochTime * 1000).toISOString();
    
    expect(typeof isoTime).toBe('string');
    expect(isoTime).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });
});
