function renderDetectionSummary(result) {
  const stats = result.stats || {};
  const engineCount = result.engine_count || 0;
  const positive = (stats.malicious || 0) + (stats.suspicious || 0);

  if (engineCount === 0) {
    return 'No engines scanned yet';
  } else if (positive > 0) {
    return `${positive} detections — ${engineCount} engines scanned`;
  } else {
    return `No detections — ${engineCount} engines scanned`;
  }
}

function renderCautionText(result) {
  const engineCount = result.engine_count || 0;
  const stats = result.stats || {};
  const positive = (stats.malicious || 0) + (stats.suspicious || 0);

  if (engineCount === 0) {
    return 'UNVERIFIABLE — no engines have scanned this resource yet.';
  } else if (positive === 0 && engineCount < 10) {
    return 'No detections, but only a small number of engines scanned — results may be incomplete.';
  } else if (positive === 0) {
    return 'No vendors flagged this resource — not guaranteed safe.';
  } else {
    return '';
  }
}

function renderAnalysisTime(result) {
  if (!result.analysis_time) return '';
  try {
    const dt = new Date(result.analysis_time);
    if (isNaN(dt.getTime())) return '';
    return `Last analysis: ${dt.toLocaleString()}`;
  } catch {
    return '';
  }
}

function shouldDisplayVTLink(result) {
  return !!(result.vt_report_url && result.vt_report_url.length > 0);
}

function shouldOverrideStatusWithUnverifiable(result) {
  const engineCount = result.engine_count || 0;
  const isScanning = result.status && result.status.toUpperCase() === 'SCANNING';
  return engineCount === 0 && !isScanning;
}

function shouldHideDuplicateScannedUrl(scanned, cleaned) {
  return !!(cleaned && scanned && cleaned === scanned);
}

describe('Popup UI Logic - Detection Summary Display', () => {
  test('renders safe detection summary with 100 engines', () => {
    const result = {
      status: 'SAFE',
      stats: { malicious: 0, suspicious: 0, harmless: 97, undetected: 3 },
      engine_count: 100
    };

    expect(renderDetectionSummary(result)).toBe('No detections — 100 engines scanned');
  });

  test('renders malicious detection summary with multiple vendors', () => {
    const result = {
      status: 'MALICIOUS',
      stats: { malicious: 5, suspicious: 2, harmless: 50, undetected: 43 },
      engine_count: 100
    };

    expect(renderDetectionSummary(result)).toBe('7 detections — 100 engines scanned');
  });

  test('renders detection count including both malicious and suspicious', () => {
    const result = {
      status: 'SUSPICIOUS',
      stats: { malicious: 1, suspicious: 3, harmless: 50, undetected: 46 },
      engine_count: 100
    };

    expect(renderDetectionSummary(result)).toBe('4 detections — 100 engines scanned');
  });

  test('renders unverifiable summary when zero engines scanned', () => {
    const result = {
      status: 'SAFE',
      stats: {},
      engine_count: 0
    };

    expect(renderDetectionSummary(result)).toBe('No engines scanned yet');
  });

  test('renders summary with missing stats object', () => {
    const result = {
      status: 'SAFE',
      engine_count: 50
    };

    expect(renderDetectionSummary(result)).toBe('No detections — 50 engines scanned');
  });

  test('renders summary with partial stats (missing keys)', () => {
    const result = {
      status: 'SAFE',
      stats: { harmless: 50, undetected: 1 },
      engine_count: 51
    };

    expect(renderDetectionSummary(result)).toBe('No detections — 51 engines scanned');
  });
});

describe('Popup UI Logic - Caution Text Display', () => {
  test('shows UNVERIFIABLE caution when zero engines scanned', () => {
    const result = { engine_count: 0, stats: {} };
    expect(renderCautionText(result)).toBe('UNVERIFIABLE — no engines have scanned this resource yet.');
  });

  test('shows incomplete caution for small engine count with safe results', () => {
    const result = {
      engine_count: 5,
      stats: { malicious: 0, suspicious: 0, harmless: 4, undetected: 1 }
    };

    const caution = renderCautionText(result);
    expect(caution).toContain('small number of engines');
    expect(caution).toContain('results may be incomplete');
  });

  test('shows incomplete caution at boundary (9 engines)', () => {
    const result = {
      engine_count: 9,
      stats: { malicious: 0, suspicious: 0, harmless: 8, undetected: 1 }
    };

    expect(renderCautionText(result)).toContain('small number of engines');
  });

  test('shows general caution at boundary (10 engines)', () => {
    const result = {
      engine_count: 10,
      stats: { malicious: 0, suspicious: 0, harmless: 9, undetected: 1 }
    };

    expect(renderCautionText(result)).toBe('No vendors flagged this resource — not guaranteed safe.');
  });

  test('shows general caution for safe results with large engine count', () => {
    const result = {
      engine_count: 100,
      stats: { malicious: 0, suspicious: 0, harmless: 97, undetected: 3 }
    };

    expect(renderCautionText(result)).toBe('No vendors flagged this resource — not guaranteed safe.');
  });

  test('shows no caution for malicious results regardless of engine count', () => {
    const result = {
      engine_count: 100,
      stats: { malicious: 5, suspicious: 0, harmless: 50, undetected: 45 }
    };

    expect(renderCautionText(result)).toBe('');
  });

  test('shows no caution for suspicious results', () => {
    const result = {
      engine_count: 100,
      stats: { malicious: 0, suspicious: 3, harmless: 50, undetected: 47 }
    };

    expect(renderCautionText(result)).toBe('');
  });

  test('handles missing stats gracefully', () => {
    const result = { engine_count: 0 };
    expect(renderCautionText(result)).toBe('UNVERIFIABLE — no engines have scanned this resource yet.');
  });
});

describe('Popup UI Logic - Analysis Time Display', () => {
  test('formats ISO timestamp correctly', () => {
    const now = new Date().toISOString();
    const result = { analysis_time: now };
    const text = renderAnalysisTime(result);

    expect(text).toContain('Last analysis:');
    expect(text).toContain(new Date(now).toLocaleString());
  });

  test('returns empty string when analysis_time is null', () => {
    const result = { analysis_time: null };
    expect(renderAnalysisTime(result)).toBe('');
  });

  test('returns empty string when analysis_time is missing', () => {
    const result = {};
    expect(renderAnalysisTime(result)).toBe('');
  });

  test('handles invalid date string gracefully', () => {
    const result = { analysis_time: 'invalid-date-string' };
    expect(renderAnalysisTime(result)).toBe('');
  });

  test('formats specific timestamp correctly', () => {
    const result = { analysis_time: '2026-01-11T14:30:45Z' };
    const text = renderAnalysisTime(result);

    expect(text).toContain('Last analysis:');
    expect(text.length).toBeGreaterThan(15);
  });
});

describe('Popup UI Logic - VirusTotal Link Display', () => {
  test('shows VT link when URL is available', () => {
    const result = { vt_report_url: 'https://www.virustotal.com/gui/analysis/test-id' };
    expect(shouldDisplayVTLink(result)).toBe(true);
  });

  test('hides VT link when URL is null', () => {
    const result = { vt_report_url: null };
    expect(shouldDisplayVTLink(result)).toBe(false);
  });

  test('hides VT link when URL is empty string', () => {
    const result = { vt_report_url: '' };
    expect(shouldDisplayVTLink(result)).toBe(false);
  });

  test('hides VT link when URL is missing', () => {
    const result = {};
    expect(shouldDisplayVTLink(result)).toBe(false);
  });

  test('shows VT link with valid analysis ID in URL', () => {
    const result = { vt_report_url: 'https://www.virustotal.com/gui/analysis/abc123def456' };
    expect(shouldDisplayVTLink(result)).toBe(true);
  });
});

describe('Popup UI Logic - Status Override to UNVERIFIABLE', () => {
  test('overrides to UNVERIFIABLE when zero engines and not SCANNING', () => {
    const result = { status: 'SAFE', engine_count: 0 };
    expect(shouldOverrideStatusWithUnverifiable(result)).toBe(true);
  });

  test('does not override when engines present', () => {
    const result = { status: 'SAFE', engine_count: 10 };
    expect(shouldOverrideStatusWithUnverifiable(result)).toBe(false);
  });

  test('does not override when SCANNING status', () => {
    const result = { status: 'SCANNING', engine_count: 0 };
    expect(shouldOverrideStatusWithUnverifiable(result)).toBe(false);
  });

  test('does not override when status is scanning (lowercase)', () => {
    const result = { status: 'scanning', engine_count: 0 };
    expect(shouldOverrideStatusWithUnverifiable(result)).toBe(false);
  });

  test('overrides when status is null and zero engines', () => {
    const result = { status: null, engine_count: 0 };
    expect(shouldOverrideStatusWithUnverifiable(result)).toBe(true);
  });

  test('overrides when status is undefined and zero engines', () => {
    const result = { engine_count: 0 };
    expect(shouldOverrideStatusWithUnverifiable(result)).toBe(true);
  });

  test('does not override with one engine', () => {
    const result = { status: 'SAFE', engine_count: 1 };
    expect(shouldOverrideStatusWithUnverifiable(result)).toBe(false);
  });
});

describe('Popup UI Logic - URL Deduplication', () => {
  test('hides scanned URL when identical to cleaned', () => {
    const scanned = 'https://example.com?utm_source=x';
    const cleaned = 'https://example.com?utm_source=x';
    expect(shouldHideDuplicateScannedUrl(scanned, cleaned)).toBe(true);
  });

  test('shows both URLs when different', () => {
    const scanned = 'https://example.com?utm_source=x&utm_medium=y';
    const cleaned = 'https://example.com';
    expect(shouldHideDuplicateScannedUrl(scanned, cleaned)).toBe(false);
  });

  test('shows both when scanned is empty', () => {
    const scanned = '';
    const cleaned = 'https://example.com';
    expect(shouldHideDuplicateScannedUrl(scanned, cleaned)).toBe(false);
  });

  test('shows both when cleaned is empty', () => {
    const scanned = 'https://example.com';
    const cleaned = '';
    expect(shouldHideDuplicateScannedUrl(scanned, cleaned)).toBe(false);
  });

  test('handles null values', () => {
    expect(shouldHideDuplicateScannedUrl(null, 'https://example.com')).toBe(false);
    expect(shouldHideDuplicateScannedUrl('https://example.com', null)).toBe(false);
  });

  test('shows both when both are null', () => {
    expect(shouldHideDuplicateScannedUrl(null, null)).toBe(false);
  });

  test('matches identical URLs with different query param order', () => {
    const scanned = 'https://example.com?a=1&b=2';
    const cleaned = 'https://example.com?a=1&b=2';
    expect(shouldHideDuplicateScannedUrl(scanned, cleaned)).toBe(true);
  });

  test('detects difference in case', () => {
    const scanned = 'https://EXAMPLE.com';
    const cleaned = 'https://example.com';
    expect(shouldHideDuplicateScannedUrl(scanned, cleaned)).toBe(false);
  });
});

describe('Popup UI Logic - Integration Scenarios', () => {
  test('handles full safe scan result with all fields', () => {
    const result = {
      status: 'SAFE',
      scanned_url: 'https://example.com?utm_source=x',
      cleaned_url: 'https://example.com',
      stats: { malicious: 0, suspicious: 0, harmless: 97, undetected: 3 },
      engine_count: 100,
      analysis_time: '2026-01-11T14:30:45Z',
      vt_report_url: 'https://www.virustotal.com/gui/analysis/abc123'
    };

    expect(renderDetectionSummary(result)).toBe('No detections — 100 engines scanned');
    expect(renderCautionText(result)).toBe('No vendors flagged this resource — not guaranteed safe.');
    expect(shouldDisplayVTLink(result)).toBe(true);
    expect(shouldHideDuplicateScannedUrl(result.scanned_url, result.cleaned_url)).toBe(false);
  });

  test('handles malicious scan result', () => {
    const result = {
      status: 'MALICIOUS',
      stats: { malicious: 12, suspicious: 5, harmless: 50, undetected: 33 },
      engine_count: 100,
      analysis_time: '2026-01-11T14:30:45Z',
      vt_report_url: 'https://www.virustotal.com/gui/analysis/def456'
    };

    expect(renderDetectionSummary(result)).toBe('17 detections — 100 engines scanned');
    expect(renderCautionText(result)).toBe('');
    expect(shouldDisplayVTLink(result)).toBe(true);
  });

  test('handles unverifiable (zero-engine) result', () => {
    const result = {
      status: 'SAFE',
      stats: {},
      engine_count: 0,
      analysis_time: null,
      vt_report_url: 'https://www.virustotal.com/gui/analysis/pending'
    };

    expect(renderDetectionSummary(result)).toBe('No engines scanned yet');
    expect(renderCautionText(result)).toBe('UNVERIFIABLE — no engines have scanned this resource yet.');
    expect(shouldOverrideStatusWithUnverifiable(result)).toBe(true);
    expect(renderAnalysisTime(result)).toBe('');
  });

  test('handles small-engine incomplete result', () => {
    const result = {
      status: 'SAFE',
      stats: { malicious: 0, suspicious: 0, harmless: 4, undetected: 1 },
      engine_count: 5,
      analysis_time: '2026-01-11T14:30:45Z',
      vt_report_url: 'https://www.virustotal.com/gui/analysis/xyz789'
    };

    expect(renderDetectionSummary(result)).toBe('No detections — 5 engines scanned');
    expect(renderCautionText(result)).toContain('small number of engines');
  });

  test('handles SCANNING status without overriding', () => {
    const result = {
      status: 'SCANNING',
      engine_count: 0,
      stats: {},
      analysis_time: null
    };

    expect(shouldOverrideStatusWithUnverifiable(result)).toBe(false);
    expect(renderAnalysisTime(result)).toBe('');
  });
});
