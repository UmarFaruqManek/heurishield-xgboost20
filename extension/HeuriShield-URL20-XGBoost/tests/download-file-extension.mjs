import assert from 'node:assert/strict';
import { urlFileExtension, executableExtensionEvidence } from '../src/analyzer/url/download-file-extension.js';
for (const [url, expected] of [
  ['https://fixture.test/setup.EXE?version=2#section', 'exe'],
  ['https://fixture.test/setup%2eapk', 'apk'],
  ['https://fixture.test/download?file=setup.exe', null],
  ['https://setup.exe/', null],
  ['https://fixture.test/?redirect=https://other.test/setup.exe', null],
  ['https://fixture.test/manual.pdf', 'pdf'],
  ['https://fixture.test/%broken', 'unknown'],
  ['not a URL', 'unknown']
]) assert.equal(urlFileExtension(url), expected, url);
assert.equal(executableExtensionEvidence(null), 'unknown');
assert.equal(executableExtensionEvidence([]), false);
assert.equal(executableExtensionEvidence(['pdf']), false);
assert.equal(executableExtensionEvidence(['pdf'], {incomplete:true}), 'unknown');
assert.equal(executableExtensionEvidence(['unknown']), 'unknown');
assert.equal(executableExtensionEvidence(['exe'], {incomplete:true}), true);
console.log('Supplemental URL suffix: path-only, encoding, unknown and executable extension evidence passed.');
