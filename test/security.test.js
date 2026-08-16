const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const { isPrivateIp, validateExternalUrl } = require('../server/services/externalUrl');
const { sealUrl, unsealUrl } = require('../server/services/urlToken');
const { fetchValidated } = require('../server/services/safeFetch');
const { createInlineScriptHash } = require('../server/services/contentSecurityPolicy');

test('CSP inline-script hashes are stable across Windows and browser newlines', () => {
    assert.equal(
        createInlineScriptHash('const ready = true;\r\nconsole.log(ready);\r\n'),
        createInlineScriptHash('const ready = true;\nconsole.log(ready);\n')
    );
});

test('browser security helpers escape markup and reject script URLs', () => {
    const context = {
        URL,
        window: { location: { origin: 'http://127.0.0.1:3000' } },
        document: { addEventListener: () => {} },
        HTMLImageElement: class {}
    };
    vm.runInNewContext(fs.readFileSync('public/js/security.js', 'utf8'), context);

    assert.equal(
        context.window.Security.escapeHtml('<img src=x onerror="alert(1)">'),
        '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'
    );
    assert.equal(context.window.Security.safeUrl('javascript:alert(1)', '/safe'), '/safe');
    assert.match(
        context.window.Security.imageUrl('https://images.example/poster.jpg'),
        /^\/api\/proxy\/image\?url=/
    );
});

test('private and loopback addresses are rejected', async () => {
    assert.equal(isPrivateIp('127.0.0.1'), true);
    assert.equal(isPrivateIp('192.168.1.2'), true);
    assert.equal(isPrivateIp('10.0.0.1'), true);
    assert.equal(isPrivateIp('::1'), true);
    assert.equal(isPrivateIp('8.8.8.8'), false);

    await assert.rejects(validateExternalUrl('http://127.0.0.1/admin'), /Private|reserved/);
    await assert.rejects(validateExternalUrl('file:///etc/passwd'), /HTTP and HTTPS/);
});

test('stream URL tokens conceal credentials and reject tampering', () => {
    const sensitiveUrl = 'https://provider.example/live/user/secret/123.m3u8';
    const token = sealUrl(sensitiveUrl);

    assert.equal(token.includes('user'), false);
    assert.equal(token.includes('secret'), false);
    assert.equal(unsealUrl(token), sensitiveUrl);
    const middle = Math.floor(token.length / 2);
    const tampered = `${token.slice(0, middle)}${token[middle] === 'a' ? 'b' : 'a'}${token.slice(middle + 1)}`;
    assert.throws(() => unsealUrl(tampered), /Invalid|expired/);
});

test('HTTPS redirects are upgraded when the media host supports HTTPS', async t => {
    const originalFetch = global.fetch;
    t.after(() => { global.fetch = originalFetch; });

    const requested = [];
    global.fetch = async value => {
        const url = String(value);
        requested.push(url);
        if (url === 'https://provider.test/start') {
            return {
                status: 302,
                headers: { get: name => name === 'location' ? 'http://cdn.test/media.m3u8' : null }
            };
        }
        return {
            status: 200,
            ok: true,
            headers: { get: () => null }
        };
    };

    const response = await fetchValidated('https://provider.test/start', { allowPrivate: true });
    assert.equal(response.status, 200);
    assert.deepEqual(requested, [
        'https://provider.test/start',
        'https://cdn.test/media.m3u8'
    ]);
});
