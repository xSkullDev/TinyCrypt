// --- UTIL: konversi string <-> byte array ---
function strToBytes(str) {
    const encoder = new TextEncoder();
    return Array.from(encoder.encode(str));
}

function bytesToStr(bytes) {
    const decoder = new TextDecoder();
    return decoder.decode(new Uint8Array(bytes));
}

function u32ToBytes(n) {
    return [ (n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff ];
}

function bytesToU32(b, offset=0) {
    return ((b[offset] << 24) >>> 0) + ((b[offset+1] << 16) >>> 0) + ((b[offset+2] << 8) >>> 0) + (b[offset+3] >>> 0);
}

// --- PKCS7 padding for block size 8 ---
function pkcs7Pad(bytes, blockSize = 8) {
    const padLen = blockSize - (bytes.length % blockSize || blockSize);
    return bytes.concat(new Array(padLen).fill(padLen));
}

function pkcs7Unpad(bytes) {
    if (bytes.length === 0) return bytes;
    const padLen = bytes[bytes.length - 1];
    if (padLen <= 0 || padLen > 8) return bytes; // invalid, return raw
    return bytes.slice(0, bytes.length - padLen);
}

// --- TEA implementation (64-bit block, 128-bit key) ---
// Works on Uint8 arrays. ECB mode for simplicity; we add a simple IV-based chaining externally if needed.
function teaEncryptBlock(v0, v1, k) {
    let sum = 0;
    const delta = 0x9E3779B9 >>> 0;
    for (let i = 0; i < 32; i++) {
        sum = (sum + delta) >>> 0;
        v0 = (v0 + ((((v1 << 4) >>> 0) + k[0]) ^ (v1 + sum) ^ (((v1 >>> 5) >>> 0) + k[1]))) >>> 0;
        v1 = (v1 + ((((v0 << 4) >>> 0) + k[2]) ^ (v0 + sum) ^ (((v0 >>> 5) >>> 0) + k[3]))) >>> 0;
    }
    return [v0 >>> 0, v1 >>> 0];
}

function teaDecryptBlock(v0, v1, k) {
    const delta = 0x9E3779B9 >>> 0;
    let sum = (delta * 32) >>> 0;
    for (let i = 0; i < 32; i++) {
        v1 = (v1 - ((((v0 << 4) >>> 0) + k[2]) ^ (v0 + sum) ^ (((v0 >>> 5) >>> 0) + k[3]))) >>> 0;
        v0 = (v0 - ((((v1 << 4) >>> 0) + k[0]) ^ (v1 + sum) ^ (((v1 >>> 5) >>> 0) + k[1]))) >>> 0;
        sum = (sum - delta) >>> 0;
    }
    return [v0 >>> 0, v1 >>> 0];
}

function keyToUint32s(keyStr) {
    const bytes = strToBytes(keyStr.padEnd(16, '\0')).slice(0,16);
    const k = [];
    for (let i = 0; i < 16; i += 4) k.push(bytesToU32(bytes, i));
    return k;
}

function teaEncrypt(plainText, keyStr) {
    const data = pkcs7Pad(strToBytes(plainText), 8);
    const k = keyToUint32s(keyStr);
    const out = [];
    for (let i = 0; i < data.length; i += 8) {
        const v0 = bytesToU32(data, i);
        const v1 = bytesToU32(data, i+4);
        const [e0, e1] = teaEncryptBlock(v0, v1, k);
        out.push(...u32ToBytes(e0), ...u32ToBytes(e1));
    }
    return btoa(String.fromCharCode(...out)); // return base64 ciphertext
}

function teaDecrypt(b64Cipher, keyStr) {
    const raw = atob(b64Cipher);
    const bytes = Array.from(raw, c => c.charCodeAt(0));
    const k = keyToUint32s(keyStr);
    const out = [];
    for (let i = 0; i < bytes.length; i += 8) {
        const v0 = bytesToU32(bytes, i);
        const v1 = bytesToU32(bytes, i+4);
        const [d0, d1] = teaDecryptBlock(v0, v1, k);
        out.push(...u32ToBytes(d0), ...u32ToBytes(d1));
    }
    const unpadded = pkcs7Unpad(out);
    return bytesToStr(unpadded);
}

// --- LSB Steganography ---
// Embed base64 string into imageData using 1 bit per color channel (R,G,B), skip alpha.
// We store a 32-bit length header (number of bytes) followed by the payload bytes.
function lsbEmbed(imageData, payloadBytes) {
    const data = imageData.data;
    const capacity = Math.floor((data.length / 4) * 3 / 8); // bytes
    if (payloadBytes.length + 4 > capacity) throw new Error('Pesan terlalu besar untuk gambar ini.');

    // build bytes sequence: 4-byte length big-endian + payload
    const lenBytes = u32ToBytes(payloadBytes.length);
    const all = lenBytes.concat(payloadBytes);

    let bitIdx = 0;
    for (let i = 0; i < all.length; i++) {
        const byte = all[i];
        for (let b = 7; b >= 0; b--) {
            const bit = (byte >> b) & 1;
            // find the channel to modify: each pixel has R G B A, we use R,G,B (3 bits per pixel)
            const pixel = Math.floor(bitIdx / 3);
            const channel = bitIdx % 3; // 0->R,1->G,2->B
            const idx = pixel * 4 + channel;
            data[idx] = (data[idx] & 0xFE) | bit;
            bitIdx++;
        }
    }
    return imageData;
}

function lsbExtract(imageData) {
    const data = imageData.data;
    const totalBits = Math.floor((data.length / 4) * 3);
    // first read 32-bit length
    let bitIdx = 0;
    function readBits(n) {
        let val = 0;
        for (let i = 0; i < n; i++) {
            const pixel = Math.floor(bitIdx / 3);
            const channel = bitIdx % 3;
            const idx = pixel * 4 + channel;
            const bit = data[idx] & 1;
            val = (val << 1) | bit;
            bitIdx++;
        }
        return val;
    }

    if (totalBits < 32) throw new Error('Gambar terlalu kecil.');
    const len = readBits(32);
    if (len <= 0 || len > Math.floor(totalBits / 8)) throw new Error('Tidak ada pesan yang valid.');
    const bytes = [];
    for (let i = 0; i < len; i++) {
        const b = readBits(8);
        bytes.push(b);
    }
    return bytes;
}

// --- UI Wiring ---
document.getElementById('encryptButton').addEventListener('click', async function() {
    const imageFile = document.getElementById('imageInput').files[0];
    const message = document.getElementById('messageInput').value || '';
    const key = document.getElementById('keyInput').value || '';

    if (!imageFile || message.length === 0 || key.length !== 16) {
        alert('Pilih gambar, masukkan pesan, dan masukkan kunci 16 karakter.');
        return;
    }

    const reader = new FileReader();
    reader.onload = function(ev) {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = async function() {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

            try {
                const cipherB64 = teaEncrypt(message, key);
                // convert base64 string to bytes
                const raw = atob(cipherB64);
                const payload = Array.from(raw, c => c.charCodeAt(0));
                const stego = lsbEmbed(imageData, payload);
                ctx.putImageData(stego, 0, 0);
                const encDataUrl = canvas.toDataURL('image/png');
                // draw to canvases: original from image, encrypted by copying the working canvas to the visible encryptedCanvas
                drawToCanvas(img, 'originalCanvas');
                const visibleEnc = document.getElementById('encryptedCanvas');
                if (visibleEnc) {
                    visibleEnc.width = canvas.width;
                    visibleEnc.height = canvas.height;
                    const vctx = visibleEnc.getContext('2d');
                    vctx.clearRect(0, 0, visibleEnc.width, visibleEnc.height);
                    vctx.drawImage(canvas, 0, 0);
                } else {
                    // fallback: try to set via data URL
                    if (encDataUrl) drawToCanvasDataUrl(encDataUrl, 'encryptedCanvas');
                }
                // fill metadata for original and encrypted
                setImageMeta('metaOriginal', img.width, img.height, imageFileSize(imageFile));
                setImageMeta('metaEncrypted', canvas.width, canvas.height, dataUrlSize(encDataUrl));
                        // compute and show diagram/heatmap/histogram
                    try {
                        // we need original imageData again: draw original into a separate canvas
                        const origCanvas = document.createElement('canvas');
                        origCanvas.width = img.width;
                        origCanvas.height = img.height;
                        const octx = origCanvas.getContext('2d');
                        octx.drawImage(img, 0, 0);
                        const origImageData = octx.getImageData(0, 0, origCanvas.width, origCanvas.height);
                        const stats = computeDiffAndShowDiagram(origImageData, stego);
                        // prepare hidden canvas for download using stego data (full resolution)
                        const hidden = document.getElementById('hiddenStegoCanvas');
                        if (hidden) {
                            hidden.width = canvas.width;
                            hidden.height = canvas.height;
                            const hctx = hidden.getContext('2d');
                            hctx.putImageData(stego, 0, 0);
                        }
                        // enable download buttons
                        document.getElementById('downloadStego').disabled = false;
                        document.getElementById('downloadHeatmap').disabled = false;
                        document.getElementById('downloadReport').disabled = false;
                        // show stats
                        const statsEl = document.getElementById('diffStats');
                        statsEl.innerHTML = `Perubahan: <strong>${stats.changedPixels}</strong> pixel (${(stats.percentChanged*100).toFixed(3)}%) • Mean diff: <strong>${stats.meanDiff.toFixed(3)}</strong>`;
                        // store the last stats for download
                        window.__tinycrypt_last_stats = Object.assign({}, stats, { imageWidth: canvas.width, imageHeight: canvas.height });
                    } catch (e) {
                        console.warn('Diagram generation failed:', e);
                    }
                alert('Pesan berhasil disisipkan ke gambar.');
            } catch (e) {
                alert('Error: ' + e.message);
            }
        };
        // set src after assigning onload to avoid race conditions
        img.src = ev.target.result;
        // try to ensure image fully decoded in browsers that support decode()
        if (img.decode) img.decode().catch(() => {/* ignore decode errors, onload will still fire */});
    };
    reader.readAsDataURL(imageFile);
});

// Download button handlers
document.getElementById('downloadStego').addEventListener('click', function() {
    const hidden = document.getElementById('hiddenStegoCanvas');
    if (!hidden || hidden.width === 0 || hidden.height === 0) {
        alert('Tidak ada gambar stego yang dapat didownload. Silakan lakukan enkripsi terlebih dahulu.');
        return;
    }
    try {
        const url = hidden.toDataURL('image/png');
        const a = document.createElement('a');
        a.href = url;
        a.download = 'stego.png';
        a.click();
    } catch (e) {
        alert('Gagal membuat file PNG: ' + e.message);
    }
});

document.getElementById('downloadHeatmap').addEventListener('click', function() {
    const canvas = document.getElementById('diffHeatmap');
    // create a temp canvas scaled up for visibility if necessary
    if (!canvas || canvas.width === 0 || canvas.height === 0) { alert('Tidak ada heatmap untuk didownload.'); return; }
    try {
        const url = canvas.toDataURL('image/png');
        const a = document.createElement('a');
        a.href = url;
        a.download = 'heatmap.png';
        a.click();
    } catch (e) {
        alert('Gagal membuat file heatmap: ' + e.message);
    }
});

document.getElementById('downloadReport').addEventListener('click', function() {
    const stats = window.__tinycrypt_last_stats;
    if (!stats) { alert('Tidak ada laporan tersedia. Silakan lakukan enkripsi terlebih dahulu.'); return; }
    const payload = JSON.stringify(stats, null, 2);
    const blob = new Blob([payload], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'stego_report.json';
    a.click();
    URL.revokeObjectURL(url);
});

document.getElementById('decryptButton').addEventListener('click', function() {
    const imageFile = document.getElementById('imageInput').files[0];
    const key = document.getElementById('keyInput').value || '';
    if (!imageFile || key.length !== 16) { alert('Pilih gambar dan masukkan kunci 16 karakter.'); return; }

    const reader = new FileReader();
    reader.onload = function(ev) {
        const img = new Image();
        img.crossOrigin = 'anonymous';
        img.onload = async function() {
            const canvas = document.createElement('canvas');
            canvas.width = img.width;
            canvas.height = img.height;
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0);
            const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

            try {
                const bytes = lsbExtract(imageData);
                const raw = String.fromCharCode(...bytes);
                const b64 = btoa(raw);
                const plain = teaDecrypt(b64, key);
                // draw decrypted (visual) to canvas
                drawToCanvas(img, 'decryptedCanvas');
                setImageMeta('metaDecrypted', img.width, img.height, imageFileSize(imageFile));
                // show message in textarea (or alert)
                document.getElementById('messageInput').value = plain;
                alert('Pesan berhasil diekstrak.');
            } catch (e) {
                alert('Error: ' + e.message);
            }
        };
        img.src = ev.target.result;
        if (img.decode) img.decode().catch(() => {/* ignore decode errors */});
    };
    reader.readAsDataURL(imageFile);
});

// --- Diagram / Diff utilities ---
function computeDiffAndShowDiagram(origImageData, stegoImageData) {
    const w = origImageData.width;
    const h = origImageData.height;
    const orig = origImageData.data;
    const st = stegoImageData.data;
    const diff = new Uint8ClampedArray(w * h); // store intensity diff 0-255
    const hist = new Uint32Array(256);
    let sumDiff = 0;
    let changed = 0;
    let sumDiffR = 0, sumDiffG = 0, sumDiffB = 0;
    let changedR = 0, changedG = 0, changedB = 0;
    for (let px = 0; px < w * h; px++) {
        const oi = px * 4;
        // compute grayscale absolute diff per pixel using RGB channels average
        const origGray = Math.round((orig[oi] + orig[oi+1] + orig[oi+2]) / 3);
        const stGray = Math.round((st[oi] + st[oi+1] + st[oi+2]) / 3);
        const d = Math.abs(origGray - stGray);
        diff[px] = d;
        hist[d]++;
        sumDiff += d;
        if (d !== 0) changed++;
        // per-channel diffs
        const dr = Math.abs(orig[oi] - st[oi]);
        const dg = Math.abs(orig[oi+1] - st[oi+1]);
        const db = Math.abs(orig[oi+2] - st[oi+2]);
        sumDiffR += dr; if (dr !== 0) changedR++;
        sumDiffG += dg; if (dg !== 0) changedG++;
        sumDiffB += db; if (db !== 0) changedB++;
    }

    drawHeatmap(diff, w, h);
    drawHistogram(hist);
    renderFlowchart();
    const meanDiff = sumDiff / (w * h);
    const percentChanged = changed / (w * h);
    const meanR = sumDiffR / (w * h);
    const meanG = sumDiffG / (w * h);
    const meanB = sumDiffB / (w * h);
    return {
        changedPixels: changed,
        percentChanged,
        meanDiff,
        perChannel: {
            R: { changed: changedR, mean: meanR },
            G: { changed: changedG, mean: meanG },
            B: { changed: changedB, mean: meanB }
        }
    };
}

function drawHeatmap(diffArray, w, h) {
    const canvas = document.getElementById('diffHeatmap');
    // set canvas pixel size to image size but constrained by CSS width
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext('2d');
    const imgData = ctx.createImageData(w, h);
    for (let i = 0; i < diffArray.length; i++) {
        const d = diffArray[i];
        const idx = i * 4;
        // map diff to red heatmap: higher diff -> more red
        imgData.data[idx] = d; // R
        imgData.data[idx+1] = 0; // G
        imgData.data[idx+2] = 0; // B
        imgData.data[idx+3] = 255; // A
    }
    ctx.putImageData(imgData, 0, 0);
    // scale down visually via CSS (browser will handle scaling)
}

function drawHistogram(hist) {
    const canvas = document.getElementById('diffHistogram');
    const ctx = canvas.getContext('2d');
    // set pixel width equal to 256 for clear bins
    canvas.width = 256;
    canvas.height = 80;
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const max = Math.max(...hist);
    for (let i = 0; i < 256; i++) {
        const hgt = Math.round((hist[i] / (max || 1)) * canvas.height);
        ctx.fillStyle = '#e74c3c';
        ctx.fillRect(i, canvas.height - hgt, 1, hgt);
    }
}

function renderFlowchart() {
    const container = document.getElementById('flowchart');
    if (!container) return;
    container.innerHTML = '';

    const SVGN = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(SVGN, 'svg');
    svg.setAttribute('viewBox', '0 0 800 140');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', 'Flowchart proses enkripsi dan penyisipan');

    const defs = document.createElementNS(SVGN, 'defs');
    const style = document.createElementNS(SVGN, 'style');
    style.textContent = `.box { fill:#ffffff; stroke:#0f172a; stroke-width:1; rx:8; }
    .label { font-family: Inter, Arial, sans-serif; font-size:13px; fill:#0f172a; }
    .arrow { stroke:#0f172a; stroke-width:2; marker-end: url(#arrowhead); }`;
    defs.appendChild(style);

    const marker = document.createElementNS(SVGN, 'marker');
    marker.setAttribute('id', 'arrowhead');
    marker.setAttribute('markerWidth', '10');
    marker.setAttribute('markerHeight', '7');
    marker.setAttribute('refX', '10');
    marker.setAttribute('refY', '3.5');
    marker.setAttribute('orient', 'auto-start-reverse');
    const poly = document.createElementNS(SVGN, 'polygon');
    poly.setAttribute('points', '0 0, 10 3.5, 0 7');
    poly.setAttribute('fill', '#0f172a');
    marker.appendChild(poly);
    defs.appendChild(marker);
    svg.appendChild(defs);

    function makeRect(x, y, w, h, cls) {
        const r = document.createElementNS(SVGN, 'rect');
        r.setAttribute('x', x);
        r.setAttribute('y', y);
        r.setAttribute('width', w);
        r.setAttribute('height', h);
        if (cls) r.setAttribute('class', cls);
        return r;
    }

    function makeText(x, y, txt, cls) {
        const t = document.createElementNS(SVGN, 'text');
        t.setAttribute('x', x);
        t.setAttribute('y', y);
        t.setAttribute('text-anchor', 'middle');
        if (cls) t.setAttribute('class', cls);
        t.textContent = txt;
        return t;
    }

    function makeLine(x1, y1, x2, y2, cls) {
        const l = document.createElementNS(SVGN, 'line');
        l.setAttribute('x1', x1);
        l.setAttribute('y1', y1);
        l.setAttribute('x2', x2);
        l.setAttribute('y2', y2);
        if (cls) l.setAttribute('class', cls);
        return l;
    }

    svg.appendChild(makeRect('20', '20', '160', '48', 'box'));
    svg.appendChild(makeText('100', '50', 'Gambar Asli', 'label'));
    svg.appendChild(makeRect('220', '20', '160', '48', 'box'));
    svg.appendChild(makeText('300', '50', 'TEA Enkripsi', 'label'));
    svg.appendChild(makeRect('420', '20', '160', '48', 'box'));
    svg.appendChild(makeText('500', '50', 'LSB Embed', 'label'));
    svg.appendChild(makeRect('620', '20', '160', '48', 'box'));
    svg.appendChild(makeText('700', '50', 'Gambar Stego', 'label'));

    svg.appendChild(makeLine('180', '44', '220', '44', 'arrow'));
    svg.appendChild(makeLine('380', '44', '420', '44', 'arrow'));
    svg.appendChild(makeLine('580', '44', '620', '44', 'arrow'));

    svg.appendChild(makeText('300', '80', 'Pesan → PKCS7 → TEA (blok 64-bit)', 'label'));
    svg.appendChild(makeText('500', '96', 'Ciphertext (base64) disisipkan ke LSB', 'label'));

    container.appendChild(svg);
}

// Draw an HTMLImageElement to a canvas by id
function drawToCanvas(imgElem, canvasId) {
    const c = document.getElementById(canvasId);
    if (!c) return;
    c.width = imgElem.naturalWidth;
    c.height = imgElem.naturalHeight;
    const ctx = c.getContext('2d');
    ctx.clearRect(0, 0, c.width, c.height);
    ctx.drawImage(imgElem, 0, 0);
}

// Draw from a dataURL into a canvas
function drawToCanvasDataUrl(dataUrl, canvasId) {
    if (!dataUrl) {
        console.warn('drawToCanvasDataUrl: empty dataUrl for', canvasId);
        return;
    }
    const img = new Image();
    img.onload = function() { drawToCanvas(img, canvasId); };
    img.onerror = function(e) { console.warn('drawToCanvasDataUrl failed to load image', e); };
    img.src = dataUrl;
}

function imageFileSize(file) {
    try { return file.size || 0; } catch (e) { return 0; }
}

// --- Helpers for image metadata ---
function dataUrlSize(dataUrl) {
    if (!dataUrl) return 0;
    // data:[<mediatype>][;base64],<data>
    const idx = dataUrl.indexOf(',');
    if (idx === -1) return 0;
    const meta = dataUrl.substring(0, idx);
    const isBase64 = meta.indexOf(';base64') !== -1;
    const data = dataUrl.substring(idx + 1);
    if (isBase64) {
        // approximate bytes from base64 length
        const padding = (data.endsWith('==') ? 2 : data.endsWith('=') ? 1 : 0);
        return Math.floor((data.length * 3) / 4) - padding;
    }
    // percent-encoded
    return decodeURIComponent(data).length;
}

function setImageMeta(elementId, width, height, byteSize) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const kb = (byteSize / 1024).toFixed(1);
    el.innerHTML = `<small>Ukuran: ${width}×${height}px • ${kb} KB</small>`;
}

