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
                            document.getElementById('downloadHeatmap').disabled = false; // repurposed to download histogram
                            document.getElementById('downloadReport').disabled = false;
                            // draw histograms for original and stego
                            try {
                                const origVis = document.getElementById('originalCanvas');
                                const encVis = document.getElementById('encryptedCanvas');
                                if (origVis && encVis) drawBothHistograms(origVis, encVis);
                            } catch (e) { console.warn('Histogram draw failed', e); }
                            // store minimal metadata
                            window.__tinycrypt_last_stats = { imageWidth: canvas.width, imageHeight: canvas.height };
                        } catch (e) {
                            console.warn('Histogram generation failed:', e);
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
    const canvas = document.getElementById('histStego');
    if (!canvas || canvas.width === 0 || canvas.height === 0) { alert('Tidak ada histogram untuk didownload.'); return; }
    try {
        const url = canvas.toDataURL('image/png');
        const a = document.createElement('a');
        a.href = url;
        a.download = 'histogram_stego.png';
        a.click();
    } catch (e) {
        alert('Gagal membuat file histogram: ' + e.message);
    }
});

// Compute per-channel (R,G,B) histograms (0..255) plus 1-bit LSB counts for each channel.
// Returns { r: Uint32Array(256), g: Uint32Array(256), b: Uint32Array(256), lsbR: Uint32Array(2), lsbG: Uint32Array(2), lsbB: Uint32Array(2), totalPixels }
function computeChannelHistogramsFromCanvas(canvas) {
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    if (!w || !h) return null;
    const img = ctx.getImageData(0, 0, w, h).data;
    const r = new Uint32Array(256), g = new Uint32Array(256), b = new Uint32Array(256);
    const lsbR = new Uint32Array(2), lsbG = new Uint32Array(2), lsbB = new Uint32Array(2);
    let pixels = 0;
    for (let i = 0; i < img.length; i += 4) {
        const rv = img[i], gv = img[i+1], bv = img[i+2];
        r[rv]++; g[gv]++; b[bv]++;
        lsbR[rv & 1]++; lsbG[gv & 1]++; lsbB[bv & 1]++;
        pixels++;
    }
    return { r, g, b, lsbR, lsbG, lsbB, totalPixels: pixels };
}

// Draw an informative histogram into a canvas element showing per-channel distributions
// and a small LSB (0/1) bar chart. If histCompare is provided, draw an absolute-difference overlay
// so changes introduced by steganography become visible.
// Signature: drawHistogramToCanvas(canvasId, histPrimary, histCompare)
function drawHistogramToCanvas(canvasId, histPrimary, histCompare) {
    const c = document.getElementById(canvasId);
    if (!c || !histPrimary) return;
    const ctx = c.getContext('2d');
    const bins = 256;
    const mainH = 120;
    const lsbH = 40;
    c.width = bins;
    c.height = mainH + lsbH;
    ctx.clearRect(0, 0, c.width, c.height);

    // find max for normalization across channels
    const maxR = Math.max(...histPrimary.r);
    const maxG = Math.max(...histPrimary.g);
    const maxB = Math.max(...histPrimary.b);
    const maxChannel = Math.max(maxR, maxG, maxB, 1);

    // draw R, G, B as translucent overlays (order: B, G, R so R is on top visually)
    for (let i = 0; i < bins; i++) {
        const hr = Math.round((histPrimary.r[i] / maxChannel) * mainH);
        const hg = Math.round((histPrimary.g[i] / maxChannel) * mainH);
        const hb = Math.round((histPrimary.b[i] / maxChannel) * mainH);
        if (hb > 0) { ctx.fillStyle = 'rgba(59,130,246,0.25)'; ctx.fillRect(i, mainH - hb, 1, hb); }
        if (hg > 0) { ctx.fillStyle = 'rgba(16,185,129,0.25)'; ctx.fillRect(i, mainH - hg, 1, hg); }
        if (hr > 0) { ctx.fillStyle = 'rgba(239,68,68,0.30)'; ctx.fillRect(i, mainH - hr, 1, hr); }
    }

    // draw difference overlay if comparison histogram is provided
    if (histCompare) {
        // compute absolute difference per-channel and use it to draw a semi-transparent gray overlay
        let maxDiff = 1;
        const diffR = new Uint32Array(bins), diffG = new Uint32Array(bins), diffB = new Uint32Array(bins);
        for (let i = 0; i < bins; i++) {
            const dR = Math.abs((histCompare.r[i] || 0) - (histPrimary.r[i] || 0));
            const dG = Math.abs((histCompare.g[i] || 0) - (histPrimary.g[i] || 0));
            const dB = Math.abs((histCompare.b[i] || 0) - (histPrimary.b[i] || 0));
            const d = Math.max(dR, dG, dB);
            diffR[i] = dR; diffG[i] = dG; diffB[i] = dB;
            if (d > maxDiff) maxDiff = d;
        }
        // draw the absolute-difference as a thin darker overlay (black-ish)
        for (let i = 0; i < bins; i++) {
            const d = Math.max(diffR[i], diffG[i], diffB[i]);
            if (d === 0) continue;
            const dh = Math.round((d / maxDiff) * mainH);
            ctx.fillStyle = 'rgba(30,30,30,0.25)';
            ctx.fillRect(i, mainH - dh, 1, dh);
        }
    }

    // draw tiny grid baseline
    ctx.strokeStyle = 'rgba(0,0,0,0.06)';
    ctx.beginPath();
    for (let y = 0; y <= mainH; y += 20) { ctx.moveTo(0, y); ctx.lineTo(bins, y); }
    ctx.stroke();

    // draw LSB 0/1 bars for each channel below
    const baseY = mainH;
    const groupW = Math.floor(bins / 4);
    const barW = Math.max(6, Math.floor(groupW / 3));
    const lsbMax = Math.max(...histPrimary.lsbR, ...histPrimary.lsbG, ...histPrimary.lsbB, 1);
    const groupsX = [Math.floor(bins * 0.2), Math.floor(bins * 0.5), Math.floor(bins * 0.8)];
    const colors = ['rgba(239,68,68,0.9)', 'rgba(16,185,129,0.9)', 'rgba(59,130,246,0.9)'];
    const channelsLSB = [histPrimary.lsbR, histPrimary.lsbG, histPrimary.lsbB];
    for (let ch = 0; ch < 3; ch++) {
        const arr = channelsLSB[ch];
        const x = groupsX[ch];
        // two bars: bit0 then bit1
        const h0 = Math.round((arr[0] / lsbMax) * lsbH);
        const h1 = Math.round((arr[1] / lsbMax) * lsbH);
        // draw backgrounds
        ctx.fillStyle = 'rgba(0,0,0,0.04)'; ctx.fillRect(x - barW - 2, baseY + 2, barW * 2 + 4, lsbH - 4);
        // bit0
        ctx.fillStyle = colors[ch].replace('0.9', '0.85');
        ctx.fillRect(x - barW, baseY + (lsbH - h0), barW, h0);
        // bit1 (darker)
        ctx.fillStyle = colors[ch];
        ctx.fillRect(x + 2, baseY + (lsbH - h1), barW, h1);
        // labels
        ctx.fillStyle = 'rgba(0,0,0,0.6)'; ctx.font = '10px sans-serif'; ctx.fillText('0', x - barW + 1, baseY + lsbH + 10);
        ctx.fillText('1', x + 3, baseY + lsbH + 10);
    }

    // add legend text
    ctx.fillStyle = 'rgba(0,0,0,0.7)'; ctx.font = '11px sans-serif';
    ctx.fillText('R', 6, 12); ctx.fillStyle = 'rgba(239,68,68,0.9)'; ctx.fillRect(24,4,10,8);
    ctx.fillStyle = 'rgba(0,0,0,0.7)'; ctx.fillText('G', 44, 12); ctx.fillStyle = 'rgba(16,185,129,0.9)'; ctx.fillRect(62,4,10,8);
    ctx.fillStyle = 'rgba(0,0,0,0.7)'; ctx.fillText('B', 84, 12); ctx.fillStyle = 'rgba(59,130,246,0.9)'; ctx.fillRect(102,4,10,8);
    ctx.fillStyle = 'rgba(0,0,0,0.6)'; ctx.fillText('LSB 0/1 (R G B)', bins - 110, 12);
}

function drawBothHistograms(origCanvas, stegoCanvas) {
    if (!origCanvas || !stegoCanvas) return;
    const oW = origCanvas.width, oH = origCanvas.height;
    const sW = stegoCanvas.width, sH = stegoCanvas.height;
    const tmpO = document.createElement('canvas'); tmpO.width = oW; tmpO.height = oH; tmpO.getContext('2d').drawImage(origCanvas, 0, 0);
    const tmpS = document.createElement('canvas'); tmpS.width = sW; tmpS.height = sH; tmpS.getContext('2d').drawImage(stegoCanvas, 0, 0);
    const histO = computeChannelHistogramsFromCanvas(tmpO);
    const histS = computeChannelHistogramsFromCanvas(tmpS);
    // draw original with difference overlay showing stego changes
    drawHistogramToCanvas('histOriginal', histO, histS);
    // draw stego with difference overlay showing original differences
    drawHistogramToCanvas('histStego', histS, histO);
}

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

