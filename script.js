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
                        document.getElementById('downloadHeatmap').disabled = false; // repurposed to download diagram
                        document.getElementById('downloadReport').disabled = false;
                        // draw diagram showing original vs stego
                        try {
                            const origCanvas = document.getElementById('originalCanvas');
                            const encCanvas = document.getElementById('encryptedCanvas');
                            if (origCanvas && encCanvas) drawDiagramCanvas(origCanvas, encCanvas);
                        } catch (e) { console.warn('Diagram draw failed', e); }
                        // store the last stats for download (kept minimal)
                        window.__tinycrypt_last_stats = { imageWidth: canvas.width, imageHeight: canvas.height };
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
    const canvas = document.getElementById('diagramCanvas');
    if (!canvas || canvas.width === 0 || canvas.height === 0) { alert('Tidak ada diagram untuk didownload.'); return; }
    try {
        const url = canvas.toDataURL('image/png');
        const a = document.createElement('a');
        a.href = url;
        a.download = 'diagram.png';
        a.click();
    } catch (e) {
        alert('Gagal membuat file diagram: ' + e.message);
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

// --- Diagram: draw original and stego side-by-side into one canvas ---
function drawDiagramCanvas(origCanvas, stegoCanvas) {
    const canvas = document.getElementById('diagramCanvas');
    if (!canvas) return;
    // compute target size: fit both images side-by-side within canvas width
    const maxWidth = 1200; // cap large sizes
    const padding = 8;
    const origW = origCanvas.width || origCanvas.naturalWidth || 0;
    const origH = origCanvas.height || origCanvas.naturalHeight || 0;
    const stegoW = stegoCanvas.width || stegoCanvas.naturalWidth || 0;
    const stegoH = stegoCanvas.height || stegoCanvas.naturalHeight || 0;
    const height = Math.max(origH, stegoH);
    const totalW = origW + stegoW + padding * 3;
    const outW = Math.min(totalW, maxWidth);
    const scale = outW / totalW;
    canvas.width = Math.round(outW);
    canvas.height = Math.round(Math.max(120, height * scale + padding * 2));
    const ctx = canvas.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    // draw original
    const ox = padding;
    const oy = padding;
    ctx.drawImage(origCanvas, ox, oy, Math.round(origW * scale), Math.round(origH * scale));
    // draw separator
    const sepX = ox + Math.round(origW * scale) + padding;
    ctx.fillStyle = '#f1f5f9';
    ctx.fillRect(sepX - 1, oy, 2, canvas.height - padding * 2);
    // draw stego
    const sx = sepX + padding;
    ctx.drawImage(stegoCanvas, sx, oy, Math.round(stegoW * scale), Math.round(stegoH * scale));
    // labels
    ctx.fillStyle = '#0f172a';
    ctx.font = '14px Inter, Arial, sans-serif';
    ctx.fillText('Original', ox + 6, canvas.height - 6);
    ctx.fillText('Stego', sx + 6, canvas.height - 6);
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

