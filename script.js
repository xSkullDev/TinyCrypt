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
        img.src = ev.target.result;
        img.onload = function() {
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
                document.getElementById('encryptedImage').src = canvas.toDataURL();
                document.getElementById('originalImage').src = img.src;
                alert('Pesan berhasil disisipkan ke gambar.');
            } catch (e) {
                alert('Error: ' + e.message);
            }
        };
    };
    reader.readAsDataURL(imageFile);
});

document.getElementById('decryptButton').addEventListener('click', function() {
    const imageFile = document.getElementById('imageInput').files[0];
    const key = document.getElementById('keyInput').value || '';
    if (!imageFile || key.length !== 16) { alert('Pilih gambar dan masukkan kunci 16 karakter.'); return; }

    const reader = new FileReader();
    reader.onload = function(ev) {
        const img = new Image();
        img.src = ev.target.result;
        img.onload = function() {
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
                document.getElementById('decryptedImage').src = img.src;
                // show message in textarea (or alert)
                document.getElementById('messageInput').value = plain;
                alert('Pesan berhasil diekstrak.');
            } catch (e) {
                alert('Error: ' + e.message);
            }
        };
    };
    reader.readAsDataURL(imageFile);
});

