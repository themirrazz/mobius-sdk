const AESjs = require('./aes.js');
const util = module.exports = {
    /**
     * 
     * @param {Blob} blob 
     */
    encryptDocument: async (blob) => {
        const buffer = await blob.arrayBuffer();
        const uint8 = new Uint8Array(buffer);
        const uint8padded = AESjs.padding.pkcs7.pad(uint8);
        const key = util.rbytes(32);
        const iv = util.rbytes(16);
        const aes = new AESjs.ModeOfOperation.cfb(key, iv, 16);
        const enc = new Blob([aes.encrypt(uint8padded)], {
            type: blob.type
        });
        return { blob: enc, key_raw: key, iv_raw: iv, key: AESjs.utils.hex.fromBytes(key), iv: AESjs.utils.hex.fromBytes(iv) }
    },
    rbytes: (len) => {
        return crypto.getRandomValues(new Uint8Array(len))
    },
    /**
     * @param {FormData} fd 
     */
    formDataToBuffer: async (fd) => {
        const boundary = '----WebKitFormBoundarylA4G3yq20NYmXx9n';
        const chunks = [];
        for (const [k, v] of fd) {
            chunks.push(Buffer.from('--' + boundary + '\r\n', 'utf-8'));
            chunks.push(Buffer.from(`Content-Disposition: form-data; name="${k}"${
                v instanceof Blob ? '; filename="blob"' : ''
            }\r\n`, 'utf-8'));
            if(v instanceof Blob) chunks.push(Buffer.from(`Content-Type: ${v.type}\r\n`, 'utf-8'));
            chunks.push(Buffer.from('\r\n', 'utf-8'));
            if(v instanceof Blob) {
                chunks.push(Buffer.from(await v.arrayBuffer()));
            } else {
                chunks.push(Buffer.from(v,'utf-8'));
            }
            chunks.push(Buffer.from('\r\n', 'utf-8'));
        }
        chunks.push(Buffer.from('--' + boundary + '--\r\n', 'utf-8'));
        return Buffer.concat(chunks);
    }
};
