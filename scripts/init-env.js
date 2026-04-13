/**
 * ينسخ .env.example أو .env.production.example إلى .env إذا لم يكن .env موجوداً.
 * استخدام:
 *   node scripts/init-env.js
 *   node scripts/init-env.js production
 */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const dest = path.join(root, '.env');
const mode = (process.argv[2] || '').toLowerCase();
const srcName =
    mode === 'production' || mode === 'prod'
        ? '.env.production.example'
        : '.env.example';
const src = path.join(root, srcName);

if (fs.existsSync(dest)) {
    console.log('ملف .env موجود مسبقاً — لم يُجرَ أي تغيير.');
    process.exit(0);
}
if (!fs.existsSync(src)) {
    console.error('المصدر غير موجود:', src);
    process.exit(1);
}
fs.copyFileSync(src, dest);
console.log('تم: نسخ', srcName, '→ .env');
console.log('عدّل القيم في .env ثم شغّل npm start');
