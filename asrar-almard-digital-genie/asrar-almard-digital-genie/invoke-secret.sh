🧾 محتوى الملف invoke-secret.sh:

`bash

!/bin/bash

استدعاء ملف السر من المسار المحدد
source "$(dirname "$0")/.env.secret"

تنفيذ أمر باستخدام السر
echo "🔐 تم استدعاء السر بنجاح: $DIGITAL_SECRET"
`

---

📦 هيكل المستودع الكامل:

`
asrar-almard-digital-genie/
├── .env.secret           ← ملف السر المشفّر
├── .gitignore            ← يمنع رفع السر
└── invoke-secret.sh      ← الملف التنفيذي الرئيسي
`

---

✅ خطوات التشغيل:

1. افتح الطرفية داخل مجلد asrar-almard-digital-genie
2. اجعل السكريپت قابل للتنفيذ:
   `bash
   chmod +x invoke-secret.sh
   `
3. شغّله:
   `bash
   ./invoke-secret.sh
   `
