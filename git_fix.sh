#!/bin/bash

# سكريبت إصلاح أخطاء Git في Termux
# بواسطة nike1212a

echo "🔧 بدء إصلاح أخطاء Git..."

# تنظيف cache Git
echo "📝 تنظيف Git cache..."
git gc --prune=now
git repack -ad

# إصلاح مشاكل المصادقة
echo "🔑 إصلاح مشاكل المصادقة..."
git config --global credential.helper store
git config --global http.postBuffer 524288000
git config --global http.maxRequestBuffer 100M

# إصلاح مشاكل SSL
echo "🔒 إصلاح مشاكل SSL..."
git config --global http.sslverify false

# إعادة تعيين remote origin
echo "🌐 إعادة تعيين remote origin..."
read -p "أدخل رابط المستودع (https://github.com/username/repo.git): " repo_url
git remote remove origin 2>/dev/null
git remote add origin "$repo_url"

# إصلاح branch الرئيسي
echo "🌿 إصلاح branch الرئيسي..."
current_branch=$(git branch --show-current)
if [ "$current_branch" = "master" ]; then
    git branch -M main
    echo "✅ تم تغيير master إلى main"
fi

# تنظيف الملفات غير المتعقبة
echo "🧹 تنظيف الملفات..."
git clean -fd

# إعادة add وcommit للملفات
echo "📦 إضافة الملفات..."
git add .

# التحقق من وجود تغييرات
if git diff --cached --quiet; then
    echo "ℹ️ لا توجد تغييرات للحفظ"
else
    read -p "أدخل رسالة commit: " commit_msg
    git commit -m "$commit_msg"
    echo "✅ تم حفظ التغييرات"
fi

# خيارات الدفع
echo "🚀 خيارات الدفع:"
echo "1. دفع عادي"
echo "2. دفع بالقوة (force push)"
echo "3. تخطي الدفع"

read -p "اختر الخيار (1-3): " push_option

case $push_option in
    1)
        echo "📤 جاري الدفع العادي..."
        git push -u origin main
        ;;
    2)
        echo "⚠️ دفع بالقوة - احذر!"
        git push -u origin main --force
        ;;
    3)
        echo "⏭️ تم تخطي الدفع"
        ;;
    *)
        echo "❌ خيار غير صحيح"
        ;;
esac

# إظهار حالة Git النهائية
echo "📊 حالة Git النهائية:"
git status
echo "🌿 الفروع المتاحة:"
git branch -a
echo "🌐 Remote repositories:"
git remote -v

echo ""
echo "✅ تم الانتهاء من إصلاح أخطاء Git!"
echo "💡 إذا كان هناك خطأ في المصادقة، استخدم Personal Access Token"
echo "🔗 إنشاء Token: https://github.com/settings/tokens"
