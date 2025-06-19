package androidx.appcompat.app;

import android.content.Context;

/* renamed from: androidx.appcompat.app.m, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final /* synthetic */ class RunnableC0057m implements Runnable {
    public final /* synthetic */ int a;
    public final /* synthetic */ Context b;

    public /* synthetic */ RunnableC0057m(Context context, int i) {
        this.a = i;
        this.b = context;
    }

    /* JADX WARN: Removed duplicated region for block: B:28:0x008e  */
    /* JADX WARN: Removed duplicated region for block: B:31:0x009a  */
    @Override // java.lang.Runnable
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void run() {
        /*
            r11 = this;
            int r0 = r11.a
            switch(r0) {
                case 0: goto L30;
                case 1: goto L14;
                default: goto L5;
            }
        L5:
            androidx.arch.core.executor.a r0 = new androidx.arch.core.executor.a
            r1 = 1
            r0.<init>(r1)
            com.quizlet.shared.usecase.folderstudymaterials.d r1 = androidx.profileinstaller.d.a
            r2 = 0
            android.content.Context r3 = r11.b
            androidx.profileinstaller.d.t(r3, r0, r1, r2)
            return
        L14:
            java.util.concurrent.ThreadPoolExecutor r4 = new java.util.concurrent.ThreadPoolExecutor
            java.util.concurrent.TimeUnit r9 = java.util.concurrent.TimeUnit.MILLISECONDS
            java.util.concurrent.LinkedBlockingQueue r10 = new java.util.concurrent.LinkedBlockingQueue
            r10.<init>()
            r6 = 1
            r7 = 0
            r5 = 0
            r4.<init>(r5, r6, r7, r9, r10)
            androidx.appcompat.app.m r0 = new androidx.appcompat.app.m
            android.content.Context r1 = r11.b
            r2 = 2
            r0.<init>(r1, r2)
            r4.execute(r0)
            return
        L30:
            int r0 = android.os.Build.VERSION.SDK_INT
            r1 = 1
            r2 = 33
            if (r0 < r2) goto Lb2
            android.content.ComponentName r3 = new android.content.ComponentName
            android.content.Context r4 = r11.b
            java.lang.String r5 = "androidx.appcompat.app.AppLocalesMetadataHolderService"
            r3.<init>(r4, r5)
            android.content.pm.PackageManager r5 = r4.getPackageManager()
            int r5 = r5.getComponentEnabledSetting(r3)
            if (r5 == r1) goto Lb2
            java.lang.String r5 = "locale"
            if (r0 < r2) goto L89
            androidx.collection.g r0 = androidx.appcompat.app.AbstractC0061q.g
            r0.getClass()
            androidx.collection.b r2 = new androidx.collection.b
            r2.<init>(r0)
        L58:
            boolean r0 = r2.hasNext()
            if (r0 == 0) goto L77
            java.lang.Object r0 = r2.next()
            java.lang.ref.WeakReference r0 = (java.lang.ref.WeakReference) r0
            java.lang.Object r0 = r0.get()
            androidx.appcompat.app.q r0 = (androidx.appcompat.app.AbstractC0061q) r0
            if (r0 == 0) goto L58
            androidx.appcompat.app.B r0 = (androidx.appcompat.app.B) r0
            android.content.Context r0 = r0.k
            if (r0 == 0) goto L58
            java.lang.Object r0 = r0.getSystemService(r5)
            goto L78
        L77:
            r0 = 0
        L78:
            if (r0 == 0) goto L8e
            android.os.LocaleList r0 = androidx.appcompat.app.AbstractC0059o.a(r0)
            androidx.core.os.f r2 = new androidx.core.os.f
            androidx.core.os.g r6 = new androidx.core.os.g
            r6.<init>(r0)
            r2.<init>(r6)
            goto L90
        L89:
            androidx.core.os.f r2 = androidx.appcompat.app.AbstractC0061q.c
            if (r2 == 0) goto L8e
            goto L90
        L8e:
            androidx.core.os.f r2 = androidx.core.os.f.b
        L90:
            androidx.core.os.g r0 = r2.a
            android.os.LocaleList r0 = r0.a
            boolean r0 = r0.isEmpty()
            if (r0 == 0) goto Lab
            java.lang.String r0 = androidx.core.app.AbstractC1019f.e(r4)
            java.lang.Object r2 = r4.getSystemService(r5)
            if (r2 == 0) goto Lab
            android.os.LocaleList r0 = androidx.appcompat.app.AbstractC0058n.a(r0)
            androidx.appcompat.app.AbstractC0059o.b(r2, r0)
        Lab:
            android.content.pm.PackageManager r0 = r4.getPackageManager()
            r0.setComponentEnabledSetting(r3, r1, r1)
        Lb2:
            androidx.appcompat.app.AbstractC0061q.f = r1
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.appcompat.app.RunnableC0057m.run():void");
    }
}
