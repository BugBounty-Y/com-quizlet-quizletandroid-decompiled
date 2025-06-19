package com.facebook.internal;

import java.util.TreeSet;

/* loaded from: classes.dex */
public final class B {
    public TreeSet a;
    public final /* synthetic */ int b;

    public /* synthetic */ B(int i) {
        this.b = i;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x0011 A[Catch: all -> 0x000f, TRY_LEAVE, TryCatch #1 {all -> 0x000f, all -> 0x0022, blocks: (B:5:0x0004, B:7:0x0008, B:20:0x0029, B:22:0x002d, B:24:0x0033, B:25:0x0035, B:27:0x0039, B:29:0x0047, B:36:0x0057, B:35:0x0054, B:12:0x0011, B:19:0x0027, B:18:0x0023, B:15:0x001d), top: B:43:0x0004 }] */
    /* JADX WARN: Unreachable blocks removed: 2, instructions: 2 */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void a(boolean r4) {
        /*
            r3 = this;
            r0 = 0
            monitor-enter(r3)
            if (r4 != 0) goto L11
            java.util.TreeSet r4 = r3.a     // Catch: java.lang.Throwable -> Lf
            if (r4 == 0) goto L11
            boolean r4 = r4.isEmpty()     // Catch: java.lang.Throwable -> Lf
            if (r4 != 0) goto L11
            goto L29
        Lf:
            r4 = move-exception
            goto L5e
        L11:
            com.facebook.internal.C r4 = com.facebook.internal.C.a     // Catch: java.lang.Throwable -> Lf
            java.lang.Class<com.facebook.internal.C> r1 = com.facebook.internal.C.class
            boolean r2 = com.facebook.internal.instrument.crashshield.a.b(r1)     // Catch: java.lang.Throwable -> Lf
            if (r2 == 0) goto L1d
        L1b:
            r4 = r0
            goto L27
        L1d:
            java.util.TreeSet r4 = r4.f(r3)     // Catch: java.lang.Throwable -> L22
            goto L27
        L22:
            r4 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r1, r4)     // Catch: java.lang.Throwable -> Lf
            goto L1b
        L27:
            r3.a = r4     // Catch: java.lang.Throwable -> Lf
        L29:
            java.util.TreeSet r4 = r3.a     // Catch: java.lang.Throwable -> Lf
            if (r4 == 0) goto L33
            boolean r4 = r4.isEmpty()     // Catch: java.lang.Throwable -> Lf
            if (r4 == 0) goto L5c
        L33:
            int r4 = r3.b     // Catch: java.lang.Throwable -> Lf
            switch(r4) {
                case 2: goto L39;
                default: goto L38;
            }     // Catch: java.lang.Throwable -> Lf
        L38:
            goto L5c
        L39:
            android.content.Context r4 = com.facebook.o.a()     // Catch: java.lang.Throwable -> Lf
            android.content.pm.ApplicationInfo r4 = r4.getApplicationInfo()     // Catch: java.lang.Throwable -> Lf
            int r4 = r4.targetSdkVersion     // Catch: java.lang.Throwable -> Lf
            r1 = 30
            if (r4 < r1) goto L5c
            java.lang.Class<com.facebook.internal.C> r4 = com.facebook.internal.C.class
            boolean r1 = com.facebook.internal.instrument.crashshield.a.b(r4)     // Catch: java.lang.Throwable -> Lf
            if (r1 == 0) goto L50
            goto L57
        L50:
            java.lang.String r0 = "com.facebook.internal.C"
            goto L57
        L53:
            r1 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r4, r1)     // Catch: java.lang.Throwable -> Lf
        L57:
            java.lang.String r4 = "Apps that target Android API 30+ (Android 11+) cannot call Facebook native apps unless the package visibility needs are declared. Please follow https://developers.facebook.com/docs/android/troubleshooting/#faq_267321845055988 to make the declaration."
            android.util.Log.w(r0, r4)     // Catch: java.lang.Throwable -> Lf
        L5c:
            monitor-exit(r3)
            return
        L5e:
            monitor-exit(r3)     // Catch: java.lang.Throwable -> Lf
            throw r4
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.internal.B.a(boolean):void");
    }

    public final String b() {
        switch (this.b) {
            case 0:
                return "com.facebook.arstudio.player";
            case 1:
                return "com.instagram.android";
            case 2:
                return "com.facebook.katana";
            case 3:
                return "com.facebook.orca";
            default:
                return "com.facebook.wakizashi";
        }
    }

    public final void c() {
    }
}
