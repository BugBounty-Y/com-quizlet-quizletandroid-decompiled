package com.google.android.gms.internal.ads;

/* loaded from: classes2.dex */
public final class J {
    public long a = -1;
    public long b = -1;
    public long c = -1;
    public long d = -1;
    public long e = -1;
    public long f = -1;
    public long g = -1;
    public long h = -1;

    public static long a(long j, long j2, long j3, long j4, long j5, long j6) {
        if (j4 + 1 >= j5 || 1 + j2 >= j3) {
            return j4;
        }
        long j7 = (long) (((j5 - j4) / (j3 - j2)) * (j - j2));
        String str = Yo.a;
        return Math.max(j4, Math.min(((j4 + j7) - j6) - (j7 / 20), j5 - 1));
    }

    /* JADX WARN: Code restructure failed: missing block: B:24:0x00ba, code lost:
    
        if (r6.contains("REWARDED") != false) goto L25;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void b(android.content.Context r6, android.view.View r7) throws java.lang.IllegalAccessException, java.lang.IllegalArgumentException, java.lang.reflect.InvocationTargetException {
        /*
            r5 = this;
            long r0 = r5.c
            r5.d = r0
            long r0 = android.os.SystemClock.uptimeMillis()
            r5.c = r0
            long r0 = r5.e
            r2 = -1
            int r4 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r4 == 0) goto L14
            r5.f = r0
        L14:
            java.lang.String r0 = "window"
            java.lang.Object r6 = r6.getSystemService(r0)
            android.view.WindowManager r6 = (android.view.WindowManager) r6
            android.view.Display r6 = r6.getDefaultDisplay()
            android.util.DisplayMetrics r0 = new android.util.DisplayMetrics
            r0.<init>()
            r6.getRealMetrics(r0)     // Catch: java.lang.NoSuchMethodError -> L29
            goto L2c
        L29:
            r6.getMetrics(r0)
        L2c:
            int r6 = r0.widthPixels
            int r1 = r0.heightPixels
            int r6 = r6 * r1
            if (r7 != 0) goto L35
            goto Lc1
        L35:
            int r1 = r7.getWidth()
            int r4 = r0.widthPixels
            int r1 = java.lang.Math.min(r1, r4)
            int r4 = r7.getHeight()
            int r0 = r0.heightPixels
            int r0 = java.lang.Math.min(r4, r0)
            int r0 = r0 * r1
            int r1 = r0 + r0
            if (r1 < r6) goto L4f
            goto Lbc
        L4f:
            if (r0 != 0) goto Lc1
            java.lang.Class r6 = r7.getClass()     // Catch: java.lang.Throwable -> Lc1
            java.lang.String r6 = r6.getName()     // Catch: java.lang.Throwable -> Lc1
            java.lang.String r0 = "DebugGestureViewWrapper"
            boolean r6 = r6.contains(r0)     // Catch: java.lang.Throwable -> Lc1
            if (r6 == 0) goto L68
            android.view.ViewGroup r7 = (android.view.ViewGroup) r7     // Catch: java.lang.Throwable -> Lc1
            r6 = 0
            android.view.View r7 = r7.getChildAt(r6)     // Catch: java.lang.Throwable -> Lc1
        L68:
            java.lang.Class r6 = r7.getClass()     // Catch: java.lang.Throwable -> Lc1
            java.lang.String r0 = "getAdConfiguration"
            r1 = 0
            java.lang.reflect.Method r6 = r6.getMethod(r0, r1)     // Catch: java.lang.Throwable -> Lc1
            java.lang.Object r6 = r6.invoke(r7, r1)     // Catch: java.lang.Throwable -> Lc1
            java.lang.Class r7 = r6.getClass()     // Catch: java.lang.Throwable -> Lc1
            java.lang.String r0 = "adType"
            java.lang.reflect.Field r7 = r7.getField(r0)     // Catch: java.lang.Throwable -> Lc1
            java.lang.Object r7 = r7.get(r6)     // Catch: java.lang.Throwable -> Lc1
            java.lang.Integer r7 = (java.lang.Integer) r7     // Catch: java.lang.Throwable -> Lc1
            r7.intValue()     // Catch: java.lang.Throwable -> Lc1
            java.lang.Class r6 = r6.getClass()     // Catch: java.lang.Throwable -> Lc1
            java.lang.String r0 = "adTypeToString"
            java.lang.Class r4 = java.lang.Integer.TYPE     // Catch: java.lang.Throwable -> Lc1
            java.lang.Class[] r4 = new java.lang.Class[]{r4}     // Catch: java.lang.Throwable -> Lc1
            java.lang.reflect.Method r6 = r6.getMethod(r0, r4)     // Catch: java.lang.Throwable -> Lc1
            java.lang.Object[] r7 = new java.lang.Object[]{r7}     // Catch: java.lang.Throwable -> Lc1
            java.lang.Object r6 = r6.invoke(r1, r7)     // Catch: java.lang.Throwable -> Lc1
            java.lang.String r6 = (java.lang.String) r6     // Catch: java.lang.Throwable -> Lc1
            java.lang.String r7 = "INTERSTITIAL"
            boolean r7 = r6.contains(r7)     // Catch: java.lang.Throwable -> Lc1
            if (r7 != 0) goto Lbc
            java.lang.String r7 = "APP_OPEN"
            boolean r7 = r6.contains(r7)     // Catch: java.lang.Throwable -> Lc1
            if (r7 != 0) goto Lbc
            java.lang.String r7 = "REWARDED"
            boolean r6 = r6.contains(r7)     // Catch: java.lang.Throwable -> Lc1
            if (r6 == 0) goto Lc1
        Lbc:
            long r6 = r5.c
            r5.e = r6
            return
        Lc1:
            r5.e = r2
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.J.b(android.content.Context, android.view.View):void");
    }
}
