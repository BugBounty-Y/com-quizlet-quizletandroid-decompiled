package com.facebook.appevents.integrity;

/* loaded from: classes.dex */
public final class c {
    public static final c a = new c();
    public static boolean b;
    public static boolean c;

    /* JADX WARN: Removed duplicated region for block: B:19:0x0035  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean a(java.lang.String r8) {
        /*
            r7 = this;
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r7)
            r1 = 0
            if (r0 == 0) goto L8
            return r1
        L8:
            boolean r0 = com.facebook.internal.instrument.crashshield.a.b(r7)     // Catch: java.lang.Throwable -> L41
            java.lang.String r2 = "none"
            r3 = 0
            if (r0 == 0) goto L12
            goto L3a
        L12:
            r0 = 30
            float[] r4 = new float[r0]     // Catch: java.lang.Throwable -> L1f
            r5 = r1
        L17:
            if (r5 >= r0) goto L21
            r6 = 0
            r4[r5] = r6     // Catch: java.lang.Throwable -> L1f
            int r5 = r5 + 1
            goto L17
        L1f:
            r8 = move-exception
            goto L37
        L21:
            com.facebook.appevents.ml.c r0 = com.facebook.appevents.ml.c.a     // Catch: java.lang.Throwable -> L1f
            float[][] r4 = new float[][]{r4}     // Catch: java.lang.Throwable -> L1f
            java.lang.String[] r8 = new java.lang.String[]{r8}     // Catch: java.lang.Throwable -> L1f
            java.lang.String[] r8 = com.facebook.appevents.ml.e.f(r0, r4, r8)     // Catch: java.lang.Throwable -> L1f
            if (r8 == 0) goto L35
            r3 = r8[r1]     // Catch: java.lang.Throwable -> L1f
            if (r3 != 0) goto L3a
        L35:
            r3 = r2
            goto L3a
        L37:
            com.facebook.internal.instrument.crashshield.a.a(r7, r8)     // Catch: java.lang.Throwable -> L41
        L3a:
            boolean r8 = r2.equals(r3)     // Catch: java.lang.Throwable -> L41
            r8 = r8 ^ 1
            return r8
        L41:
            r8 = move-exception
            com.facebook.internal.instrument.crashshield.a.a(r7, r8)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.facebook.appevents.integrity.c.a(java.lang.String):boolean");
    }
}
