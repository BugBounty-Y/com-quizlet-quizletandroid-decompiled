package com.google.android.gms.internal.ads;

/* renamed from: com.google.android.gms.internal.ads.gn, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2108gn implements Pv {
    public final /* synthetic */ long a;
    public final /* synthetic */ Xp b;
    public final /* synthetic */ Vp c;
    public final /* synthetic */ String d;
    public final /* synthetic */ C2542qr e;
    public final /* synthetic */ C1849aq f;
    public final /* synthetic */ C2195in g;

    public C2108gn(C2195in c2195in, long j, Xp xp, Vp vp, String str, C2542qr c2542qr, C1849aq c1849aq) {
        this.a = j;
        this.b = xp;
        this.c = vp;
        this.d = str;
        this.e = c2542qr;
        this.f = c1849aq;
        this.g = c2195in;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x0036 A[Catch: all -> 0x0020, DONT_GENERATE, TRY_ENTER, TRY_LEAVE, TryCatch #0 {all -> 0x0020, blocks: (B:4:0x000d, B:6:0x0011, B:10:0x0023, B:12:0x0027, B:14:0x0029, B:15:0x002b, B:18:0x0036, B:25:0x004a, B:26:0x005a, B:27:0x0064, B:23:0x003e, B:24:0x003f, B:31:0x0068, B:16:0x002c, B:20:0x0038), top: B:34:0x000d, inners: #1 }] */
    @Override // com.google.android.gms.internal.ads.Pv
    /* renamed from: c */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void mo15c(java.lang.Object r12) {
        /*
            r11 = this;
            com.google.android.gms.internal.ads.in r12 = r11.g
            com.google.android.gms.common.util.a r0 = r12.a
            long r0 = r0.elapsedRealtime()
            long r2 = r11.a
            long r6 = r0 - r2
            monitor-enter(r12)
            boolean r0 = r12.e     // Catch: java.lang.Throwable -> L20
            if (r0 == 0) goto L22
            com.google.android.gms.internal.ads.lq r4 = r12.b     // Catch: java.lang.Throwable -> L20
            com.google.android.gms.internal.ads.Xp r5 = r11.b     // Catch: java.lang.Throwable -> L20
            r8 = r6
            com.google.android.gms.internal.ads.Vp r6 = r11.c     // Catch: java.lang.Throwable -> L20
            r7 = 0
            r9 = r8
            r8 = 0
            r4.i(r5, r6, r7, r8, r9)     // Catch: java.lang.Throwable -> L20
            r8 = r9
            goto L23
        L20:
            r0 = move-exception
            goto L69
        L22:
            r8 = r6
        L23:
            boolean r0 = r12.g     // Catch: java.lang.Throwable -> L20
            if (r0 == 0) goto L29
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L20
            return
        L29:
            com.google.android.gms.internal.ads.Vp r0 = r11.c     // Catch: java.lang.Throwable -> L20
            monitor-enter(r12)     // Catch: java.lang.Throwable -> L20
            java.util.LinkedHashMap r1 = r12.d     // Catch: java.lang.Throwable -> L66
            java.lang.Object r1 = r1.get(r0)     // Catch: java.lang.Throwable -> L66
            com.google.android.gms.internal.ads.hn r1 = (com.google.android.gms.internal.ads.C2152hn) r1     // Catch: java.lang.Throwable -> L66
            if (r1 != 0) goto L38
        L36:
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L20
            goto L4a
        L38:
            int r1 = r1.c     // Catch: java.lang.Throwable -> L66
            r2 = 8
            if (r1 != r2) goto L36
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L20
            java.util.LinkedHashMap r1 = r12.d     // Catch: java.lang.Throwable -> L20
            java.lang.Object r1 = r1.get(r0)     // Catch: java.lang.Throwable -> L20
            com.google.android.gms.internal.ads.hn r1 = (com.google.android.gms.internal.ads.C2152hn) r1     // Catch: java.lang.Throwable -> L20
            r1.d = r8     // Catch: java.lang.Throwable -> L20
            goto L5a
        L4a:
            java.util.LinkedHashMap r1 = r12.d     // Catch: java.lang.Throwable -> L20
            com.google.android.gms.internal.ads.hn r4 = new com.google.android.gms.internal.ads.hn     // Catch: java.lang.Throwable -> L20
            java.lang.String r5 = r11.d     // Catch: java.lang.Throwable -> L20
            java.lang.String r6 = r0.f0     // Catch: java.lang.Throwable -> L20
            r7 = 0
            r10 = 0
            r4.<init>(r5, r6, r7, r8, r10)     // Catch: java.lang.Throwable -> L20
            r1.put(r0, r4)     // Catch: java.lang.Throwable -> L20
        L5a:
            com.google.android.gms.internal.ads.zm r4 = r12.f     // Catch: java.lang.Throwable -> L20
            r9 = r8
            r8 = 0
            r6 = r9
            r9 = 1
            r5 = r0
            r4.d(r5, r6, r8, r9)     // Catch: java.lang.Throwable -> L20
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L20
            return
        L66:
            r0 = move-exception
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L66
            throw r0     // Catch: java.lang.Throwable -> L20
        L69:
            monitor-exit(r12)     // Catch: java.lang.Throwable -> L20
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2108gn.mo15c(java.lang.Object):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:60:0x005e A[EXC_TOP_SPLITTER, SYNTHETIC] */
    @Override // com.google.android.gms.internal.ads.Pv
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void zza(java.lang.Throwable r14) {
        /*
            Method dump skipped, instructions count: 237
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2108gn.zza(java.lang.Throwable):void");
    }
}
