package com.google.android.gms.internal.ads;

import java.util.HashMap;
import java.util.Random;

/* loaded from: classes2.dex */
public final class YD {
    public static final Random h = new Random();
    public C1874bE d;
    public String f;
    public final C2518q9 a = new C2518q9();
    public final C2303l9 b = new C2303l9();
    public final HashMap c = new HashMap();
    public A9 e = A9.a;
    public long g = -1;

    public final synchronized String a(A9 a9, C2093gF c2093gF) {
        return c(a9.n(c2093gF.a, this.b).c, c2093gF).a;
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0028 A[Catch: all -> 0x004c, TryCatch #0 {all -> 0x004c, blocks: (B:3:0x0001, B:5:0x0005, B:8:0x000f, B:10:0x0013, B:12:0x0021, B:16:0x002d, B:18:0x0033, B:20:0x003f, B:22:0x0045, B:15:0x0028, B:27:0x004f, B:29:0x0059, B:32:0x0060, B:34:0x0066, B:36:0x0079, B:37:0x0097, B:39:0x009b, B:40:0x009d, B:42:0x00a7, B:44:0x00ab, B:46:0x00b8, B:49:0x00bf, B:55:0x00dc), top: B:58:0x0001 }] */
    /* JADX WARN: Removed duplicated region for block: B:27:0x004f A[Catch: all -> 0x004c, TryCatch #0 {all -> 0x004c, blocks: (B:3:0x0001, B:5:0x0005, B:8:0x000f, B:10:0x0013, B:12:0x0021, B:16:0x002d, B:18:0x0033, B:20:0x003f, B:22:0x0045, B:15:0x0028, B:27:0x004f, B:29:0x0059, B:32:0x0060, B:34:0x0066, B:36:0x0079, B:37:0x0097, B:39:0x009b, B:40:0x009d, B:42:0x00a7, B:44:0x00ab, B:46:0x00b8, B:49:0x00bf, B:55:0x00dc), top: B:58:0x0001 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final synchronized void b(com.google.android.gms.internal.ads.RD r10) {
        /*
            Method dump skipped, instructions count: 223
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.YD.b(com.google.android.gms.internal.ads.RD):void");
    }

    /* JADX WARN: Removed duplicated region for block: B:15:0x0045  */
    /* JADX WARN: Removed duplicated region for block: B:39:0x0087  */
    /* JADX WARN: Removed duplicated region for block: B:55:0x0099 A[ADDED_TO_REGION, REMOVE, SYNTHETIC] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final com.google.android.gms.internal.ads.XD c(int r18, com.google.android.gms.internal.ads.C2093gF r19) {
        /*
            r17 = this;
            r0 = r17
            r1 = r18
            r2 = r19
            java.util.HashMap r3 = r0.c
            java.util.Collection r4 = r3.values()
            java.util.Iterator r4 = r4.iterator()
            r5 = 9223372036854775807(0x7fffffffffffffff, double:NaN)
            r7 = 0
        L16:
            boolean r8 = r4.hasNext()
            if (r8 == 0) goto L9d
            java.lang.Object r8 = r4.next()
            com.google.android.gms.internal.ads.XD r8 = (com.google.android.gms.internal.ads.XD) r8
            long r9 = r8.c
            r11 = -1
            int r9 = (r9 > r11 ? 1 : (r9 == r11 ? 0 : -1))
            if (r9 != 0) goto L52
            int r9 = r8.b
            if (r1 != r9) goto L52
            if (r2 == 0) goto L52
            com.google.android.gms.internal.ads.YD r9 = r8.g
            java.util.HashMap r10 = r9.c
            java.lang.String r13 = r9.f
            java.lang.Object r10 = r10.get(r13)
            com.google.android.gms.internal.ads.XD r10 = (com.google.android.gms.internal.ads.XD) r10
            if (r10 == 0) goto L45
            long r13 = r10.c
            int r10 = (r13 > r11 ? 1 : (r13 == r11 ? 0 : -1))
            if (r10 == 0) goto L45
            goto L4a
        L45:
            long r9 = r9.g
            r13 = 1
            long r13 = r13 + r9
        L4a:
            long r9 = r2.d
            int r13 = (r9 > r13 ? 1 : (r9 == r13 ? 0 : -1))
            if (r13 < 0) goto L52
            r8.c = r9
        L52:
            com.google.android.gms.internal.ads.gF r9 = r8.d
            if (r2 != 0) goto L5c
            int r10 = r8.b
            if (r1 != r10) goto L16
            r15 = r11
            goto L81
        L5c:
            long r13 = r2.d
            if (r9 != 0) goto L6e
            boolean r10 = r2.b()
            if (r10 != 0) goto L16
            r15 = r11
            long r11 = r8.c
            int r10 = (r13 > r11 ? 1 : (r13 == r11 ? 0 : -1))
            if (r10 != 0) goto L16
            goto L81
        L6e:
            r15 = r11
            long r10 = r9.d
            int r10 = (r13 > r10 ? 1 : (r13 == r10 ? 0 : -1))
            if (r10 != 0) goto L16
            int r10 = r2.b
            int r11 = r9.b
            if (r10 != r11) goto L16
            int r10 = r2.c
            int r11 = r9.c
            if (r10 != r11) goto L16
        L81:
            long r10 = r8.c
            int r12 = (r10 > r15 ? 1 : (r10 == r15 ? 0 : -1))
            if (r12 == 0) goto L99
            int r12 = (r10 > r5 ? 1 : (r10 == r5 ? 0 : -1))
            if (r12 >= 0) goto L8c
            goto L99
        L8c:
            if (r12 != 0) goto L16
            java.lang.String r10 = com.google.android.gms.internal.ads.Yo.a
            com.google.android.gms.internal.ads.gF r10 = r7.d
            if (r10 == 0) goto L16
            if (r9 == 0) goto L16
            r7 = r8
            goto L16
        L99:
            r7 = r8
            r5 = r10
            goto L16
        L9d:
            if (r7 != 0) goto Lb7
            r4 = 12
            byte[] r4 = new byte[r4]
            java.util.Random r5 = com.google.android.gms.internal.ads.YD.h
            r5.nextBytes(r4)
            r5 = 10
            java.lang.String r4 = android.util.Base64.encodeToString(r4, r5)
            com.google.android.gms.internal.ads.XD r5 = new com.google.android.gms.internal.ads.XD
            r5.<init>(r0, r4, r1, r2)
            r3.put(r4, r5)
            return r5
        Lb7:
            return r7
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.YD.c(int, com.google.android.gms.internal.ads.gF):com.google.android.gms.internal.ads.XD");
    }

    public final void d(XD xd) {
        long j = xd.c;
        if (j != -1) {
            this.g = j;
        }
        this.f = null;
    }

    public final void e(RD rd) {
        C2093gF c2093gF;
        boolean zO = rd.b.o();
        HashMap map = this.c;
        if (zO) {
            String str = this.f;
            if (str != null) {
                XD xd = (XD) map.get(str);
                xd.getClass();
                d(xd);
                return;
            }
            return;
        }
        XD xd2 = (XD) map.get(this.f);
        int i = rd.c;
        C2093gF c2093gF2 = rd.d;
        this.f = c(i, c2093gF2).a;
        b(rd);
        if (c2093gF2 == null || !c2093gF2.b()) {
            return;
        }
        long j = c2093gF2.d;
        if (xd2 != null && xd2.c == j && (c2093gF = xd2.d) != null && c2093gF.b == c2093gF2.b && c2093gF.c == c2093gF2.c) {
            return;
        }
        c(i, new C2093gF(j, c2093gF2.a));
    }
}
