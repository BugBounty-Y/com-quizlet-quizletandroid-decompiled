package com.airbnb.lottie.parser.moshi;

import com.squareup.moshi.s;
import java.io.IOException;
import okio.AbstractC5085b;
import okio.C5091h;
import okio.k;
import okio.w;

/* loaded from: classes.dex */
public final class c {
    public final String[] a;
    public final w b;

    public /* synthetic */ c(String[] strArr, w wVar) {
        this.a = strArr;
        this.b = wVar;
    }

    /* JADX WARN: Removed duplicated region for block: B:19:0x003a A[Catch: IOException -> 0x006d, TryCatch #0 {IOException -> 0x006d, blocks: (B:2:0x0000, B:3:0x000a, B:5:0x000d, B:7:0x001e, B:9:0x0026, B:21:0x0042, B:19:0x003a, B:20:0x003d, B:23:0x0047, B:24:0x004a, B:25:0x005b), top: B:30:0x0000 }] */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.airbnb.lottie.parser.moshi.c a(java.lang.String... r12) {
        /*
            int r0 = r12.length     // Catch: java.io.IOException -> L6d
            okio.k[] r0 = new okio.k[r0]     // Catch: java.io.IOException -> L6d
            okio.h r1 = new okio.h     // Catch: java.io.IOException -> L6d
            r1.<init>()     // Catch: java.io.IOException -> L6d
            r2 = 0
            r3 = r2
        La:
            int r4 = r12.length     // Catch: java.io.IOException -> L6d
            if (r3 >= r4) goto L5b
            r4 = r12[r3]     // Catch: java.io.IOException -> L6d
            java.lang.String[] r5 = com.airbnb.lottie.parser.moshi.d.e     // Catch: java.io.IOException -> L6d
            r6 = 34
            r1.p0(r6)     // Catch: java.io.IOException -> L6d
            int r7 = r4.length()     // Catch: java.io.IOException -> L6d
            r8 = r2
            r9 = r8
        L1c:
            if (r8 >= r7) goto L45
            char r10 = r4.charAt(r8)     // Catch: java.io.IOException -> L6d
            r11 = 128(0x80, float:1.8E-43)
            if (r10 >= r11) goto L2b
            r10 = r5[r10]     // Catch: java.io.IOException -> L6d
            if (r10 != 0) goto L38
            goto L42
        L2b:
            r11 = 8232(0x2028, float:1.1535E-41)
            if (r10 != r11) goto L32
            java.lang.String r10 = "\\u2028"
            goto L38
        L32:
            r11 = 8233(0x2029, float:1.1537E-41)
            if (r10 != r11) goto L42
            java.lang.String r10 = "\\u2029"
        L38:
            if (r9 >= r8) goto L3d
            r1.t0(r9, r8, r4)     // Catch: java.io.IOException -> L6d
        L3d:
            r1.u0(r10)     // Catch: java.io.IOException -> L6d
            int r9 = r8 + 1
        L42:
            int r8 = r8 + 1
            goto L1c
        L45:
            if (r9 >= r7) goto L4a
            r1.t0(r9, r7, r4)     // Catch: java.io.IOException -> L6d
        L4a:
            r1.p0(r6)     // Catch: java.io.IOException -> L6d
            r1.readByte()     // Catch: java.io.IOException -> L6d
            long r4 = r1.b     // Catch: java.io.IOException -> L6d
            okio.k r4 = r1.D(r4)     // Catch: java.io.IOException -> L6d
            r0[r3] = r4     // Catch: java.io.IOException -> L6d
            int r3 = r3 + 1
            goto La
        L5b:
            com.airbnb.lottie.parser.moshi.c r1 = new com.airbnb.lottie.parser.moshi.c     // Catch: java.io.IOException -> L6d
            java.lang.Object r12 = r12.clone()     // Catch: java.io.IOException -> L6d
            java.lang.String[] r12 = (java.lang.String[]) r12     // Catch: java.io.IOException -> L6d
            int r2 = okio.w.d     // Catch: java.io.IOException -> L6d
            okio.w r0 = okio.AbstractC5085b.g(r0)     // Catch: java.io.IOException -> L6d
            r1.<init>(r12, r0)     // Catch: java.io.IOException -> L6d
            return r1
        L6d:
            r12 = move-exception
            java.lang.AssertionError r0 = new java.lang.AssertionError
            r0.<init>(r12)
            throw r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.airbnb.lottie.parser.moshi.c.a(java.lang.String[]):com.airbnb.lottie.parser.moshi.c");
    }

    public static c b(String... strArr) {
        try {
            k[] kVarArr = new k[strArr.length];
            C5091h c5091h = new C5091h();
            for (int i = 0; i < strArr.length; i++) {
                s.a0(c5091h, strArr[i]);
                c5091h.readByte();
                kVarArr[i] = c5091h.D(c5091h.b);
            }
            String[] strArr2 = (String[]) strArr.clone();
            int i2 = w.d;
            return new c(strArr2, AbstractC5085b.g(kVarArr));
        } catch (IOException e) {
            throw new AssertionError(e);
        }
    }
}
