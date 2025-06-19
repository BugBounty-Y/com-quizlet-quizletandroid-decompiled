package com.google.android.gms.internal.ads;

import android.util.SparseArray;
import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.e3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1993e3 implements U {
    public boolean e;
    public boolean f;
    public boolean g;
    public long h;
    public C0 i;
    public C2695uF j;
    public boolean k;
    public final Eo a = new Eo();
    public final Kn c = new Kn(4096);
    public final SparseArray b = new SparseArray();
    public final C1906c3 d = new C1906c3(0);

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) throws EOFException, InterruptedIOException {
        byte[] bArr = new byte[14];
        P p = (P) v;
        p.k(bArr, 0, 14, false);
        if ((((bArr[0] & 255) << 24) | ((bArr[1] & 255) << 16) | ((bArr[2] & 255) << 8) | (bArr[3] & 255)) == 442 && (bArr[4] & 196) == 68 && (bArr[6] & 4) == 4 && (bArr[8] & 4) == 4 && (bArr[9] & 1) == 1 && (bArr[12] & 3) == 3) {
            p.n(bArr[13] & 7, false);
            p.k(bArr, 0, 3, false);
            if ((((bArr[0] & 255) << 16) | ((bArr[1] & 255) << 8) | (bArr[2] & 255)) == 1) {
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        this.j = (C2695uF) w;
    }

    /* JADX WARN: Removed duplicated region for block: B:104:0x0237  */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r26, androidx.compose.foundation.lazy.layout.C0429a r27) throws java.io.EOFException, java.io.InterruptedIOException {
        /*
            Method dump skipped, instructions count: 824
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1993e3.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:14:0x0021  */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void h(long r5, long r7) {
        /*
            r4 = this;
            com.google.android.gms.internal.ads.Eo r5 = r4.a
            monitor-enter(r5)
            long r0 = r5.b     // Catch: java.lang.Throwable -> L46
            monitor-exit(r5)
            r2 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            int r6 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r6 == 0) goto L21
            long r0 = r5.d()
            int r6 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r6 == 0) goto L24
            r2 = 0
            int r6 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            if (r6 == 0) goto L24
            int r6 = (r0 > r7 ? 1 : (r0 == r7 ? 0 : -1))
            if (r6 == 0) goto L24
        L21:
            r5.e(r7)
        L24:
            com.google.android.gms.internal.ads.C0 r5 = r4.i
            r6 = 0
            if (r5 == 0) goto L2c
            r5.d(r7)
        L2c:
            r5 = r6
        L2d:
            android.util.SparseArray r7 = r4.b
            int r8 = r7.size()
            if (r5 >= r8) goto L45
            java.lang.Object r7 = r7.valueAt(r5)
            com.google.android.gms.internal.ads.d3 r7 = (com.google.android.gms.internal.ads.C1950d3) r7
            r7.f = r6
            com.google.android.gms.internal.ads.N2 r7 = r7.a
            r7.zze()
            int r5 = r5 + 1
            goto L2d
        L45:
            return
        L46:
            r6 = move-exception
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L46
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C1993e3.h(long, long):void");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}
