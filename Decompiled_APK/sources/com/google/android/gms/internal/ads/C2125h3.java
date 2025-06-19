package com.google.android.gms.internal.ads;

import android.util.SparseArray;
import android.util.SparseBooleanArray;
import android.util.SparseIntArray;
import java.util.Collections;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.h3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2125h3 implements U {
    public final List a;
    public final Kn b = new Kn(0, new byte[9400]);
    public final SparseIntArray c;
    public final C2881yn d;
    public final C1 e;
    public final SparseArray f;
    public final SparseBooleanArray g;
    public final SparseBooleanArray h;
    public final C1906c3 i;
    public C0 j;
    public W k;
    public boolean l;
    public boolean m;
    public boolean n;
    public int o;

    public C2125h3(C1 c1, Eo eo, C2881yn c2881yn) {
        this.d = c2881yn;
        this.e = c1;
        this.a = Collections.singletonList(eo);
        SparseBooleanArray sparseBooleanArray = new SparseBooleanArray();
        this.g = sparseBooleanArray;
        this.h = new SparseBooleanArray();
        SparseArray sparseArray = new SparseArray();
        this.f = sparseArray;
        this.c = new SparseIntArray();
        this.i = new C1906c3(1);
        this.k = W.O0;
        this.o = -1;
        sparseBooleanArray.clear();
        sparseArray.clear();
        SparseArray sparseArray2 = new SparseArray();
        int size = sparseArray2.size();
        for (int i = 0; i < size; i++) {
            this.f.put(sparseArray2.keyAt(i), (InterfaceC2211j3) sparseArray2.valueAt(i));
        }
        this.f.put(0, new C2081g3(new C1732Mb(this)));
    }

    /* JADX WARN: Code restructure failed: missing block: B:10:0x001e, code lost:
    
        r2 = r2 + 1;
     */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean d(com.google.android.gms.internal.ads.V r7) throws java.io.EOFException, java.io.InterruptedIOException {
        /*
            r6 = this;
            com.google.android.gms.internal.ads.Kn r0 = r6.b
            byte[] r0 = r0.a
            com.google.android.gms.internal.ads.P r7 = (com.google.android.gms.internal.ads.P) r7
            r1 = 0
            r2 = 940(0x3ac, float:1.317E-42)
            r7.k(r0, r1, r2, r1)
            r2 = r1
        Ld:
            r3 = 188(0xbc, float:2.63E-43)
            if (r2 >= r3) goto L29
            r3 = r1
        L12:
            r4 = 5
            if (r3 >= r4) goto L24
            int r4 = r3 * 188
            int r4 = r4 + r2
            r4 = r0[r4]
            r5 = 71
            if (r4 == r5) goto L21
            int r2 = r2 + 1
            goto Ld
        L21:
            int r3 = r3 + 1
            goto L12
        L24:
            r7.p(r2)
            r7 = 1
            return r7
        L29:
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2125h3.d(com.google.android.gms.internal.ads.V):boolean");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        this.k = new androidx.browser.customtabs.k(w, this.e);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:156:0x0288  */
    /* JADX WARN: Type inference failed for: r15v0 */
    /* JADX WARN: Type inference failed for: r15v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r15v12 */
    /* JADX WARN: Type inference failed for: r15v3 */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r24, androidx.compose.foundation.lazy.layout.C0429a r25) throws java.io.EOFException, java.io.InterruptedIOException {
        /*
            Method dump skipped, instructions count: 662
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2125h3.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    /* JADX WARN: Removed duplicated region for block: B:17:0x002f  */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void h(long r10, long r12) {
        /*
            r9 = this;
            java.util.List r10 = r9.a
            int r11 = r10.size()
            r0 = 0
            r1 = r0
        L8:
            r2 = 0
            if (r1 >= r11) goto L38
            java.lang.Object r4 = r10.get(r1)
            com.google.android.gms.internal.ads.Eo r4 = (com.google.android.gms.internal.ads.Eo) r4
            monitor-enter(r4)
            long r5 = r4.b     // Catch: java.lang.Throwable -> L35
            monitor-exit(r4)
            r7 = -9223372036854775807(0x8000000000000001, double:-4.9E-324)
            int r5 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r5 == 0) goto L2f
            long r5 = r4.d()
            int r7 = (r5 > r7 ? 1 : (r5 == r7 ? 0 : -1))
            if (r7 == 0) goto L32
            int r2 = (r5 > r2 ? 1 : (r5 == r2 ? 0 : -1))
            if (r2 == 0) goto L32
            int r2 = (r5 > r12 ? 1 : (r5 == r12 ? 0 : -1))
            if (r2 == 0) goto L32
        L2f:
            r4.e(r12)
        L32:
            int r1 = r1 + 1
            goto L8
        L35:
            r10 = move-exception
            monitor-exit(r4)     // Catch: java.lang.Throwable -> L35
            throw r10
        L38:
            int r10 = (r12 > r2 ? 1 : (r12 == r2 ? 0 : -1))
            if (r10 == 0) goto L43
            com.google.android.gms.internal.ads.C0 r10 = r9.j
            if (r10 == 0) goto L43
            r10.d(r12)
        L43:
            com.google.android.gms.internal.ads.Kn r10 = r9.b
            r10.g(r0)
            android.util.SparseIntArray r10 = r9.c
            r10.clear()
        L4d:
            android.util.SparseArray r10 = r9.f
            int r11 = r10.size()
            if (r0 >= r11) goto L61
            java.lang.Object r10 = r10.valueAt(r0)
            com.google.android.gms.internal.ads.j3 r10 = (com.google.android.gms.internal.ads.InterfaceC2211j3) r10
            r10.a()
            int r0 = r0 + 1
            goto L4d
        L61:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2125h3.h(long, long):void");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}
