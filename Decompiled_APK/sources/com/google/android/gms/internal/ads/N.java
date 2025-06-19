package com.google.android.gms.internal.ads;

import androidx.compose.foundation.lazy.layout.C0429a;

/* loaded from: classes2.dex */
public abstract class N {
    public final int a;
    public final Object b;
    public final Object c;
    public Object d;

    public N(K k, M m, long j, long j2, long j3, long j4, long j5, int i) {
        this.c = m;
        this.a = i;
        this.b = new I(k, j, j2, j3, j4, j5);
    }

    public static final int e(P p, long j, C0429a c0429a) {
        if (j == p.d) {
            return 0;
        }
        c0429a.a = j;
        return 1;
    }

    public abstract int a();

    public abstract com.quizlet.qutils.string.f b();

    /* JADX WARN: Code restructure failed: missing block: B:29:0x00c0, code lost:
    
        return e(r28, r8, r29);
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public int c(com.google.android.gms.internal.ads.P r28, androidx.compose.foundation.lazy.layout.C0429a r29) throws java.io.EOFException, java.io.InterruptedIOException {
        /*
            r27 = this;
            r0 = r27
            r1 = r28
            r2 = r29
        L6:
            java.lang.Object r3 = r0.d
            com.google.android.gms.internal.ads.J r3 = (com.google.android.gms.internal.ads.J) r3
            com.google.android.gms.internal.ads.AbstractC1795We.p(r3)
            long r4 = r3.f
            long r6 = r3.g
            long r8 = r3.h
            long r6 = r6 - r4
            int r10 = r0.a
            long r10 = (long) r10
            int r6 = (r6 > r10 ? 1 : (r6 == r10 ? 0 : -1))
            r7 = 0
            java.lang.Object r10 = r0.c
            com.google.android.gms.internal.ads.M r10 = (com.google.android.gms.internal.ads.M) r10
            if (r6 > 0) goto L2a
            r0.d = r7
            r10.mo14zzb()
            int r1 = e(r1, r4, r2)
            return r1
        L2a:
            long r4 = r1.d
            long r4 = r8 - r4
            r11 = 0
            int r6 = (r4 > r11 ? 1 : (r4 == r11 ? 0 : -1))
            if (r6 < 0) goto Lbc
            r13 = 262144(0x40000, double:1.295163E-318)
            int r6 = (r4 > r13 ? 1 : (r4 == r13 ? 0 : -1))
            if (r6 > 0) goto Lbc
            int r4 = (int) r4
            r1.p(r4)
            r4 = 0
            r1.f = r4
            long r4 = r3.b
            com.google.android.gms.internal.ads.L r4 = r10.d(r1, r4)
            r5 = -3
            int r6 = r4.a
            if (r6 == r5) goto Lb2
            r5 = -2
            long r8 = r4.b
            r15 = r11
            long r11 = r4.c
            if (r6 == r5) goto L91
            r4 = -1
            if (r6 == r4) goto L72
            long r3 = r1.d
            long r3 = r11 - r3
            int r5 = (r3 > r15 ? 1 : (r3 == r15 ? 0 : -1))
            if (r5 < 0) goto L68
            int r5 = (r3 > r13 ? 1 : (r3 == r13 ? 0 : -1))
            if (r5 > 0) goto L68
            int r3 = (int) r3
            r1.p(r3)
        L68:
            r0.d = r7
            r10.mo14zzb()
            int r1 = e(r1, r11, r2)
            return r1
        L72:
            r3.e = r8
            r3.g = r11
            long r4 = r3.d
            long r6 = r3.f
            long r13 = r3.c
            r17 = r4
            long r4 = r3.b
            r15 = r4
            r21 = r6
            r19 = r8
            r23 = r11
            r25 = r13
            long r4 = com.google.android.gms.internal.ads.J.a(r15, r17, r19, r21, r23, r25)
            r3.h = r4
            goto L6
        L91:
            r4 = r8
            r6 = r11
            r3.d = r4
            r3.f = r6
            long r8 = r3.e
            long r10 = r3.g
            long r12 = r3.c
            long r14 = r3.b
            r17 = r4
            r21 = r6
            r19 = r8
            r23 = r10
            r25 = r12
            r15 = r14
            long r4 = com.google.android.gms.internal.ads.J.a(r15, r17, r19, r21, r23, r25)
            r3.h = r4
            goto L6
        Lb2:
            r0.d = r7
            r10.mo14zzb()
            int r1 = e(r1, r8, r2)
            return r1
        Lbc:
            int r1 = e(r1, r8, r2)
            return r1
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.N.c(com.google.android.gms.internal.ads.P, androidx.compose.foundation.lazy.layout.a):int");
    }

    public void d(long j) {
        J j2 = (J) this.d;
        if (j2 == null || j2.a != j) {
            I i = (I) this.b;
            long jH = i.a.h(j);
            long j3 = i.e;
            long j4 = i.f;
            long j5 = i.c;
            long j6 = i.d;
            J j7 = new J();
            j7.a = j;
            j7.b = jH;
            j7.d = 0L;
            j7.e = j5;
            j7.f = j6;
            j7.g = j3;
            j7.c = j4;
            j7.h = J.a(jH, 0L, j5, j6, j3, j4);
            this.d = j7;
        }
    }

    public N(int i, com.quizlet.features.flashcards.data.n nVar, com.quizlet.features.flashcards.data.n nVar2, com.quizlet.features.flashcards.data.n nVar3) {
        this.a = i;
        this.b = nVar;
        this.c = nVar2;
        this.d = nVar3;
    }
}
