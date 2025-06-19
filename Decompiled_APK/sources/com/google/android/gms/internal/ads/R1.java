package com.google.android.gms.internal.ads;

import java.io.EOFException;

/* loaded from: classes2.dex */
public final class R1 {
    public int a;
    public long b;
    public int c;
    public int d;
    public int e;
    public final int[] f = new int[255];
    public final Kn g = new Kn(255);

    public final boolean a(P p, boolean z) throws zzaz, EOFException {
        boolean zK;
        boolean zK2;
        this.a = 0;
        this.b = 0L;
        this.c = 0;
        this.d = 0;
        this.e = 0;
        Kn kn = this.g;
        kn.g(27);
        try {
            zK = p.k(kn.a, 0, 27, z);
        } catch (EOFException e) {
            if (!z) {
                throw e;
            }
            zK = false;
        }
        if (zK && kn.H() == 1332176723) {
            if (kn.z() == 0) {
                this.a = kn.z();
                this.b = kn.E();
                kn.F();
                kn.F();
                kn.F();
                int iZ = kn.z();
                this.c = iZ;
                this.d = iZ + 27;
                kn.g(iZ);
                try {
                    zK2 = p.k(kn.a, 0, this.c, z);
                } catch (EOFException e2) {
                    if (!z) {
                        throw e2;
                    }
                    zK2 = false;
                }
                if (zK2) {
                    for (int i = 0; i < this.c; i++) {
                        int iZ2 = kn.z();
                        this.f[i] = iZ2;
                        this.e += iZ2;
                    }
                    return true;
                }
            } else if (!z) {
                throw zzaz.b("unsupported bit stream revision");
            }
        }
        return false;
    }

    /* JADX WARN: Code restructure failed: missing block: B:22:0x0047, code lost:
    
        if (r13 == (-1)) goto L25;
     */
    /* JADX WARN: Code restructure failed: missing block: B:24:0x004d, code lost:
    
        if (r12.d >= r13) goto L42;
     */
    /* JADX WARN: Code restructure failed: missing block: B:25:0x004f, code lost:
    
        r0 = java.lang.Math.min(r12.g, 1);
        r12.s(r0);
     */
    /* JADX WARN: Code restructure failed: missing block: B:26:0x0059, code lost:
    
        if (r0 != 0) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:27:0x005b, code lost:
    
        r5 = r12;
        r0 = r5.q(r12.a, 0, java.lang.Math.min(1, 4096), 0, true);
     */
    /* JADX WARN: Code restructure failed: missing block: B:28:0x006c, code lost:
    
        r5 = r12;
     */
    /* JADX WARN: Code restructure failed: missing block: B:30:0x006e, code lost:
    
        if (r0 == (-1)) goto L32;
     */
    /* JADX WARN: Code restructure failed: missing block: B:31:0x0070, code lost:
    
        r5.d += r0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:33:0x0077, code lost:
    
        if (r0 != (-1)) goto L35;
     */
    /* JADX WARN: Code restructure failed: missing block: B:34:0x0079, code lost:
    
        return false;
     */
    /* JADX WARN: Code restructure failed: missing block: B:35:0x007a, code lost:
    
        r12 = r5;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final boolean b(com.google.android.gms.internal.ads.P r12, long r13) throws java.io.EOFException, java.io.InterruptedIOException {
        /*
            r11 = this;
            long r0 = r12.d
            long r2 = r12.zze()
            int r0 = (r0 > r2 ? 1 : (r0 == r2 ? 0 : -1))
            r1 = 0
            r2 = 1
            if (r0 != 0) goto Le
            r0 = r2
            goto Lf
        Le:
            r0 = r1
        Lf:
            com.google.android.gms.internal.ads.AbstractC1795We.B(r0)
            com.google.android.gms.internal.ads.Kn r0 = r11.g
            r3 = 4
            r0.g(r3)
        L18:
            r4 = -1
            int r4 = (r13 > r4 ? 1 : (r13 == r4 ? 0 : -1))
            if (r4 == 0) goto L28
            long r5 = r12.d
            r7 = 4
            long r5 = r5 + r7
            int r5 = (r5 > r13 ? 1 : (r5 == r13 ? 0 : -1))
            if (r5 < 0) goto L28
            goto L47
        L28:
            byte[] r5 = r0.a
            boolean r5 = r12.k(r5, r1, r3, r2)     // Catch: java.io.EOFException -> L2f
            goto L30
        L2f:
            r5 = r1
        L30:
            if (r5 == 0) goto L47
            r0.j(r1)
            long r4 = r0.H()
            r6 = 1332176723(0x4f676753, double:6.58182753E-315)
            int r4 = (r4 > r6 ? 1 : (r4 == r6 ? 0 : -1))
            if (r4 != 0) goto L43
            r12.f = r1
            return r2
        L43:
            r12.p(r2)
            goto L18
        L47:
            if (r4 == 0) goto L4f
            long r2 = r12.d
            int r0 = (r2 > r13 ? 1 : (r2 == r13 ? 0 : -1))
            if (r0 >= 0) goto L79
        L4f:
            int r0 = r12.g
            r2 = 1
            int r0 = java.lang.Math.min(r0, r2)
            r12.s(r0)
            if (r0 != 0) goto L6c
            r0 = 4096(0x1000, float:5.74E-42)
            int r8 = java.lang.Math.min(r2, r0)
            byte[] r6 = r12.a
            r7 = 0
            r9 = 0
            r10 = 1
            r5 = r12
            int r0 = r5.q(r6, r7, r8, r9, r10)
            goto L6d
        L6c:
            r5 = r12
        L6d:
            r12 = -1
            if (r0 == r12) goto L76
            long r2 = r5.d
            long r6 = (long) r0
            long r2 = r2 + r6
            r5.d = r2
        L76:
            r12 = -1
            if (r0 != r12) goto L7a
        L79:
            return r1
        L7a:
            r12 = r5
            goto L47
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.R1.b(com.google.android.gms.internal.ads.P, long):boolean");
    }
}
