package com.google.android.gms.internal.ads;

import android.util.SparseArray;
import androidx.camera.core.impl.C0186z;
import java.io.EOFException;
import java.util.Objects;

/* renamed from: com.google.android.gms.internal.ads.zF, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2910zF implements InterfaceC2380n0 {
    public C2883yp A;
    public final C2824xF a;
    public final C0186z b;
    public final I3 c;
    public final C1 d;
    public C2695uF e;
    public C1832aG f;
    public int g;
    public long[] h;
    public long[] i;
    public int[] j;
    public int[] k;
    public long[] l;
    public C2337m0[] m;
    public int n;
    public int o;
    public int p;
    public int q;
    public long r;
    public long s;
    public long t;
    public boolean u;
    public boolean v;
    public boolean w;
    public C1832aG x;
    public boolean y;
    public boolean z;

    public C2910zF(C1963dG c1963dG, C1 c1, C2866yE c2866yE) {
        this.d = c1;
        C2824xF c2824xF = new C2824xF();
        c2824xF.f = c1963dG;
        c2824xF.b = new Kn(32);
        androidx.compose.foundation.lazy.layout.p0 p0Var = new androidx.compose.foundation.lazy.layout.p0(0L);
        c2824xF.c = p0Var;
        c2824xF.d = p0Var;
        c2824xF.e = p0Var;
        this.a = c2824xF;
        this.b = new C0186z();
        this.g = 1000;
        this.h = new long[1000];
        this.i = new long[1000];
        this.l = new long[1000];
        this.k = new int[1000];
        this.j = new int[1000];
        this.m = new C2337m0[1000];
        this.c = new I3(new TD(18));
        this.r = Long.MIN_VALUE;
        this.s = Long.MIN_VALUE;
        this.t = Long.MIN_VALUE;
        this.w = true;
        this.v = true;
        this.y = true;
    }

    /* JADX WARN: Removed duplicated region for block: B:18:0x004f A[Catch: all -> 0x004d, TryCatch #0 {all -> 0x004d, blocks: (B:4:0x0002, B:8:0x000e, B:13:0x0020, B:15:0x0038, B:19:0x0051, B:18:0x004f), top: B:29:0x0002 }] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void a(com.google.android.gms.internal.ads.C1832aG r6) {
        /*
            r5 = this;
            monitor-enter(r5)
            r0 = 0
            r5.w = r0     // Catch: java.lang.Throwable -> L4d
            com.google.android.gms.internal.ads.aG r1 = r5.x     // Catch: java.lang.Throwable -> L4d
            boolean r1 = java.util.Objects.equals(r6, r1)     // Catch: java.lang.Throwable -> L4d
            if (r1 == 0) goto Le
            monitor-exit(r5)
            goto L64
        Le:
            com.google.android.gms.internal.ads.I3 r1 = r5.c     // Catch: java.lang.Throwable -> L4d
            java.lang.Object r2 = r1.c     // Catch: java.lang.Throwable -> L4d
            android.util.SparseArray r2 = (android.util.SparseArray) r2     // Catch: java.lang.Throwable -> L4d
            int r2 = r2.size()     // Catch: java.lang.Throwable -> L4d
            r3 = 1
            if (r2 != 0) goto L1d
            r2 = r3
            goto L1e
        L1d:
            r2 = r0
        L1e:
            if (r2 != 0) goto L4f
            java.lang.Object r2 = r1.c     // Catch: java.lang.Throwable -> L4d
            android.util.SparseArray r2 = (android.util.SparseArray) r2     // Catch: java.lang.Throwable -> L4d
            int r4 = r2.size()     // Catch: java.lang.Throwable -> L4d
            int r4 = r4 + (-1)
            java.lang.Object r2 = r2.valueAt(r4)     // Catch: java.lang.Throwable -> L4d
            com.google.android.gms.internal.ads.yF r2 = (com.google.android.gms.internal.ads.C2867yF) r2     // Catch: java.lang.Throwable -> L4d
            com.google.android.gms.internal.ads.aG r2 = r2.a     // Catch: java.lang.Throwable -> L4d
            boolean r2 = r2.equals(r6)     // Catch: java.lang.Throwable -> L4d
            if (r2 == 0) goto L4f
            java.lang.Object r6 = r1.c     // Catch: java.lang.Throwable -> L4d
            android.util.SparseArray r6 = (android.util.SparseArray) r6     // Catch: java.lang.Throwable -> L4d
            int r1 = r6.size()     // Catch: java.lang.Throwable -> L4d
            int r1 = r1 + (-1)
            java.lang.Object r6 = r6.valueAt(r1)     // Catch: java.lang.Throwable -> L4d
            com.google.android.gms.internal.ads.yF r6 = (com.google.android.gms.internal.ads.C2867yF) r6     // Catch: java.lang.Throwable -> L4d
            com.google.android.gms.internal.ads.aG r6 = r6.a     // Catch: java.lang.Throwable -> L4d
            r5.x = r6     // Catch: java.lang.Throwable -> L4d
            goto L51
        L4d:
            r6 = move-exception
            goto L72
        L4f:
            r5.x = r6     // Catch: java.lang.Throwable -> L4d
        L51:
            boolean r6 = r5.y     // Catch: java.lang.Throwable -> L4d
            com.google.android.gms.internal.ads.aG r1 = r5.x     // Catch: java.lang.Throwable -> L4d
            java.lang.String r2 = r1.m     // Catch: java.lang.Throwable -> L4d
            java.lang.String r1 = r1.j     // Catch: java.lang.Throwable -> L4d
            boolean r1 = com.google.android.gms.internal.ads.AbstractC2514q5.f(r2, r1)     // Catch: java.lang.Throwable -> L4d
            r6 = r6 & r1
            r5.y = r6     // Catch: java.lang.Throwable -> L4d
            r5.z = r0     // Catch: java.lang.Throwable -> L4d
            monitor-exit(r5)
            r0 = r3
        L64:
            com.google.android.gms.internal.ads.uF r6 = r5.e
            if (r6 == 0) goto L71
            if (r0 == 0) goto L71
            android.os.Handler r0 = r6.n
            com.google.android.gms.internal.ads.pF r6 = r6.l
            r0.post(r6)
        L71:
            return
        L72:
            monitor-exit(r5)     // Catch: java.lang.Throwable -> L4d
            throw r6
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2910zF.a(com.google.android.gms.internal.ads.aG):void");
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final void b(Kn kn, int i, int i2) {
        while (true) {
            C2824xF c2824xF = this.a;
            if (i <= 0) {
                c2824xF.getClass();
                return;
            }
            int iF = c2824xF.f(i);
            androidx.compose.foundation.lazy.layout.p0 p0Var = (androidx.compose.foundation.lazy.layout.p0) c2824xF.e;
            ZF zf = (ZF) p0Var.c;
            byte[] bArr = zf.a;
            long j = c2824xF.a - p0Var.a;
            zf.getClass();
            kn.f((int) j, bArr, iF);
            i -= iF;
            long j2 = c2824xF.a + iF;
            c2824xF.a = j2;
            androidx.compose.foundation.lazy.layout.p0 p0Var2 = (androidx.compose.foundation.lazy.layout.p0) c2824xF.e;
            if (j2 == p0Var2.b) {
                c2824xF.e = (androidx.compose.foundation.lazy.layout.p0) p0Var2.d;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final int c(InterfaceC2779wD interfaceC2779wD, int i, boolean z) throws EOFException {
        C2824xF c2824xF = this.a;
        int iF = c2824xF.f(i);
        androidx.compose.foundation.lazy.layout.p0 p0Var = (androidx.compose.foundation.lazy.layout.p0) c2824xF.e;
        ZF zf = (ZF) p0Var.c;
        byte[] bArr = zf.a;
        long j = c2824xF.a - p0Var.a;
        zf.getClass();
        int iD = interfaceC2779wD.d((int) j, bArr, iF);
        if (iD == -1) {
            if (z) {
                return -1;
            }
            throw new EOFException();
        }
        long j2 = c2824xF.a + iD;
        c2824xF.a = j2;
        androidx.compose.foundation.lazy.layout.p0 p0Var2 = (androidx.compose.foundation.lazy.layout.p0) c2824xF.e;
        if (j2 == p0Var2.b) {
            c2824xF.e = (androidx.compose.foundation.lazy.layout.p0) p0Var2.d;
        }
        return iD;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final int d(InterfaceC2779wD interfaceC2779wD, int i, boolean z) {
        return c(interfaceC2779wD, i, z);
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    public final void e(int i, Kn kn) {
        b(kn, i, 0);
    }

    /* JADX WARN: Removed duplicated region for block: B:41:0x00bd A[Catch: all -> 0x005e, TryCatch #0 {all -> 0x005e, blocks: (B:21:0x003f, B:23:0x0044, B:27:0x005a, B:30:0x0061, B:34:0x0069, B:39:0x00a4, B:60:0x0112, B:62:0x011b, B:41:0x00bd, B:43:0x00c1, B:45:0x00d8, B:49:0x00e1, B:50:0x00e6, B:52:0x00ec, B:56:0x00fa, B:58:0x00ff, B:59:0x010f, B:68:0x0189), top: B:71:0x003f }] */
    @Override // com.google.android.gms.internal.ads.InterfaceC2380n0
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final void f(long r10, int r12, int r13, int r14, com.google.android.gms.internal.ads.C2337m0 r15) {
        /*
            Method dump skipped, instructions count: 396
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2910zF.f(long, int, int, int, com.google.android.gms.internal.ads.m0):void");
    }

    public final synchronized boolean g(long j, boolean z) {
        C2910zF c2910zF;
        long j2;
        try {
            synchronized (this) {
                try {
                    try {
                        this.q = 0;
                        C2824xF c2824xF = this.a;
                        c2824xF.d = (androidx.compose.foundation.lazy.layout.p0) c2824xF.c;
                        int i = i(0);
                        int i2 = this.q;
                        int iH = this.n;
                        if ((i2 != iH) && j >= this.l[i]) {
                            if (j > this.t) {
                                if (z) {
                                    z = true;
                                }
                            }
                            if (this.y) {
                                int i3 = 0;
                                while (true) {
                                    if (i3 < iH) {
                                        try {
                                            if (this.l[i] >= j) {
                                                c2910zF = this;
                                                j2 = j;
                                                iH = i3;
                                                break;
                                            }
                                            i++;
                                            if (i == this.g) {
                                                i = 0;
                                            }
                                            i3++;
                                        } catch (Throwable th) {
                                            Throwable th2 = th;
                                            throw th2;
                                        }
                                    } else {
                                        c2910zF = this;
                                        j2 = j;
                                        if (!z) {
                                            iH = -1;
                                        }
                                    }
                                }
                            } else {
                                c2910zF = this;
                                j2 = j;
                                iH = c2910zF.h(i, iH, j2, true);
                            }
                            if (iH != -1) {
                                c2910zF.r = j2;
                                c2910zF.q += iH;
                                return true;
                            }
                        }
                        return false;
                    } finally {
                        th = th;
                        while (true) {
                            Throwable th3 = th;
                            try {
                            } catch (Throwable th4) {
                                th = th4;
                            }
                        }
                    }
                } catch (Throwable th5) {
                    th = th5;
                    throw th2;
                }
            }
        } catch (Throwable th6) {
            th = th6;
        }
    }

    public final int h(int i, int i2, long j, boolean z) {
        int i3 = -1;
        for (int i4 = 0; i4 < i2; i4++) {
            long j2 = this.l[i];
            if (j2 > j) {
                break;
            }
            if (!z || (this.k[i] & 1) != 0) {
                if (j2 == j) {
                    return i4;
                }
                i3 = i4;
            }
            i++;
            if (i == this.g) {
                i = 0;
            }
        }
        return i3;
    }

    public final int i(int i) {
        int i2 = this.p + i;
        int i3 = this.g;
        return i2 < i3 ? i2 : i2 - i3;
    }

    public final long j(int i) {
        long j = this.s;
        long jMax = Long.MIN_VALUE;
        int i2 = 0;
        if (i != 0) {
            int i3 = i(i - 1);
            for (int i4 = 0; i4 < i; i4++) {
                jMax = Math.max(jMax, this.l[i3]);
                if ((this.k[i3] & 1) != 0) {
                    break;
                }
                i3--;
                if (i3 == -1) {
                    i3 = this.g - 1;
                }
            }
        }
        this.s = Math.max(j, jMax);
        this.n -= i;
        int i5 = this.o + i;
        this.o = i5;
        int i6 = this.p + i;
        this.p = i6;
        int i7 = this.g;
        if (i6 >= i7) {
            this.p = i6 - i7;
        }
        int i8 = this.q - i;
        this.q = i8;
        if (i8 < 0) {
            this.q = 0;
        }
        while (true) {
            I3 i32 = this.c;
            SparseArray sparseArray = (SparseArray) i32.c;
            if (i2 >= sparseArray.size() - 1) {
                break;
            }
            int i9 = i2 + 1;
            if (i5 < sparseArray.keyAt(i9)) {
                break;
            }
            ((TD) i32.d).mo10b(sparseArray.valueAt(i2));
            sparseArray.removeAt(i2);
            int i10 = i32.b;
            if (i10 > 0) {
                i32.b = i10 - 1;
            }
            i2 = i9;
        }
        if (this.n != 0) {
            return this.i[this.p];
        }
        int i11 = this.p;
        if (i11 == 0) {
            i11 = this.g;
        }
        return this.i[i11 - 1] + this.j[r12];
    }

    public final void k(C1832aG c1832aG, Ps ps) {
        C1832aG c1832aG2 = this.f;
        zzs zzsVar = c1832aG2 == null ? null : c1832aG2.q;
        this.f = c1832aG;
        zzs zzsVar2 = c1832aG.q;
        this.d.getClass();
        zzs zzsVar3 = c1832aG.q;
        int i = zzsVar3 != null ? 1 : 0;
        EF ef = new EF(c1832aG);
        ef.I = i;
        ps.a = new C1832aG(ef);
        ps.b = this.A;
        if (c1832aG2 == null || !Objects.equals(zzsVar, zzsVar2)) {
            C2883yp c2883yp = zzsVar3 != null ? new C2883yp(new zzru(new zzse()), 12) : null;
            this.A = c2883yp;
            ps.b = c2883yp;
        }
    }

    public final void l() {
        long j;
        C2824xF c2824xF = this.a;
        synchronized (this) {
            int i = this.n;
            j = i == 0 ? -1L : j(i);
        }
        c2824xF.e(j);
    }

    public final void m(boolean z) {
        SparseArray sparseArray;
        C2824xF c2824xF = this.a;
        androidx.compose.foundation.lazy.layout.p0 p0Var = (androidx.compose.foundation.lazy.layout.p0) c2824xF.c;
        if (((ZF) p0Var.c) != null) {
            C1963dG c1963dG = (C1963dG) c2824xF.f;
            synchronized (c1963dG) {
                androidx.compose.foundation.lazy.layout.p0 p0Var2 = p0Var;
                while (p0Var2 != null) {
                    try {
                        ZF[] zfArr = c1963dG.d;
                        int i = c1963dG.c;
                        c1963dG.c = i + 1;
                        ZF zf = (ZF) p0Var2.c;
                        zf.getClass();
                        zfArr[i] = zf;
                        c1963dG.b--;
                        p0Var2 = (androidx.compose.foundation.lazy.layout.p0) p0Var2.d;
                        if (p0Var2 == null || ((ZF) p0Var2.c) == null) {
                            p0Var2 = null;
                        }
                    } catch (Throwable th) {
                        throw th;
                    }
                }
                c1963dG.notifyAll();
            }
            p0Var.c = null;
            p0Var.d = null;
        }
        androidx.compose.foundation.lazy.layout.p0 p0Var3 = (androidx.compose.foundation.lazy.layout.p0) c2824xF.c;
        int i2 = 0;
        AbstractC1795We.L(((ZF) p0Var3.c) == null);
        p0Var3.a = 0L;
        p0Var3.b = 65536L;
        androidx.compose.foundation.lazy.layout.p0 p0Var4 = (androidx.compose.foundation.lazy.layout.p0) c2824xF.c;
        c2824xF.d = p0Var4;
        c2824xF.e = p0Var4;
        c2824xF.a = 0L;
        ((C1963dG) c2824xF.f).b();
        this.n = 0;
        this.o = 0;
        this.p = 0;
        this.q = 0;
        this.v = true;
        this.r = Long.MIN_VALUE;
        this.s = Long.MIN_VALUE;
        this.t = Long.MIN_VALUE;
        this.u = false;
        I3 i3 = this.c;
        while (true) {
            sparseArray = (SparseArray) i3.c;
            if (i2 >= sparseArray.size()) {
                break;
            }
            ((TD) i3.d).mo10b(sparseArray.valueAt(i2));
            i2++;
        }
        i3.b = -1;
        sparseArray.clear();
        if (z) {
            this.x = null;
            this.w = true;
            this.y = true;
        }
    }

    public final synchronized boolean n(boolean z) {
        int i = this.q;
        boolean z2 = false;
        if (i != this.n) {
            if (((C2867yF) this.c.c(this.o + i)).a != this.f) {
                return true;
            }
            int i2 = i(this.q);
            if (this.A != null) {
                int i3 = this.k[i2];
            } else {
                z2 = true;
            }
            return z2;
        }
        if (z || this.u) {
            z2 = true;
        } else {
            C1832aG c1832aG = this.x;
            if (c1832aG != null) {
                if (c1832aG == this.f) {
                    return false;
                }
                z2 = true;
            }
        }
        return z2;
    }
}
