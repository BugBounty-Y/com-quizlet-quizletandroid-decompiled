package com.google.android.gms.internal.ads;

import androidx.compose.foundation.lazy.layout.C0429a;
import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.Arrays;
import java.util.List;

/* loaded from: classes2.dex */
public final class D0 implements U {
    public C2695uF d;
    public InterfaceC2380n0 e;
    public K4 g;
    public Z h;
    public int i;
    public int j;
    public C0 k;
    public int l;
    public long m;
    public final byte[] a = new byte[42];
    public final Kn b = new Kn(0, new byte[32768]);
    public final C0429a c = new C0429a();
    public int f = 0;

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) {
        K4 k4B = new C1947d0(0).b((P) v, AbstractC1972di.d);
        if (k4B != null) {
            int length = k4B.a.length;
        }
        Kn kn = new Kn(4);
        ((P) v).k(kn.a, 0, 4, false);
        return kn.H() == 1716281667;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        C2695uF c2695uF = (C2695uF) w;
        this.d = c2695uF;
        this.e = c2695uF.q(0, 1);
        c2695uF.n();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r1v11 */
    /* JADX WARN: Type inference failed for: r1v12, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r1v27 */
    @Override // com.google.android.gms.internal.ads.U
    public final int f(V v, C0429a c0429a) throws zzaz, EOFException, InterruptedIOException {
        Z z;
        int i;
        C2695uF c2695uF;
        InterfaceC2122h0 y;
        C2695uF c2695uF2;
        long j;
        boolean z2;
        long j2;
        boolean zV;
        int i2 = 2;
        boolean z3 = true;
        int i3 = this.f;
        K4 k4 = null;
        if (i3 == 0) {
            ((P) v).f = 0;
            P p = (P) v;
            long jZze = p.zze();
            K4 k4B = new C1947d0(0).b(p, null);
            if (k4B != null && k4B.a.length != 0) {
                k4 = k4B;
            }
            p.p((int) (p.zze() - jZze));
            this.g = k4;
            this.f = 1;
            return 0;
        }
        byte[] bArr = this.a;
        if (i3 == 1) {
            ((P) v).k(bArr, 0, 42, false);
            ((P) v).f = 0;
            this.f = 2;
            return 0;
        }
        int i4 = 3;
        if (i3 == 2) {
            Kn kn = new Kn(4);
            ((P) v).h(kn.a, 0, 4, false);
            if (kn.H() != 1716281667) {
                throw zzaz.a(null, "Failed to read FLAC stream marker.");
            }
            this.f = 3;
            return 0;
        }
        if (i3 != 3) {
            long J = 0;
            if (i3 == 4) {
                ((P) v).f = 0;
                Kn kn2 = new Kn(2);
                P p2 = (P) v;
                p2.k(kn2.a, 0, 2, false);
                int iD = kn2.D();
                if ((iD >> 2) != 16382) {
                    p2.f = 0;
                    throw zzaz.a(null, "First frame does not start with sync code.");
                }
                p2.f = 0;
                this.j = iD;
                C2695uF c2695uF3 = this.d;
                String str = Yo.a;
                long j3 = p2.d;
                Z z4 = this.h;
                z4.getClass();
                if (z4.k != null) {
                    y = new Y(z4, j3, 0);
                    i = 0;
                    c2695uF2 = c2695uF3;
                } else {
                    long j4 = p2.c;
                    if (j4 == -1 || z4.j <= 0) {
                        i = 0;
                        c2695uF = c2695uF3;
                        y = new Y(z4.a(), 0L);
                    } else {
                        int i5 = this.j;
                        Os os = new Os(z4, i2);
                        I3 i32 = new I3(z4, i5);
                        long jA = z4.a();
                        int i6 = z4.c;
                        int i7 = z4.d;
                        if (i7 > 0) {
                            j = ((i7 + i6) / 2) + 1;
                            i = 0;
                            c2695uF = c2695uF3;
                        } else {
                            int i8 = z4.b;
                            long j5 = 4096;
                            int i9 = z4.a;
                            if (i9 == i8 && i9 > 0) {
                                j5 = i9;
                            }
                            i = 0;
                            c2695uF = c2695uF3;
                            j = (((j5 * z4.g) * z4.h) / 8) + 64;
                        }
                        C0 c0 = new C0(os, i32, jA, z4.j, j3, j4, j, Math.max(6, i6));
                        this.k = c0;
                        y = (I) c0.b;
                    }
                    c2695uF2 = c2695uF;
                }
                c2695uF2.p(y);
                this.f = 5;
                return i;
            }
            this.e.getClass();
            this.h.getClass();
            C0 c02 = this.k;
            if (c02 != null && ((J) c02.d) != null) {
                return c02.c((P) v, c0429a);
            }
            if (this.m == -1) {
                ((P) v).f = 0;
                P p3 = (P) v;
                p3.n(1, false);
                byte[] bArr2 = new byte[1];
                p3.k(bArr2, 0, 1, false);
                int i10 = bArr2[0] & 1;
                boolean z5 = 1 == i10;
                p3.n(2, false);
                i = 1 != i10 ? 6 : 7;
                Kn kn3 = new Kn(i);
                byte[] bArr3 = kn3.a;
                int i11 = 0;
                while (i11 < i) {
                    int iB = p3.b(i11, bArr3, i - i11);
                    if (iB == -1) {
                        break;
                    }
                    i11 += iB;
                }
                kn3.i(i11);
                p3.f = 0;
                try {
                    J = kn3.J();
                    if (!z5) {
                        J *= r4.b;
                    }
                } catch (NumberFormatException unused) {
                    z3 = false;
                }
                if (!z3) {
                    throw zzaz.a(null, null);
                }
                this.m = J;
            } else {
                Kn kn4 = this.b;
                int i12 = kn4.c;
                if (i12 < 32768) {
                    int iD2 = ((P) v).d(i12, kn4.a, 32768 - i12);
                    z2 = iD2 == -1;
                    if (!z2) {
                        kn4.i(i12 + iD2);
                    } else if (kn4.s() == 0) {
                        long j6 = this.m * 1000000;
                        Z z6 = this.h;
                        String str2 = Yo.a;
                        this.e.f(j6 / z6.e, 1, this.l, 0, null);
                        return -1;
                    }
                } else {
                    z2 = false;
                }
                int i13 = kn4.b;
                int i14 = this.l;
                int i15 = this.i;
                if (i14 < i15) {
                    kn4.k(Math.min(i15 - i14, kn4.s()));
                }
                this.h.getClass();
                int i16 = kn4.b;
                while (true) {
                    int i17 = kn4.c - 16;
                    C0429a c0429a2 = this.c;
                    if (i16 <= i17) {
                        kn4.j(i16);
                        if (AbstractC1795We.v(kn4, this.h, this.j, c0429a2)) {
                            kn4.j(i16);
                            j2 = c0429a2.a;
                            break;
                        }
                        i16++;
                    } else {
                        if (z2) {
                            while (true) {
                                int i18 = kn4.c;
                                if (i16 > i18 - this.i) {
                                    kn4.j(i18);
                                    break;
                                }
                                kn4.j(i16);
                                try {
                                    zV = AbstractC1795We.v(kn4, this.h, this.j, c0429a2);
                                } catch (IndexOutOfBoundsException unused2) {
                                    zV = false;
                                }
                                if (kn4.b <= kn4.c && zV) {
                                    kn4.j(i16);
                                    j2 = c0429a2.a;
                                    break;
                                }
                                i16++;
                            }
                        } else {
                            kn4.j(i16);
                        }
                        j2 = -1;
                    }
                }
                int i19 = kn4.b - i13;
                kn4.j(i13);
                this.e.e(i19, kn4);
                int i20 = this.l + i19;
                this.l = i20;
                if (j2 != -1) {
                    long j7 = this.m * 1000000;
                    Z z7 = this.h;
                    String str3 = Yo.a;
                    this.e.f(j7 / z7.e, 1, i20, 0, null);
                    this.l = 0;
                    this.m = j2;
                }
                int length = kn4.a.length - kn4.c;
                if (kn4.s() < 16 && length < 16) {
                    int iS = kn4.s();
                    byte[] bArr4 = kn4.a;
                    System.arraycopy(bArr4, kn4.b, bArr4, 0, iS);
                    kn4.j(0);
                    kn4.i(iS);
                }
            }
            return 0;
        }
        ?? r1 = 0;
        Z z8 = this.h;
        while (true) {
            ((P) v).f = r1;
            byte[] bArr5 = new byte[4];
            C2466p0 c2466p0 = new C2466p0(4, bArr5);
            P p4 = (P) v;
            p4.k(bArr5, r1, 4, r1);
            boolean zW = c2466p0.w();
            int iF = c2466p0.f(i);
            int iF2 = c2466p0.f(24) + 4;
            if (iF == 0) {
                byte[] bArr6 = new byte[38];
                p4.h(bArr6, r1, 38, r1);
                z8 = new Z(4, bArr6);
            } else {
                if (z8 == null) {
                    throw new IllegalArgumentException();
                }
                if (iF == i4) {
                    Kn kn5 = new Kn(iF2);
                    p4.h(kn5.a, 0, iF2, false);
                    z8 = new Z(z8.a, z8.b, z8.c, z8.d, z8.e, z8.g, z8.h, z8.j, AbstractC1972di.m(kn5), z8.l);
                } else {
                    K4 k42 = z8.l;
                    if (iF == 4) {
                        Kn kn6 = new Kn(iF2);
                        p4.h(kn6.a, 0, iF2, false);
                        kn6.k(4);
                        K4 k4M = AbstractC2096gb.m(Arrays.asList((String[]) AbstractC2096gb.r(kn6, false, false).b));
                        if (k42 != null) {
                            k4M = k42.b(k4M);
                        }
                        z = new Z(z8.a, z8.b, z8.c, z8.d, z8.e, z8.g, z8.h, z8.j, z8.k, k4M);
                    } else if (iF == 6) {
                        Kn kn7 = new Kn(iF2);
                        p4.h(kn7.a, 0, iF2, false);
                        kn7.k(4);
                        K4 k43 = new K4(AbstractC2330lu.s(N0.b(kn7)));
                        if (k42 != null) {
                            k43 = k42.b(k43);
                        }
                        z = new Z(z8.a, z8.b, z8.c, z8.d, z8.e, z8.g, z8.h, z8.j, z8.k, k43);
                    } else {
                        p4.p(iF2);
                    }
                    z8 = z;
                }
            }
            String str4 = Yo.a;
            this.h = z8;
            if (zW) {
                this.i = Math.max(z8.c, 6);
                C1832aG c1832aGB = this.h.b(bArr, this.g);
                InterfaceC2380n0 interfaceC2380n0 = this.e;
                EF ef = new EF(c1832aGB);
                ef.a("audio/flac");
                interfaceC2380n0.a(new C1832aG(ef));
                InterfaceC2380n0 interfaceC2380n02 = this.e;
                this.h.a();
                interfaceC2380n02.getClass();
                this.f = 4;
                return 0;
            }
            r1 = 0;
            i4 = 3;
            i = 7;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        if (j == 0) {
            this.f = 0;
        } else {
            C0 c0 = this.k;
            if (c0 != null) {
                c0.d(j2);
            }
        }
        this.m = j2 != 0 ? -1L : 0L;
        this.l = 0;
        this.b.g(0);
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        C2244ju c2244ju = AbstractC2330lu.b;
        return Bu.e;
    }
}
