package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;
import java.io.EOFException;
import java.io.InterruptedIOException;
import java.util.List;

/* loaded from: classes2.dex */
public final class P1 implements U {
    public final /* synthetic */ int a;
    public boolean b;
    public Object c;
    public Object d;

    public P1(int i) {
        this.a = i;
        switch (i) {
            case 1:
                this.c = new I2(null, 0, "audio/ac3", 0);
                this.d = new Kn(2786);
                break;
            case 2:
                this.c = new I2(null, 0, "audio/ac4", 1);
                this.d = new Kn(16384);
                break;
        }
    }

    public boolean a(P p) {
        R1 r1 = new R1();
        if (r1.a(p, true) && (r1.a & 2) == 2) {
            int iMin = Math.min(r1.e, 8);
            Kn kn = new Kn(iMin);
            p.k(kn.a, 0, iMin, false);
            kn.j(0);
            if (kn.s() >= 5 && kn.z() == 127 && kn.H() == 1179402563) {
                this.d = new O1();
                return true;
            }
            kn.j(0);
            try {
                if (AbstractC2096gb.B(1, kn, true)) {
                    this.d = new W1();
                    return true;
                }
            } catch (zzaz unused) {
            }
            kn.j(0);
            if (T1.e(kn, T1.o)) {
                this.d = new T1();
                return true;
            }
        }
        return false;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final boolean d(V v) throws EOFException, InterruptedIOException {
        int iH;
        int i;
        int i2;
        int i3;
        switch (this.a) {
            case 0:
                try {
                    break;
                }
            case 1:
                Kn kn = new Kn(10);
                int i4 = 0;
                while (true) {
                    P p = (P) v;
                    p.k(kn.a, 0, 10, false);
                    kn.j(0);
                    if (kn.B() != 4801587) {
                        P p2 = (P) v;
                        p2.f = 0;
                        p.n(i4, false);
                        int i5 = 0;
                        int i6 = i4;
                        while (true) {
                            p.k(kn.a, 0, 6, false);
                            kn.j(0);
                            if (kn.D() != 2935) {
                                p2.f = 0;
                                i6++;
                                if (i6 - i4 >= 8192) {
                                    break;
                                } else {
                                    p.n(i6, false);
                                    i5 = 0;
                                }
                            } else {
                                i5++;
                                if (i5 >= 4) {
                                    break;
                                } else {
                                    byte[] bArr = kn.a;
                                    if (bArr.length < 6) {
                                        iH = -1;
                                    } else if (((bArr[5] & 248) >> 3) > 10) {
                                        int i7 = (((bArr[2] & 7) << 8) | (bArr[3] & 255)) + 1;
                                        iH = i7 + i7;
                                    } else {
                                        byte b = bArr[4];
                                        iH = AbstractC1795We.H((b & 192) >> 6, b & 63);
                                    }
                                    if (iH == -1) {
                                        break;
                                    } else {
                                        p.n(iH - 6, false);
                                    }
                                }
                            }
                        }
                    } else {
                        kn.k(3);
                        int iY = kn.y();
                        i4 += iY + 10;
                        p.n(iY, false);
                    }
                }
            default:
                Kn kn2 = new Kn(10);
                int i8 = 0;
                while (true) {
                    P p3 = (P) v;
                    p3.k(kn2.a, 0, 10, false);
                    kn2.j(0);
                    if (kn2.B() != 4801587) {
                        P p4 = (P) v;
                        p4.f = 0;
                        p3.n(i8, false);
                        int i9 = 0;
                        int i10 = i8;
                        while (true) {
                            p3.k(kn2.a, 0, 7, false);
                            kn2.j(0);
                            int iD = kn2.D();
                            if (iD != 44096 && iD != 44097) {
                                p4.f = 0;
                                i10++;
                                if (i10 - i8 >= 8192) {
                                    break;
                                } else {
                                    p3.n(i10, false);
                                    i9 = 0;
                                }
                            } else {
                                i9++;
                                if (i9 >= 4) {
                                    break;
                                } else {
                                    byte[] bArr2 = kn2.a;
                                    if (bArr2.length < 7) {
                                        i3 = -1;
                                    } else {
                                        int i11 = (bArr2[3] & 255) | ((bArr2[2] & 255) << 8);
                                        if (i11 == 65535) {
                                            i = ((bArr2[4] & 255) << 16) | ((bArr2[5] & 255) << 8) | (bArr2[6] & 255);
                                            i2 = 7;
                                        } else {
                                            i = i11;
                                            i2 = 4;
                                        }
                                        if (iD == 44097) {
                                            i2 += 2;
                                        }
                                        i3 = i + i2;
                                    }
                                    if (i3 == -1) {
                                        break;
                                    } else {
                                        p3.n(i3 - 7, false);
                                    }
                                }
                            }
                        }
                    } else {
                        kn2.k(3);
                        int iY2 = kn2.y();
                        i8 += iY2 + 10;
                        p3.n(iY2, false);
                    }
                }
                break;
        }
        return true;
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void e(W w) {
        switch (this.a) {
            case 0:
                this.c = (C2695uF) w;
                break;
            case 1:
                ((I2) this.c).e(w, new C0591b1(Integer.MIN_VALUE, 0, 1));
                C2695uF c2695uF = (C2695uF) w;
                c2695uF.n();
                c2695uF.p(new Y(-9223372036854775807L, 0L));
                break;
            default:
                ((I2) this.c).e(w, new C0591b1(Integer.MIN_VALUE, 0, 1));
                C2695uF c2695uF2 = (C2695uF) w;
                c2695uF2.n();
                c2695uF2.p(new Y(-9223372036854775807L, 0L));
                break;
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:83:0x01ed  */
    @Override // com.google.android.gms.internal.ads.U
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final int f(com.google.android.gms.internal.ads.V r22, androidx.compose.foundation.lazy.layout.C0429a r23) throws com.google.android.gms.internal.ads.zzaz, java.io.EOFException, java.io.InterruptedIOException {
        /*
            Method dump skipped, instructions count: 520
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.P1.f(com.google.android.gms.internal.ads.V, androidx.compose.foundation.lazy.layout.a):int");
    }

    @Override // com.google.android.gms.internal.ads.U
    public final void h(long j, long j2) {
        switch (this.a) {
            case 0:
                U1 u1 = (U1) this.d;
                if (u1 != null) {
                    Q1 q1 = u1.a;
                    R1 r1 = (R1) q1.d;
                    r1.a = 0;
                    r1.b = 0L;
                    r1.c = 0;
                    r1.d = 0;
                    r1.e = 0;
                    ((Kn) q1.e).g(0);
                    q1.b = -1;
                    q1.a = false;
                    if (j != 0) {
                        if (u1.h != 0) {
                            long j3 = (u1.i * j2) / 1000000;
                            u1.e = j3;
                            S1 s1 = u1.d;
                            String str = Yo.a;
                            s1.b(j3);
                            u1.h = 2;
                            break;
                        }
                    } else {
                        u1.b(!u1.l);
                        break;
                    }
                }
                break;
            case 1:
                this.b = false;
                ((I2) this.c).zze();
                break;
            default:
                this.b = false;
                ((I2) this.c).zze();
                break;
        }
    }

    @Override // com.google.android.gms.internal.ads.U
    public final List j() {
        switch (this.a) {
            case 0:
                C2244ju c2244ju = AbstractC2330lu.b;
                break;
            case 1:
                C2244ju c2244ju2 = AbstractC2330lu.b;
                break;
            default:
                C2244ju c2244ju3 = AbstractC2330lu.b;
                break;
        }
        return Bu.e;
    }
}
