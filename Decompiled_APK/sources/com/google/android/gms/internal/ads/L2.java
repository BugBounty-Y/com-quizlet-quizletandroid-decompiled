package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;
import com.amazon.device.ads.DtbConstants;
import java.math.RoundingMode;
import java.util.concurrent.atomic.AtomicInteger;

/* loaded from: classes2.dex */
public final class L2 implements N2 {
    public final Kn a;
    public final String c;
    public final int d;
    public String f;
    public InterfaceC2380n0 g;
    public int i;
    public int j;
    public long k;
    public C1832aG l;
    public int m;
    public int n;
    public int h = 0;
    public long q = -9223372036854775807L;
    public final AtomicInteger b = new AtomicInteger();
    public int o = -1;
    public int p = -1;
    public final String e = "video/mp2t";

    public L2(String str, int i, int i2) {
        this.a = new Kn(new byte[i2]);
        this.c = str;
        this.d = i;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void a(boolean z) {
    }

    public final void b(F f) {
        int i;
        int i2 = f.b;
        if (i2 == -2147483647 || (i = f.c) == -1) {
            return;
        }
        C1832aG c1832aG = this.l;
        String str = f.a;
        if (c1832aG != null && i == c1832aG.C && i2 == c1832aG.D && str.equals(c1832aG.m)) {
            return;
        }
        C1832aG c1832aG2 = this.l;
        EF ef = c1832aG2 == null ? new EF() : new EF(c1832aG2);
        ef.a = this.f;
        ef.a(this.e);
        ef.d(str);
        ef.B = i;
        ef.C = i2;
        ef.d = this.c;
        ef.f = this.d;
        C1832aG c1832aG3 = new C1832aG(ef);
        this.l = c1832aG3;
        this.g.a(c1832aG3);
    }

    public final boolean c(Kn kn, byte[] bArr, int i) {
        int iMin = Math.min(kn.s(), i - this.i);
        kn.f(this.i, bArr, iMin);
        int i2 = this.i + iMin;
        this.i = i2;
        return i2 == i;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void d(Kn kn) throws zzaz {
        int i;
        boolean z;
        int i2;
        byte b;
        int i3;
        byte b2;
        int i4;
        int i5;
        byte b3;
        int i6;
        long jV;
        int i7;
        int i8;
        int i9;
        int iF;
        int i10;
        int iF2;
        long jV2;
        int i11;
        int i12 = 4;
        AbstractC1795We.p(this.g);
        while (kn.s() > 0) {
            int i13 = this.h;
            Kn kn2 = this.a;
            if (i13 != 0) {
                if (i13 != 1) {
                    if (i13 != 2) {
                        int iF3 = -2147483647;
                        int i14 = 8;
                        if (i13 != 3) {
                            if (i13 == i12) {
                                i6 = i12;
                                if (c(kn, kn2.a, 6)) {
                                    C2466p0 c2466p0E = LA.E(kn2.a);
                                    c2466p0E.u(32);
                                    int iB = LA.B(c2466p0E, LA.i) + 1;
                                    this.p = iB;
                                    int i15 = this.i;
                                    if (i15 > iB) {
                                        int i16 = i15 - iB;
                                        this.i = i15 - i16;
                                        kn.j(kn.b - i16);
                                    }
                                    this.h = 5;
                                }
                            } else if (i13 != 5) {
                                int iMin = Math.min(kn.s(), this.m - this.i);
                                this.g.e(iMin, kn);
                                int i17 = this.i + iMin;
                                this.i = i17;
                                if (i17 == this.m) {
                                    AbstractC1795We.L(this.q != -9223372036854775807L);
                                    this.g.f(this.q, this.n == i12 ? 0 : 1, this.m, 0, null);
                                    this.q += this.k;
                                    this.h = 0;
                                }
                            } else if (c(kn, kn2.a, this.p)) {
                                AtomicInteger atomicInteger = this.b;
                                byte[] bArr = kn2.a;
                                i6 = i12;
                                C2466p0 c2466p0E2 = LA.E(bArr);
                                int iF4 = c2466p0E2.f(32);
                                int iB2 = LA.B(c2466p0E2, LA.e);
                                int i18 = iB2 + 1;
                                char c = iF4 == 1078008818 ? (char) 1 : (char) 0;
                                if (c == 0) {
                                    jV = -9223372036854775807L;
                                } else {
                                    if (!c2466p0E2.w()) {
                                        throw zzaz.b("Only supports full channel mask-based audio presentation");
                                    }
                                    int i19 = iB2 - 1;
                                    int i20 = bArr[i19] << 8;
                                    int i21 = bArr[iB2] & 255;
                                    String str = Yo.a;
                                    char c2 = 65535;
                                    for (int i22 = 0; i22 < i19; i22++) {
                                        byte b4 = bArr[i22];
                                        int[] iArr = Yo.h;
                                        char c3 = (char) (iArr[(c2 >> '\f') ^ ((b4 & 255) >> 4)] ^ ((char) (c2 << 4)));
                                        c2 = (char) (((char) (c3 << 4)) ^ iArr[(b4 & 15) ^ (c3 >> '\f')]);
                                    }
                                    if ((((char) i20) | i21) != c2) {
                                        throw zzaz.a(null, "CRC check failed");
                                    }
                                    int iF5 = c2466p0E2.f(2);
                                    if (iF5 != 0) {
                                        if (iF5 == 1) {
                                            i8 = DtbConstants.DEFAULT_PLAYER_HEIGHT;
                                        } else {
                                            if (iF5 != 2) {
                                                throw zzaz.a(null, "Unsupported base duration index in DTS UHD header: " + iF5);
                                            }
                                            i8 = 384;
                                        }
                                        i7 = 3;
                                    } else {
                                        i7 = 3;
                                        i8 = com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
                                    }
                                    int iF6 = c2466p0E2.f(i7) + 1;
                                    int iF7 = c2466p0E2.f(2);
                                    if (iF7 == 0) {
                                        i9 = 32000;
                                    } else if (iF7 == 1) {
                                        i9 = 44100;
                                    } else {
                                        if (iF7 != 2) {
                                            throw zzaz.a(null, "Unsupported clock rate index in DTS UHD header: " + iF7);
                                        }
                                        i9 = 48000;
                                    }
                                    if (c2466p0E2.w()) {
                                        c2466p0E2.u(36);
                                    }
                                    iF3 = i9 * (1 << c2466p0E2.f(2));
                                    jV = Yo.v(i8 * iF6, 1000000L, i9, RoundingMode.DOWN);
                                }
                                int i23 = iF3;
                                int iB3 = 0;
                                for (char c4 = 0; c4 < c; c4 = 1) {
                                    iB3 += LA.B(c2466p0E2, LA.f);
                                }
                                for (int i24 = 0; i24 <= 0; i24++) {
                                    if (c != 0) {
                                        atomicInteger.set(LA.B(c2466p0E2, LA.g));
                                    }
                                    iB3 += atomicInteger.get() != 0 ? LA.B(c2466p0E2, LA.h) : 0;
                                }
                                int i25 = i18 + iB3;
                                F f = new F(2, i23, i25, jV, "audio/vnd.dts.uhd;profile=p2");
                                if (this.n == 3) {
                                    b(f);
                                }
                                this.m = i25;
                                this.k = jV == -9223372036854775807L ? 0L : jV;
                                kn2.j(0);
                                this.g.e(this.p, kn2);
                                this.h = 6;
                            } else {
                                continue;
                            }
                            i12 = i6;
                        } else {
                            int i26 = i12;
                            if (c(kn, kn2.a, this.o)) {
                                C2466p0 c2466p0E3 = LA.E(kn2.a);
                                c2466p0E3.u(40);
                                int iF8 = c2466p0E3.f(2);
                                boolean zW = c2466p0E3.w();
                                int i27 = true != zW ? 16 : 20;
                                c2466p0E3.u(true != zW ? 8 : 12);
                                int iF9 = c2466p0E3.f(i27) + 1;
                                boolean zW2 = c2466p0E3.w();
                                if (zW2) {
                                    iF = c2466p0E3.f(2);
                                    int iF10 = c2466p0E3.f(3) + 1;
                                    if (c2466p0E3.w()) {
                                        c2466p0E3.u(36);
                                    }
                                    int iF11 = c2466p0E3.f(3) + 1;
                                    int iF12 = c2466p0E3.f(3) + 1;
                                    if (iF11 != 1 || iF12 != 1) {
                                        throw zzaz.b("Multiple audio presentations or assets not supported");
                                    }
                                    int i28 = iF8 + 1;
                                    int iF13 = c2466p0E3.f(i28);
                                    int i29 = 0;
                                    while (i29 < i28) {
                                        if (((iF13 >> i29) & 1) == 1) {
                                            c2466p0E3.u(i14);
                                        }
                                        i29++;
                                        i14 = 8;
                                    }
                                    i10 = iF10 * com.google.android.gms.ads.g.MAX_CONTENT_URL_LENGTH;
                                    if (c2466p0E3.w()) {
                                        c2466p0E3.u(2);
                                        int iF14 = (c2466p0E3.f(2) + 1) << 2;
                                        int iF15 = c2466p0E3.f(2) + 1;
                                        for (int i30 = 0; i30 < iF15; i30++) {
                                            c2466p0E3.u(iF14);
                                        }
                                    }
                                } else {
                                    iF = -1;
                                    i10 = 0;
                                }
                                c2466p0E3.u(i27);
                                c2466p0E3.u(12);
                                if (zW2) {
                                    if (c2466p0E3.w()) {
                                        c2466p0E3.u(i26);
                                    }
                                    if (c2466p0E3.w()) {
                                        c2466p0E3.u(24);
                                    }
                                    if (c2466p0E3.w()) {
                                        c2466p0E3.v(c2466p0E3.f(10) + 1);
                                    }
                                    c2466p0E3.u(5);
                                    iF3 = LA.d[c2466p0E3.f(4)];
                                    iF2 = c2466p0E3.f(8) + 1;
                                } else {
                                    iF2 = -1;
                                }
                                int i31 = iF3;
                                if (zW2) {
                                    if (iF == 0) {
                                        i11 = 32000;
                                    } else if (iF == 1) {
                                        i11 = 44100;
                                    } else {
                                        if (iF != 2) {
                                            throw zzaz.a(null, "Unsupported reference clock code in DTS HD header: " + iF);
                                        }
                                        i11 = 48000;
                                    }
                                    jV2 = Yo.v(i10, 1000000L, i11, RoundingMode.DOWN);
                                } else {
                                    jV2 = -9223372036854775807L;
                                }
                                b(new F(iF2, i31, iF9, jV2, "audio/vnd.dts.hd;profile=lbr"));
                                this.m = iF9;
                                this.k = jV2 == -9223372036854775807L ? 0L : jV2;
                                kn2.j(0);
                                this.g.e(this.o, kn2);
                                this.h = 6;
                            }
                        }
                    } else if (c(kn, kn2.a, 7)) {
                        C2466p0 c2466p0E4 = LA.E(kn2.a);
                        c2466p0E4.u(42);
                        this.o = c2466p0E4.f(true != c2466p0E4.w() ? 8 : 12) + 1;
                        this.h = 3;
                    }
                } else if (c(kn, kn2.a, 18)) {
                    byte[] bArr2 = kn2.a;
                    if (this.l == null) {
                        String str2 = this.f;
                        C2466p0 c2466p0E5 = LA.E(bArr2);
                        c2466p0E5.u(60);
                        int i32 = LA.a[c2466p0E5.f(6)];
                        int i33 = LA.b[c2466p0E5.f(4)];
                        int iF16 = c2466p0E5.f(5);
                        int i34 = iF16 >= 29 ? -1 : (LA.c[iF16] * 1000) / 2;
                        c2466p0E5.u(10);
                        int i35 = i32 + (c2466p0E5.f(2) > 0 ? 1 : 0);
                        EF ef = new EF();
                        ef.a = str2;
                        ef.a("video/mp2t");
                        ef.d("audio/vnd.dts");
                        ef.g = i34;
                        ef.B = i35;
                        ef.C = i33;
                        ef.p = null;
                        ef.d = this.c;
                        ef.f = this.d;
                        C1832aG c1832aG = new C1832aG(ef);
                        this.l = c1832aG;
                        this.g.a(c1832aG);
                    }
                    byte b5 = bArr2[0];
                    if (b5 != -2) {
                        if (b5 == -1) {
                            i4 = (bArr2[7] & 3) << 12;
                            i5 = (bArr2[6] & 255) << 4;
                            b3 = bArr2[9];
                        } else if (b5 != 31) {
                            i = (((bArr2[5] & 3) << 12) | ((bArr2[6] & 255) << 4) | ((bArr2[7] & 240) >> 4)) + 1;
                            z = false;
                        } else {
                            i4 = (bArr2[6] & 3) << 12;
                            i5 = (bArr2[7] & 255) << 4;
                            b3 = bArr2[8];
                        }
                        i = (i4 | i5 | ((b3 & 60) >> 2)) + 1;
                        z = true;
                    } else {
                        i = (((bArr2[4] & 3) << 12) | ((bArr2[7] & 255) << 4) | ((bArr2[6] & 240) >> 4)) + 1;
                        z = false;
                    }
                    if (z) {
                        i = (i * 16) / 14;
                    }
                    this.m = i;
                    if (b5 != -2) {
                        if (b5 == -1) {
                            i2 = (bArr2[4] & 7) << 4;
                            b2 = bArr2[7];
                        } else if (b5 != 31) {
                            i2 = (bArr2[4] & 1) << 6;
                            b = bArr2[5];
                        } else {
                            i2 = (bArr2[5] & 7) << 4;
                            b2 = bArr2[6];
                        }
                        i3 = b2 & 60;
                        this.k = AbstractC1981ds.k(Yo.u(this.l.D, (((i3 >> 2) | i2) + 1) * 32));
                        kn2.j(0);
                        this.g.e(18, kn2);
                        this.h = 6;
                    } else {
                        i2 = (bArr2[5] & 1) << 6;
                        b = bArr2[4];
                    }
                    i3 = b & 252;
                    this.k = AbstractC1981ds.k(Yo.u(this.l.D, (((i3 >> 2) | i2) + 1) * 32));
                    kn2.j(0);
                    this.g.e(18, kn2);
                    this.h = 6;
                }
                i12 = 4;
            } else {
                while (kn.s() > 0) {
                    int i36 = this.j << 8;
                    this.j = i36;
                    int iZ = i36 | kn.z();
                    this.j = iZ;
                    int i37 = (iZ == 2147385345 || iZ == -25230976 || iZ == 536864768 || iZ == -14745368) ? 1 : (iZ == 1683496997 || iZ == 622876772) ? 2 : (iZ == 1078008818 || iZ == -233094848) ? 3 : (iZ == 1908687592 || iZ == -398277519) ? 4 : 0;
                    this.n = i37;
                    if (i37 != 0) {
                        byte[] bArr3 = kn2.a;
                        bArr3[0] = (byte) ((iZ >> 24) & 255);
                        bArr3[1] = (byte) ((iZ >> 16) & 255);
                        bArr3[2] = (byte) ((iZ >> 8) & 255);
                        bArr3[3] = (byte) (iZ & 255);
                        this.i = 4;
                        this.j = 0;
                        if (i37 == 3 || i37 == 4) {
                            this.h = 4;
                        } else if (i37 == 1) {
                            this.h = 1;
                        } else {
                            this.h = 2;
                        }
                        i12 = 4;
                    }
                }
                i12 = 4;
            }
        }
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void e(W w, C0591b1 c0591b1) {
        c0591b1.b();
        c0591b1.c();
        this.f = (String) c0591b1.e;
        c0591b1.c();
        this.g = w.q(c0591b1.c, 1);
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void f(int i, long j) {
        this.q = j;
    }

    @Override // com.google.android.gms.internal.ads.N2
    public final void zze() {
        this.h = 0;
        this.i = 0;
        this.j = 0;
        this.q = -9223372036854775807L;
        this.b.set(0);
    }
}
