package com.google.android.gms.internal.ads;

import androidx.compose.material3.C0591b1;
import com.google.android.gms.ads.nonagon.signalgeneration.AbstractC1642h;

/* renamed from: com.google.android.gms.internal.ads.b3, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C1863b3 implements InterfaceC2211j3 {
    public final N2 a;
    public final C2466p0 b = new C2466p0(10, new byte[10]);
    public int c = 0;
    public int d;
    public Eo e;
    public boolean f;
    public boolean g;
    public boolean h;
    public int i;
    public int j;
    public boolean k;

    public C1863b3(N2 n2) {
        this.a = n2;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2211j3
    public final void a() {
        this.c = 0;
        this.d = 0;
        this.h = false;
        this.a.zze();
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v0, types: [com.google.android.gms.internal.ads.p0] */
    /* JADX WARN: Type inference failed for: r3v0, types: [com.google.android.gms.internal.ads.N2] */
    /* JADX WARN: Type inference failed for: r8v0 */
    /* JADX WARN: Type inference failed for: r8v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r8v15 */
    /* JADX WARN: Type inference failed for: r8v4 */
    /* JADX WARN: Type inference failed for: r8v5 */
    @Override // com.google.android.gms.internal.ads.InterfaceC2211j3
    public final void b(int i, Kn kn) {
        int i2;
        int i3;
        int i4;
        int i5;
        long jB;
        long j;
        int i6;
        AbstractC1795We.p(this.e);
        int i7 = i & 1;
        ?? r3 = this.a;
        int i8 = -1;
        int i9 = 2;
        ?? r8 = 0;
        if (i7 != 0) {
            int i10 = this.c;
            if (i10 != 0 && i10 != 1) {
                if (i10 != 2) {
                    int i11 = this.j;
                    if (i11 != -1) {
                        AbstractC2096gb.J("PesReader", "Unexpected start indicator: expected " + i11 + " more bytes");
                    }
                    r3.a(kn.c == 0);
                } else {
                    AbstractC2096gb.J("PesReader", "Unexpected start indicator reading extended header");
                }
            }
            this.c = 1;
            this.d = 0;
        }
        int i12 = i;
        while (kn.s() > 0) {
            int i13 = this.c;
            if (i13 != 0) {
                ?? r10 = this.b;
                if (i13 != 1) {
                    if (i13 != i9) {
                        int iS = kn.s();
                        int i14 = this.j;
                        int i15 = i14 == i8 ? r8 : iS - i14;
                        if (i15 > 0) {
                            iS -= i15;
                            kn.i(kn.b + iS);
                        }
                        r3.d(kn);
                        int i16 = this.j;
                        if (i16 != i8) {
                            int i17 = i16 - iS;
                            this.j = i17;
                            if (i17 == 0) {
                                r3.a(r8);
                                this.c = 1;
                                this.d = r8;
                            }
                        }
                    } else {
                        if (c(kn, r10.b, Math.min(10, this.i)) && c(kn, null, this.i)) {
                            r10.s(r8);
                            if (this.f) {
                                r10.u(4);
                                long jF = r10.f(3);
                                r10.u(1);
                                int iF = r10.f(15) << 15;
                                r10.u(1);
                                long jF2 = r10.f(15);
                                r10.u(1);
                                if (this.h || !this.g) {
                                    j = jF;
                                    i6 = iF;
                                } else {
                                    r10.u(4);
                                    j = jF;
                                    r10.u(1);
                                    int iF2 = r10.f(15) << 15;
                                    r10.u(1);
                                    long jF3 = r10.f(15);
                                    r10.u(1);
                                    i6 = iF;
                                    this.e.b((r10.f(3) << 30) | iF2 | jF3);
                                    this.h = true;
                                }
                                jB = this.e.b(jF2 | (j << 30) | i6);
                            } else {
                                jB = -9223372036854775807L;
                            }
                            i12 |= true != this.k ? 0 : 4;
                            r3.f(i12, jB);
                            this.c = 3;
                            this.d = 0;
                            r8 = 0;
                            i8 = -1;
                            i9 = 2;
                        }
                    }
                    i2 = i8;
                    i3 = r8;
                    i4 = i9;
                } else {
                    i3 = r8;
                    if (c(kn, r10.b, 9)) {
                        r10.s(i3);
                        int iF3 = r10.f(24);
                        if (iF3 != 1) {
                            AbstractC1642h.s(iF3, "Unexpected start code prefix: ", "PesReader");
                            this.j = -1;
                            i2 = -1;
                            i5 = 0;
                            i4 = 2;
                        } else {
                            r10.u(8);
                            int iF4 = r10.f(16);
                            r10.u(5);
                            this.k = r10.w();
                            i4 = 2;
                            r10.u(2);
                            this.f = r10.w();
                            this.g = r10.w();
                            r10.u(6);
                            int iF5 = r10.f(8);
                            this.i = iF5;
                            i2 = -1;
                            if (iF4 == 0) {
                                this.j = -1;
                            } else {
                                int i18 = (iF4 - 3) - iF5;
                                this.j = i18;
                                if (i18 < 0) {
                                    AbstractC1642h.s(i18, "Found negative packet payload size: ", "PesReader");
                                    this.j = -1;
                                }
                            }
                            i5 = 2;
                        }
                        this.c = i5;
                        i3 = 0;
                        this.d = 0;
                    } else {
                        i4 = 2;
                        i2 = -1;
                    }
                }
            } else {
                i2 = i8;
                i3 = r8;
                i4 = i9;
                kn.k(kn.s());
            }
            i9 = i4;
            r8 = i3;
            i8 = i2;
        }
    }

    public final boolean c(Kn kn, byte[] bArr, int i) {
        int iMin = Math.min(kn.s(), i - this.d);
        if (iMin <= 0) {
            return true;
        }
        if (bArr == null) {
            kn.k(iMin);
        } else {
            kn.f(this.d, bArr, iMin);
        }
        int i2 = this.d + iMin;
        this.d = i2;
        return i2 == i;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC2211j3
    public final void e(Eo eo, W w, C0591b1 c0591b1) {
        this.e = eo;
        this.a.e(w, c0591b1);
    }
}
