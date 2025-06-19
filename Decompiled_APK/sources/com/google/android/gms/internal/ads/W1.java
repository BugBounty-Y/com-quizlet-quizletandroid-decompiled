package com.google.android.gms.internal.ads;

import java.util.ArrayList;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class W1 extends U1 {
    public YF n;
    public int o;
    public boolean p;
    public C2034f0 q;
    public C2881yn r;

    @Override // com.google.android.gms.internal.ads.U1
    public final long a(Kn kn) {
        byte b = kn.a[0];
        if ((b & 1) == 1) {
            return -1L;
        }
        YF yf = this.n;
        AbstractC1795We.p(yf);
        boolean z = ((androidx.camera.camera2.internal.compat.workaround.e[]) yf.e)[(b >> 1) & (255 >>> (8 - yf.a))].b;
        C2034f0 c2034f0 = (C2034f0) yf.b;
        int i = !z ? c2034f0.f : c2034f0.g;
        int i2 = this.p ? (this.o + i) / 4 : 0;
        byte[] bArr = kn.a;
        int length = bArr.length;
        int i3 = kn.c + 4;
        if (length < i3) {
            byte[] bArrCopyOf = Arrays.copyOf(bArr, i3);
            kn.h(bArrCopyOf.length, bArrCopyOf);
        } else {
            kn.i(i3);
        }
        long j = i2;
        byte[] bArr2 = kn.a;
        int i4 = kn.c;
        bArr2[i4 - 4] = (byte) (j & 255);
        bArr2[i4 - 3] = (byte) ((j >>> 8) & 255);
        bArr2[i4 - 2] = (byte) ((j >>> 16) & 255);
        bArr2[i4 - 1] = (byte) ((j >>> 24) & 255);
        this.p = true;
        this.o = i;
        return j;
    }

    @Override // com.google.android.gms.internal.ads.U1
    public final void b(boolean z) {
        super.b(z);
        if (z) {
            this.n = null;
            this.q = null;
            this.r = null;
        }
        this.o = 0;
        this.p = false;
    }

    /* JADX WARN: Type inference failed for: r1v48, types: [byte[], java.io.Serializable] */
    @Override // com.google.android.gms.internal.ads.U1
    public final boolean c(Kn kn, long j, Fi fi) throws zzaz {
        YF yf;
        C2034f0 c2034f0;
        int i;
        int i2;
        C2034f0 c2034f02;
        long jFloor;
        if (this.n != null) {
            ((C1832aG) fi.b).getClass();
            return false;
        }
        C2034f0 c2034f03 = this.q;
        int i3 = 1;
        int i4 = 4;
        if (c2034f03 == null) {
            AbstractC2096gb.B(1, kn, false);
            kn.w();
            int iZ = kn.z();
            int iW = kn.w();
            int iV = kn.v();
            if (iV <= 0) {
                iV = -1;
            }
            int iV2 = kn.v();
            int i5 = iV2 <= 0 ? -1 : iV2;
            kn.v();
            int iZ2 = kn.z();
            int iPow = (int) Math.pow(2.0d, iZ2 & 15);
            int iPow2 = (int) Math.pow(2.0d, (iZ2 & 240) >> 4);
            kn.z();
            ?? CopyOf = Arrays.copyOf(kn.a, kn.c);
            C2034f0 c2034f04 = new C2034f0();
            c2034f04.a = iZ;
            c2034f04.b = iW;
            c2034f04.c = iV;
            c2034f04.d = i5;
            c2034f04.f = iPow;
            c2034f04.g = iPow2;
            c2034f04.e = CopyOf;
            this.q = c2034f04;
        } else {
            C2881yn c2881yn = this.r;
            if (c2881yn == null) {
                this.r = AbstractC2096gb.r(kn, true, true);
            } else {
                int i6 = kn.c;
                byte[] bArr = new byte[i6];
                System.arraycopy(kn.a, 0, bArr, 0, i6);
                int i7 = 5;
                AbstractC2096gb.B(5, kn, false);
                int iZ3 = kn.z() + 1;
                C2466p0 c2466p0 = new C2466p0(kn.a);
                int i8 = 8;
                c2466p0.e(kn.b * 8);
                int i9 = 0;
                while (true) {
                    int i10 = 2;
                    int i11 = 16;
                    if (i9 < iZ3) {
                        int i12 = i8;
                        if (c2466p0.d(24) != 5653314) {
                            throw zzaz.a(null, "expected code book to start with [0x56, 0x43, 0x42] at " + ((c2466p0.d * 8) + c2466p0.e));
                        }
                        int iD = c2466p0.d(16);
                        int iD2 = c2466p0.d(24);
                        if (c2466p0.g()) {
                            c2466p0.e(5);
                            for (int iD3 = 0; iD3 < iD2; iD3 += c2466p0.d(AbstractC2096gb.b(iD2 - iD3))) {
                            }
                        } else {
                            boolean zG = c2466p0.g();
                            for (int i13 = 0; i13 < iD2; i13++) {
                                if (!zG) {
                                    c2466p0.e(5);
                                } else if (c2466p0.g()) {
                                    c2466p0.e(5);
                                }
                            }
                        }
                        int iD4 = c2466p0.d(i4);
                        if (iD4 > 2) {
                            throw zzaz.a(null, "lookup type greater than 2 not decodable: " + iD4);
                        }
                        if (iD4 != 1) {
                            if (iD4 != 2) {
                                c2034f02 = c2034f03;
                            }
                            i9++;
                            i8 = i12;
                            c2034f03 = c2034f02;
                            i4 = 4;
                        } else {
                            i10 = iD4;
                        }
                        c2466p0.e(32);
                        c2466p0.e(32);
                        int iD5 = c2466p0.d(i4) + 1;
                        c2466p0.e(1);
                        if (i10 != 1) {
                            c2034f02 = c2034f03;
                            jFloor = iD * iD2;
                        } else if (iD != 0) {
                            c2034f02 = c2034f03;
                            jFloor = (long) Math.floor(Math.pow(iD2, 1.0d / iD));
                        } else {
                            c2034f02 = c2034f03;
                            jFloor = 0;
                        }
                        c2466p0.e((int) (jFloor * iD5));
                        i9++;
                        i8 = i12;
                        c2034f03 = c2034f02;
                        i4 = 4;
                    } else {
                        C2034f0 c2034f05 = c2034f03;
                        int i14 = i8;
                        int i15 = 6;
                        int iD6 = c2466p0.d(6) + 1;
                        for (int i16 = 0; i16 < iD6; i16++) {
                            if (c2466p0.d(16) != 0) {
                                throw zzaz.a(null, "placeholder of time domain transforms not zeroed out");
                            }
                        }
                        int iD7 = c2466p0.d(6) + 1;
                        int i17 = 0;
                        while (true) {
                            int i18 = 3;
                            if (i17 < iD7) {
                                int iD8 = c2466p0.d(i11);
                                if (iD8 == 0) {
                                    int i19 = i14;
                                    i = i3;
                                    c2466p0.e(i19);
                                    c2466p0.e(16);
                                    c2466p0.e(16);
                                    c2466p0.e(6);
                                    c2466p0.e(i19);
                                    int iD9 = c2466p0.d(4) + 1;
                                    int i20 = 0;
                                    while (i20 < iD9) {
                                        c2466p0.e(i19);
                                        i20++;
                                        i19 = 8;
                                    }
                                } else {
                                    if (iD8 != i3) {
                                        throw zzaz.a(null, "floor type greater than 1 not decodable: " + iD8);
                                    }
                                    int iD10 = c2466p0.d(i7);
                                    int[] iArr = new int[iD10];
                                    i = i3;
                                    int i21 = -1;
                                    for (int i22 = 0; i22 < iD10; i22++) {
                                        int iD11 = c2466p0.d(4);
                                        iArr[i22] = iD11;
                                        if (iD11 > i21) {
                                            i21 = iD11;
                                        }
                                    }
                                    int i23 = i21 + 1;
                                    int[] iArr2 = new int[i23];
                                    int i24 = 0;
                                    while (i24 < i23) {
                                        iArr2[i24] = c2466p0.d(i18) + 1;
                                        int iD12 = c2466p0.d(i10);
                                        if (iD12 > 0) {
                                            i2 = i14;
                                            c2466p0.e(i2);
                                        } else {
                                            i2 = i14;
                                        }
                                        int i25 = 0;
                                        while (i25 < (i << iD12)) {
                                            c2466p0.e(i2);
                                            i25++;
                                            i2 = 8;
                                        }
                                        i24++;
                                        i14 = 8;
                                        i10 = 2;
                                        i18 = 3;
                                    }
                                    c2466p0.e(i10);
                                    int iD13 = c2466p0.d(4);
                                    int i26 = 0;
                                    int i27 = 0;
                                    for (int i28 = 0; i28 < iD10; i28++) {
                                        i26 += iArr2[iArr[i28]];
                                        while (i27 < i26) {
                                            c2466p0.e(iD13);
                                            i27++;
                                        }
                                    }
                                }
                                i17++;
                                i3 = i;
                                i14 = 8;
                                i15 = 6;
                                i10 = 2;
                                i11 = 16;
                                i7 = 5;
                            } else {
                                int i29 = i3;
                                int iD14 = c2466p0.d(i15) + 1;
                                int i30 = 0;
                                while (i30 < iD14) {
                                    if (c2466p0.d(16) > 2) {
                                        throw zzaz.a(null, "residueType greater than 2 is not decodable");
                                    }
                                    c2466p0.e(24);
                                    c2466p0.e(24);
                                    c2466p0.e(24);
                                    int iD15 = c2466p0.d(i15) + 1;
                                    int i31 = 8;
                                    c2466p0.e(8);
                                    int[] iArr3 = new int[iD15];
                                    for (int i32 = 0; i32 < iD15; i32++) {
                                        iArr3[i32] = ((c2466p0.g() ? c2466p0.d(5) : 0) * 8) + c2466p0.d(3);
                                    }
                                    int i33 = 0;
                                    while (i33 < iD15) {
                                        int i34 = 0;
                                        while (i34 < i31) {
                                            if ((iArr3[i33] & (i29 << i34)) != 0) {
                                                c2466p0.e(i31);
                                            }
                                            i34++;
                                            i31 = 8;
                                        }
                                        i33++;
                                        i31 = 8;
                                    }
                                    i30++;
                                    i15 = 6;
                                }
                                int iD16 = c2466p0.d(i15) + 1;
                                int i35 = 0;
                                while (i35 < iD16) {
                                    int iD17 = c2466p0.d(16);
                                    if (iD17 != 0) {
                                        AbstractC2096gb.s("VorbisUtil", "mapping type other than 0 not supported: " + iD17);
                                        c2034f0 = c2034f05;
                                    } else {
                                        int iD18 = c2466p0.g() ? c2466p0.d(4) + 1 : i29;
                                        boolean zG2 = c2466p0.g();
                                        c2034f0 = c2034f05;
                                        int i36 = c2034f0.a;
                                        if (zG2) {
                                            int iD19 = c2466p0.d(8) + 1;
                                            for (int i37 = 0; i37 < iD19; i37++) {
                                                int i38 = i36 - 1;
                                                c2466p0.e(AbstractC2096gb.b(i38));
                                                c2466p0.e(AbstractC2096gb.b(i38));
                                            }
                                        }
                                        if (c2466p0.d(2) != 0) {
                                            throw zzaz.a(null, "to reserved bits must be zero after mapping coupling steps");
                                        }
                                        if (iD18 > i29) {
                                            for (int i39 = 0; i39 < i36; i39++) {
                                                c2466p0.e(4);
                                            }
                                        }
                                        for (int i40 = 0; i40 < iD18; i40++) {
                                            c2466p0.e(8);
                                            c2466p0.e(8);
                                            c2466p0.e(8);
                                        }
                                    }
                                    i35++;
                                    c2034f05 = c2034f0;
                                    i29 = 1;
                                }
                                C2034f0 c2034f06 = c2034f05;
                                int iD20 = c2466p0.d(6);
                                int i41 = iD20 + 1;
                                androidx.camera.camera2.internal.compat.workaround.e[] eVarArr = new androidx.camera.camera2.internal.compat.workaround.e[i41];
                                for (int i42 = 0; i42 < i41; i42++) {
                                    boolean zG3 = c2466p0.g();
                                    c2466p0.d(16);
                                    c2466p0.d(16);
                                    c2466p0.d(8);
                                    eVarArr[i42] = new androidx.camera.camera2.internal.compat.workaround.e(zG3, 5);
                                }
                                if (!c2466p0.g()) {
                                    throw zzaz.a(null, "framing bit after modes not set as expected");
                                }
                                yf = new YF(c2034f06, c2881yn, bArr, eVarArr, AbstractC2096gb.b(iD20));
                            }
                        }
                    }
                }
            }
        }
        yf = null;
        this.n = yf;
        if (yf == null) {
            return true;
        }
        ArrayList arrayList = new ArrayList();
        C2034f0 c2034f07 = (C2034f0) yf.b;
        arrayList.add((byte[]) c2034f07.e);
        arrayList.add((byte[]) yf.d);
        K4 k4M = AbstractC2096gb.m(AbstractC2330lu.o((String[]) ((C2881yn) yf.c).b));
        EF ef = new EF();
        ef.a("audio/ogg");
        ef.d("audio/vorbis");
        ef.g = c2034f07.d;
        ef.h = c2034f07.c;
        ef.B = c2034f07.a;
        ef.C = c2034f07.b;
        ef.o = arrayList;
        ef.j = k4M;
        fi.b = new C1832aG(ef);
        return true;
    }

    @Override // com.google.android.gms.internal.ads.U1
    public final void d(long j) {
        this.g = j;
        this.p = j != 0;
        C2034f0 c2034f0 = this.q;
        this.o = c2034f0 != null ? c2034f0.f : 0;
    }
}
