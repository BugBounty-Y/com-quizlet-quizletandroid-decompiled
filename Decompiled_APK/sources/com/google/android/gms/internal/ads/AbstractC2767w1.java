package com.google.android.gms.internal.ads;

import android.util.Pair;
import java.nio.charset.StandardCharsets;

/* renamed from: com.google.android.gms.internal.ads.w1, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public abstract class AbstractC2767w1 {
    public static final byte[] a;

    static {
        String str = Yo.a;
        a = "OpusHead".getBytes(StandardCharsets.UTF_8);
    }

    public static int a(int i) {
        return (i >> 24) & 255;
    }

    public static C2541qq b(Kn kn) {
        long jG;
        long jG2;
        kn.j(8);
        if (a(kn.u()) == 0) {
            jG = kn.H();
            jG2 = kn.H();
        } else {
            jG = kn.G();
            jG2 = kn.G();
        }
        return new C2541qq(jG, jG2, kn.H());
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:118:0x02ff A[ADDED_TO_REGION, LOOP:15: B:118:0x02ff->B:122:0x030a, LOOP_START, PHI: r30
  0x02ff: PHI (r30v2 int) = (r30v1 int), (r30v3 int) binds: [B:117:0x02fd, B:122:0x030a] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:123:0x0310  */
    /* JADX WARN: Removed duplicated region for block: B:125:0x0314  */
    /* JADX WARN: Removed duplicated region for block: B:136:0x036b  */
    /* JADX WARN: Removed duplicated region for block: B:139:0x03b2  */
    /* JADX WARN: Removed duplicated region for block: B:140:0x03b5  */
    /* JADX WARN: Removed duplicated region for block: B:313:0x02ed A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:76:0x0204 A[PHI: r10
  0x0204: PHI (r10v4 int) = (r10v3 int), (r10v3 int), (r10v18 int), (r10v3 int) binds: [B:50:0x0145, B:57:0x015f, B:75:0x0202, B:56:0x015d] A[DONT_GENERATE, DONT_INLINE]] */
    /* JADX WARN: Removed duplicated region for block: B:78:0x022a  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static com.google.android.gms.internal.ads.L1 c(com.google.android.gms.internal.ads.I1 r45, com.google.android.gms.internal.ads.C2840xp r46, com.google.android.gms.internal.ads.C1860b0 r47) throws com.google.android.gms.internal.ads.zzaz {
        /*
            Method dump skipped, instructions count: 1779
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2767w1.c(com.google.android.gms.internal.ads.I1, com.google.android.gms.internal.ads.xp, com.google.android.gms.internal.ads.b0):com.google.android.gms.internal.ads.L1");
    }

    /* JADX WARN: Code restructure failed: missing block: B:46:0x0111, code lost:
    
        r8 = -9223372036854775807L;
     */
    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Removed duplicated region for block: B:107:0x023c  */
    /* JADX WARN: Removed duplicated region for block: B:116:0x0259  */
    /* JADX WARN: Removed duplicated region for block: B:450:0x0973  */
    /* JADX WARN: Removed duplicated region for block: B:456:0x0981  */
    /* JADX WARN: Removed duplicated region for block: B:458:0x0986  */
    /* JADX WARN: Removed duplicated region for block: B:461:0x099a  */
    /* JADX WARN: Removed duplicated region for block: B:463:0x09bc  */
    /* JADX WARN: Removed duplicated region for block: B:503:0x0aa6  */
    /* JADX WARN: Removed duplicated region for block: B:506:0x0ab3  */
    /* JADX WARN: Removed duplicated region for block: B:508:0x0ab9  */
    /* JADX WARN: Removed duplicated region for block: B:510:0x0abc  */
    /* JADX WARN: Removed duplicated region for block: B:513:0x0ac4  */
    /* JADX WARN: Removed duplicated region for block: B:516:0x0acb  */
    /* JADX WARN: Removed duplicated region for block: B:531:0x0afb  */
    /* JADX WARN: Removed duplicated region for block: B:532:0x0afd  */
    /* JADX WARN: Removed duplicated region for block: B:534:0x0b0b  */
    /* JADX WARN: Removed duplicated region for block: B:60:0x0157  */
    /* JADX WARN: Removed duplicated region for block: B:635:0x0e27  */
    /* JADX WARN: Removed duplicated region for block: B:636:0x0e29  */
    /* JADX WARN: Removed duplicated region for block: B:68:0x0167  */
    /* JADX WARN: Removed duplicated region for block: B:693:0x1005  */
    /* JADX WARN: Removed duplicated region for block: B:694:0x100b  */
    /* JADX WARN: Removed duplicated region for block: B:715:0x10aa A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:721:0x0212 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:74:0x0175  */
    /* JADX WARN: Removed duplicated region for block: B:77:0x017b  */
    /* JADX WARN: Removed duplicated region for block: B:78:0x017e  */
    /* JADX WARN: Removed duplicated region for block: B:81:0x018c  */
    /* JADX WARN: Removed duplicated region for block: B:83:0x0194  */
    /* JADX WARN: Removed duplicated region for block: B:86:0x01ce  */
    /* JADX WARN: Removed duplicated region for block: B:87:0x01d1  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x01e0  */
    /* JADX WARN: Removed duplicated region for block: B:91:0x01e2  */
    /* JADX WARN: Removed duplicated region for block: B:93:0x01e6  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static java.util.ArrayList d(com.google.android.gms.internal.ads.C2840xp r91, com.google.android.gms.internal.ads.C1860b0 r92, long r93, com.google.android.gms.internal.ads.zzs r95, boolean r96, boolean r97, com.google.android.gms.internal.ads.InterfaceC2544qt r98) {
        /*
            Method dump skipped, instructions count: 4276
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2767w1.d(com.google.android.gms.internal.ads.xp, com.google.android.gms.internal.ads.b0, long, com.google.android.gms.internal.ads.zzs, boolean, boolean, com.google.android.gms.internal.ads.qt):java.util.ArrayList");
    }

    public static int e(Kn kn) {
        int iZ = kn.z();
        int i = iZ & 127;
        while ((iZ & 128) == 128) {
            iZ = kn.z();
            i = (i << 7) | (iZ & 127);
        }
        return i;
    }

    public static Pair f(Kn kn, int i, int i2) throws zzaz {
        Integer num;
        J1 j1;
        Pair pairCreate;
        int i3;
        int i4;
        Integer num2;
        boolean z;
        int i5 = kn.b;
        while (i5 - i < i2) {
            kn.j(i5);
            int iU = kn.u();
            AbstractC2096gb.q("childAtomSize must be positive", iU > 0);
            if (kn.u() == 1936289382) {
                int i6 = i5 + 8;
                int i7 = 0;
                int i8 = -1;
                Integer numValueOf = null;
                String strB = null;
                while (i6 - i5 < iU) {
                    kn.j(i6);
                    int iU2 = kn.u();
                    int iU3 = kn.u();
                    if (iU3 == 1718775137) {
                        numValueOf = Integer.valueOf(kn.u());
                    } else if (iU3 == 1935894637) {
                        kn.k(4);
                        strB = kn.b(4, StandardCharsets.UTF_8);
                    } else if (iU3 == 1935894633) {
                        i8 = i6;
                        i7 = iU2;
                    }
                    i6 += iU2;
                }
                byte[] bArr = null;
                if ("cenc".equals(strB) || "cbc1".equals(strB) || "cens".equals(strB) || "cbcs".equals(strB)) {
                    AbstractC2096gb.q("frma atom is mandatory", numValueOf != null);
                    AbstractC2096gb.q("schi atom is mandatory", i8 != -1);
                    int i9 = i8 + 8;
                    while (true) {
                        if (i9 - i8 >= i7) {
                            num = numValueOf;
                            j1 = null;
                            break;
                        }
                        kn.j(i9);
                        int iU4 = kn.u();
                        if (kn.u() == 1952804451) {
                            int iA = a(kn.u());
                            kn.k(1);
                            if (iA == 0) {
                                kn.k(1);
                                i4 = 0;
                                i3 = 0;
                            } else {
                                int iZ = kn.z();
                                i3 = iZ & 15;
                                i4 = (iZ & 240) >> 4;
                            }
                            if (kn.z() == 1) {
                                num2 = numValueOf;
                                z = true;
                            } else {
                                num2 = numValueOf;
                                z = false;
                            }
                            int iZ2 = kn.z();
                            byte[] bArr2 = new byte[16];
                            kn.f(0, bArr2, 16);
                            if (z && iZ2 == 0) {
                                int iZ3 = kn.z();
                                byte[] bArr3 = new byte[iZ3];
                                kn.f(0, bArr3, iZ3);
                                bArr = bArr3;
                            }
                            num = num2;
                            j1 = new J1(z, strB, iZ2, bArr2, i4, i3, bArr);
                        } else {
                            i9 += iU4;
                        }
                    }
                    AbstractC2096gb.q("tenc atom is mandatory", j1 != null);
                    String str = Yo.a;
                    pairCreate = Pair.create(num, j1);
                } else {
                    pairCreate = null;
                }
                if (pairCreate != null) {
                    return pairCreate;
                }
            }
            i5 += iU;
        }
        return null;
    }

    public static androidx.compose.foundation.lazy.layout.p0 g(int i, Kn kn) {
        kn.j(i + 12);
        kn.k(1);
        e(kn);
        kn.k(2);
        int iZ = kn.z();
        if ((iZ & 128) != 0) {
            kn.k(2);
        }
        if ((iZ & 64) != 0) {
            kn.k(kn.z());
        }
        if ((iZ & 32) != 0) {
            kn.k(2);
        }
        kn.k(1);
        e(kn);
        String strD = AbstractC2514q5.d(kn.z());
        if ("audio/mpeg".equals(strD) || "audio/vnd.dts".equals(strD) || "audio/vnd.dts.hd".equals(strD)) {
            return new androidx.compose.foundation.lazy.layout.p0(strD, null, -1L, -1L);
        }
        kn.k(4);
        long jH = kn.H();
        long jH2 = kn.H();
        kn.k(1);
        int iE = e(kn);
        long j = jH2;
        byte[] bArr = new byte[iE];
        kn.f(0, bArr, iE);
        if (j <= 0) {
            j = -1;
        }
        return new androidx.compose.foundation.lazy.layout.p0(strD, bArr, j, jH > 0 ? jH : -1L);
    }

    /* JADX WARN: Removed duplicated region for block: B:208:0x0465  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0089  */
    /* JADX WARN: Removed duplicated region for block: B:301:0x0645  */
    /* JADX WARN: Removed duplicated region for block: B:359:0x06f4  */
    /* JADX WARN: Removed duplicated region for block: B:362:0x06ff A[LOOP:5: B:361:0x06fd->B:362:0x06ff, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:365:0x070d  */
    /* JADX WARN: Removed duplicated region for block: B:383:0x075b  */
    /* JADX WARN: Removed duplicated region for block: B:386:0x0763  */
    /* JADX WARN: Removed duplicated region for block: B:401:0x07a1  */
    /* JADX WARN: Removed duplicated region for block: B:433:0x0804  */
    /* JADX WARN: Removed duplicated region for block: B:439:0x0818  */
    /* JADX WARN: Removed duplicated region for block: B:529:0x0868 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:84:0x0162  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void h(com.google.android.gms.internal.ads.Kn r49, int r50, int r51, int r52, int r53, java.lang.String r54, boolean r55, com.google.android.gms.internal.ads.zzs r56, androidx.compose.ui.text.android.selection.f r57, int r58) throws com.google.android.gms.internal.ads.zzaz {
        /*
            Method dump skipped, instructions count: 2980
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.AbstractC2767w1.h(com.google.android.gms.internal.ads.Kn, int, int, int, int, java.lang.String, boolean, com.google.android.gms.internal.ads.zzs, androidx.compose.ui.text.android.selection.f, int):void");
    }
}
