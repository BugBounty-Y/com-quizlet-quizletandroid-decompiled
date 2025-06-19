package com.google.android.gms.internal.ads;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff;
import android.graphics.PorterDuffXfermode;
import android.os.RemoteException;
import android.util.SparseArray;
import android.webkit.WebView;
import androidx.camera.core.impl.C0186z;
import com.google.android.gms.ads.internal.client.C1596h;
import com.google.android.gms.ads.internal.client.C1608n;
import com.google.android.gms.ads.internal.client.C1614q;
import com.skydoves.balloon.internals.DefinitionKt;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

/* renamed from: com.google.android.gms.internal.ads.j2, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2210j2 implements InterfaceC1818a2 {
    public static final byte[] h = {0, 7, 8, 15};
    public static final byte[] i = {0, 119, -120, -1};
    public static final byte[] j = {0, 17, 34, 51, 68, 85, 102, 119, -120, -103, -86, -69, -52, -35, -18, -1};
    public Object a;
    public Object b;
    public Object c;
    public Object d;
    public Object e;
    public final Object f;
    public Object g;

    public C2210j2() {
        this.f = new androidx.collection.V(0);
        this.g = new androidx.collection.V(0);
    }

    public static int c(int i2, int i3, int i4, int i5) {
        return (i2 << 24) | (i3 << 16) | (i4 << 8) | i5;
    }

    public static C1905c2 d(C2466p0 c2466p0, int i2) {
        int iF;
        int iF2;
        int iF3;
        int iF4;
        int i3 = 8;
        int iF5 = c2466p0.f(8);
        c2466p0.u(8);
        int i4 = 0;
        int[] iArr = {0, -1, -16777216, -8421505};
        int[] iArrH = h();
        int[] iArrI = i();
        int i5 = i2 - 2;
        while (i5 > 0) {
            int iF6 = c2466p0.f(i3);
            int iF7 = c2466p0.f(i3);
            int[] iArr2 = (iF7 & 128) != 0 ? iArr : (iF7 & 64) != 0 ? iArrH : iArrI;
            if ((iF7 & 1) != 0) {
                iF3 = c2466p0.f(i3);
                iF4 = c2466p0.f(i3);
                iF = c2466p0.f(i3);
                iF2 = c2466p0.f(i3);
                i5 -= 6;
            } else {
                int iF8 = c2466p0.f(6) << 2;
                int iF9 = c2466p0.f(4) << 4;
                i5 -= 4;
                iF = c2466p0.f(4) << 4;
                iF2 = c2466p0.f(2) << 6;
                iF3 = iF8;
                iF4 = iF9;
            }
            if (iF3 == 0) {
                iF2 = 255;
            }
            if (iF3 == 0) {
                iF = i4;
            }
            if (iF3 == 0) {
                iF4 = i4;
            }
            double d = iF3;
            String str = Yo.a;
            double d2 = iF4 - 128;
            double d3 = iF - 128;
            iArr2[iF6] = c((byte) (255 - (iF2 & 255)), Math.max(0, Math.min((int) ((1.402d * d2) + d), 255)), Math.max(0, Math.min((int) ((d - (0.34414d * d3)) - (d2 * 0.71414d)), 255)), Math.max(0, Math.min((int) ((d3 * 1.772d) + d), 255)));
            i4 = 0;
            iF5 = iF5;
            iArrI = iArrI;
            i3 = 8;
        }
        return new C1905c2(iF5, iArr, iArrH, iArrI);
    }

    public static C1992e2 e(C2466p0 c2466p0) {
        byte[] bArr;
        int iF = c2466p0.f(16);
        c2466p0.u(4);
        int iF2 = c2466p0.f(2);
        boolean zW = c2466p0.w();
        c2466p0.u(1);
        byte[] bArr2 = Yo.b;
        if (iF2 != 1) {
            if (iF2 == 0) {
                int iF3 = c2466p0.f(16);
                int iF4 = c2466p0.f(16);
                if (iF3 > 0) {
                    bArr2 = new byte[iF3];
                    AbstractC1795We.L(c2466p0.d == 0);
                    System.arraycopy(c2466p0.b, c2466p0.c, bArr2, 0, iF3);
                    c2466p0.c += iF3;
                    c2466p0.x();
                }
                if (iF4 > 0) {
                    bArr = new byte[iF4];
                    AbstractC1795We.L(c2466p0.d == 0);
                    System.arraycopy(c2466p0.b, c2466p0.c, bArr, 0, iF4);
                    c2466p0.c += iF4;
                    c2466p0.x();
                }
            }
            return new C1992e2(iF, zW, bArr2, bArr);
        }
        c2466p0.u(c2466p0.f(8) * 16);
        bArr = bArr2;
        return new C1992e2(iF, zW, bArr2, bArr);
    }

    /* JADX WARN: Removed duplicated region for block: B:108:0x01d3 A[ADDED_TO_REGION] */
    /* JADX WARN: Removed duplicated region for block: B:113:0x01f0  */
    /* JADX WARN: Removed duplicated region for block: B:118:0x01ff A[LOOP:3: B:86:0x0164->B:118:0x01ff, LOOP_END] */
    /* JADX WARN: Removed duplicated region for block: B:140:0x01f8 A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:88:0x016a  */
    /* JADX WARN: Removed duplicated region for block: B:90:0x0172  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public static void f(byte[] r22, int[] r23, int r24, int r25, int r26, android.graphics.Paint r27, android.graphics.Canvas r28) {
        /*
            Method dump skipped, instructions count: 544
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.C2210j2.f(byte[], int[], int, int, int, android.graphics.Paint, android.graphics.Canvas):void");
    }

    public static byte[] g(int i2, int i3, C2466p0 c2466p0) {
        byte[] bArr = new byte[i2];
        for (int i4 = 0; i4 < i2; i4++) {
            bArr[i4] = (byte) c2466p0.f(i3);
        }
        return bArr;
    }

    public static int[] h() {
        int[] iArr = new int[16];
        iArr[0] = 0;
        for (int i2 = 1; i2 < 16; i2++) {
            int i3 = i2 & 4;
            int i4 = i2 & 2;
            int i5 = i2 & 1;
            if (i2 < 8) {
                iArr[i2] = c(255, 1 != i5 ? 0 : 255, i4 != 0 ? 255 : 0, i3 != 0 ? 255 : 0);
            } else {
                iArr[i2] = c(255, 1 != i5 ? 0 : 127, i4 != 0 ? 127 : 0, i3 == 0 ? 0 : 127);
            }
        }
        return iArr;
    }

    public static int[] i() {
        int[] iArr = new int[256];
        iArr[0] = 0;
        for (int i2 = 0; i2 < 256; i2++) {
            if (i2 < 8) {
                iArr[i2] = c(63, 1 != (i2 & 1) ? 0 : 255, (i2 & 2) != 0 ? 255 : 0, (i2 & 4) == 0 ? 0 : 255);
            } else {
                int i3 = i2 & 136;
                if (i3 == 0) {
                    iArr[i2] = c(255, (1 != (i2 & 1) ? 0 : 85) + ((i2 & 16) != 0 ? 170 : 0), ((i2 & 2) != 0 ? 85 : 0) + ((i2 & 32) != 0 ? 170 : 0), ((i2 & 4) == 0 ? 0 : 85) + ((i2 & 64) == 0 ? 0 : 170));
                } else if (i3 == 8) {
                    iArr[i2] = c(127, (1 != (i2 & 1) ? 0 : 85) + ((i2 & 16) != 0 ? 170 : 0), ((i2 & 2) != 0 ? 85 : 0) + ((i2 & 32) != 0 ? 170 : 0), ((i2 & 4) == 0 ? 0 : 85) + ((i2 & 64) == 0 ? 0 : 170));
                } else if (i3 == 128) {
                    iArr[i2] = c(255, (1 != (i2 & 1) ? 0 : 43) + 127 + ((i2 & 16) != 0 ? 85 : 0), ((i2 & 2) != 0 ? 43 : 0) + 127 + ((i2 & 32) != 0 ? 85 : 0), ((i2 & 4) == 0 ? 0 : 43) + 127 + ((i2 & 64) == 0 ? 0 : 85));
                } else if (i3 == 136) {
                    iArr[i2] = c(255, (1 != (i2 & 1) ? 0 : 43) + ((i2 & 16) != 0 ? 85 : 0), ((i2 & 2) != 0 ? 43 : 0) + ((i2 & 32) != 0 ? 85 : 0), ((i2 & 4) == 0 ? 0 : 43) + ((i2 & 64) == 0 ? 0 : 85));
                }
            }
        }
        return iArr;
    }

    @Override // com.google.android.gms.internal.ads.InterfaceC1818a2
    public void a(byte[] bArr, int i2, int i3, C0186z c0186z) {
        C2168i2 c2168i2;
        X1 x1;
        char c;
        char c2;
        char c3;
        int i4;
        C1949d2 c1949d2;
        ArrayList arrayList;
        C2168i2 c2168i22;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        C2080g2 c2080g2;
        int i10;
        int iF;
        int i11;
        int i12;
        boolean z = true;
        C2466p0 c2466p0 = new C2466p0(i2 + i3, bArr);
        c2466p0.s(i2);
        while (true) {
            int iA = c2466p0.a();
            c2168i2 = (C2168i2) this.f;
            if (iA >= 48 && c2466p0.f(8) == 15) {
                int iF2 = c2466p0.f(8);
                int iF3 = c2466p0.f(16);
                int iF4 = c2466p0.f(16);
                int iC = c2466p0.c() + iF4;
                if (iF4 * 8 > c2466p0.a()) {
                    AbstractC2096gb.J("DvbParser", "Data field length exceeds limit");
                    c2466p0.u(c2466p0.a());
                } else {
                    switch (iF2) {
                        case 16:
                            if (iF3 == c2168i2.a) {
                                C2338m1 c2338m1 = c2168i2.i;
                                c2466p0.f(8);
                                int iF5 = c2466p0.f(4);
                                int iF6 = c2466p0.f(2);
                                c2466p0.u(2);
                                SparseArray sparseArray = new SparseArray();
                                for (int i13 = iF4 - 2; i13 > 0; i13 -= 6) {
                                    int iF7 = c2466p0.f(8);
                                    c2466p0.u(8);
                                    sparseArray.put(iF7, new C2036f2(c2466p0.f(16), c2466p0.f(16)));
                                }
                                C2338m1 c2338m12 = new C2338m1();
                                c2338m12.a = iF5;
                                c2338m12.b = iF6;
                                c2338m12.c = sparseArray;
                                if (iF6 != 0) {
                                    c2168i2.i = c2338m12;
                                    c2168i2.c.clear();
                                    c2168i2.d.clear();
                                    c2168i2.e.clear();
                                    break;
                                } else if (c2338m1 != null && c2338m1.a != iF5) {
                                    c2168i2.i = c2338m12;
                                    break;
                                }
                            }
                            break;
                        case 17:
                            C2338m1 c2338m13 = c2168i2.i;
                            if (iF3 == c2168i2.a && c2338m13 != null) {
                                int iF8 = c2466p0.f(8);
                                c2466p0.u(4);
                                boolean zW = c2466p0.w();
                                c2466p0.u(3);
                                int iF9 = c2466p0.f(16);
                                int iF10 = c2466p0.f(16);
                                c2466p0.f(3);
                                int iF11 = c2466p0.f(3);
                                c2466p0.u(2);
                                int iF12 = c2466p0.f(8);
                                int iF13 = c2466p0.f(8);
                                int iF14 = c2466p0.f(4);
                                int iF15 = c2466p0.f(2);
                                c2466p0.u(2);
                                int i14 = iF4 - 10;
                                SparseArray sparseArray2 = new SparseArray();
                                while (i14 > 0) {
                                    int iF16 = c2466p0.f(16);
                                    int iF17 = c2466p0.f(2);
                                    c2466p0.f(2);
                                    int iF18 = c2466p0.f(12);
                                    c2466p0.u(4);
                                    int iF19 = c2466p0.f(12);
                                    int i15 = i14 - 6;
                                    if (iF17 == 1 || iF17 == 2) {
                                        c2466p0.f(8);
                                        c2466p0.f(8);
                                        i14 -= 8;
                                    } else {
                                        i14 = i15;
                                    }
                                    sparseArray2.put(iF16, new C2124h2(iF18, iF19));
                                }
                                C2080g2 c2080g22 = new C2080g2(iF8, zW, iF9, iF10, iF11, iF12, iF13, iF14, iF15, sparseArray2);
                                SparseArray sparseArray3 = c2168i2.c;
                                if (c2338m13.b == 0 && (c2080g2 = (C2080g2) sparseArray3.get(iF8)) != null) {
                                    int i16 = 0;
                                    while (true) {
                                        SparseArray sparseArray4 = c2080g2.j;
                                        if (i16 < sparseArray4.size()) {
                                            c2080g22.j.put(sparseArray4.keyAt(i16), (C2124h2) sparseArray4.valueAt(i16));
                                            i16++;
                                        }
                                    }
                                }
                                sparseArray3.put(c2080g22.a, c2080g22);
                                break;
                            }
                            break;
                        case 18:
                            if (iF3 == c2168i2.a) {
                                C1905c2 c1905c2D = d(c2466p0, iF4);
                                c2168i2.d.put(c1905c2D.a, c1905c2D);
                                break;
                            } else if (iF3 == c2168i2.b) {
                                C1905c2 c1905c2D2 = d(c2466p0, iF4);
                                c2168i2.f.put(c1905c2D2.a, c1905c2D2);
                                break;
                            }
                            break;
                        case 19:
                            if (iF3 == c2168i2.a) {
                                C1992e2 c1992e2E = e(c2466p0);
                                c2168i2.e.put(c1992e2E.a, c1992e2E);
                                break;
                            } else if (iF3 == c2168i2.b) {
                                C1992e2 c1992e2E2 = e(c2466p0);
                                c2168i2.g.put(c1992e2E2.a, c1992e2E2);
                                break;
                            }
                            break;
                        case 20:
                            if (iF3 == c2168i2.a) {
                                c2466p0.u(4);
                                boolean zW2 = c2466p0.w();
                                c2466p0.u(3);
                                int iF20 = c2466p0.f(16);
                                int iF21 = c2466p0.f(16);
                                if (zW2) {
                                    int iF22 = c2466p0.f(16);
                                    int iF23 = c2466p0.f(16);
                                    int iF24 = c2466p0.f(16);
                                    i10 = iF23;
                                    iF = c2466p0.f(16);
                                    i12 = iF24;
                                    i11 = iF22;
                                } else {
                                    i10 = iF20;
                                    iF = iF21;
                                    i11 = 0;
                                    i12 = 0;
                                }
                                c2168i2.h = new C1949d2(iF20, iF21, i11, i10, i12, iF);
                                break;
                            }
                            break;
                    }
                    c2466p0.v(iC - c2466p0.c());
                }
            }
        }
        C2338m1 c2338m14 = c2168i2.i;
        if (c2338m14 == null) {
            C2244ju c2244ju = AbstractC2330lu.b;
            x1 = new X1(Bu.e, -9223372036854775807L, -9223372036854775807L);
        } else {
            C1949d2 c1949d22 = c2168i2.h;
            if (c1949d22 == null) {
                c1949d22 = (C1949d2) this.d;
            }
            Bitmap bitmap = (Bitmap) this.g;
            Canvas canvas = (Canvas) this.c;
            if (bitmap == null || c1949d22.a + 1 != bitmap.getWidth() || c1949d22.b + 1 != ((Bitmap) this.g).getHeight()) {
                Bitmap bitmapCreateBitmap = Bitmap.createBitmap(c1949d22.a + 1, c1949d22.b + 1, Bitmap.Config.ARGB_8888);
                this.g = bitmapCreateBitmap;
                canvas.setBitmap(bitmapCreateBitmap);
            }
            ArrayList arrayList2 = new ArrayList();
            int i17 = 0;
            while (true) {
                SparseArray sparseArray5 = (SparseArray) c2338m14.c;
                if (i17 < sparseArray5.size()) {
                    canvas.save();
                    C2036f2 c2036f2 = (C2036f2) sparseArray5.valueAt(i17);
                    C2080g2 c2080g23 = (C2080g2) c2168i2.c.get(sparseArray5.keyAt(i17));
                    int i18 = c2036f2.a + c1949d22.c;
                    int i19 = c2036f2.b + c1949d22.e;
                    int i20 = c2080g23.c;
                    int i21 = i18 + i20;
                    int iMin = Math.min(i21, c1949d22.d);
                    boolean z2 = z;
                    int i22 = c2080g23.d;
                    int i23 = i19 + i22;
                    canvas.clipRect(i18, i19, iMin, Math.min(i23, c1949d22.f));
                    SparseArray sparseArray6 = c2168i2.d;
                    int i24 = c2080g23.f;
                    C1905c2 c1905c2 = (C1905c2) sparseArray6.get(i24);
                    if (c1905c2 == null && (c1905c2 = (C1905c2) c2168i2.f.get(i24)) == null) {
                        c1905c2 = (C1905c2) this.e;
                    }
                    C2338m1 c2338m15 = c2338m14;
                    int i25 = 0;
                    while (true) {
                        SparseArray sparseArray7 = c2080g23.j;
                        int i26 = i17;
                        if (i25 < sparseArray7.size()) {
                            int iKeyAt = sparseArray7.keyAt(i25);
                            C2124h2 c2124h2 = (C2124h2) sparseArray7.valueAt(i25);
                            Canvas canvas2 = canvas;
                            C1992e2 c1992e2 = (C1992e2) c2168i2.e.get(iKeyAt);
                            if (c1992e2 == null) {
                                c1992e2 = (C1992e2) c2168i2.g.get(iKeyAt);
                            }
                            C1992e2 c1992e22 = c1992e2;
                            if (c1992e22 != null) {
                                Paint paint = c1992e22.b ? null : (Paint) this.a;
                                c2168i22 = c2168i2;
                                int i27 = c2124h2.a + i18;
                                int i28 = c2124h2.b + i19;
                                int i29 = i18;
                                int i30 = c2080g23.e;
                                i9 = i25;
                                Paint paint2 = paint;
                                int i31 = i19;
                                int[] iArr = i30 == 3 ? c1905c2.d : i30 == 2 ? c1905c2.c : c1905c2.b;
                                i6 = i29;
                                arrayList = arrayList2;
                                i7 = i20;
                                i5 = i31;
                                c1949d2 = c1949d22;
                                i8 = i21;
                                f(c1992e22.c, iArr, i30, i27, i28, paint2, canvas2);
                                f(c1992e22.d, iArr, i30, i27, i28 + 1, paint2, canvas2);
                            } else {
                                c1949d2 = c1949d22;
                                arrayList = arrayList2;
                                c2168i22 = c2168i2;
                                i5 = i19;
                                i6 = i18;
                                i7 = i20;
                                i8 = i21;
                                i9 = i25;
                            }
                            i25 = i9 + 1;
                            i18 = i6;
                            i21 = i8;
                            i20 = i7;
                            i19 = i5;
                            canvas = canvas2;
                            i17 = i26;
                            c2168i2 = c2168i22;
                            arrayList2 = arrayList;
                            c1949d22 = c1949d2;
                        } else {
                            C1949d2 c1949d23 = c1949d22;
                            ArrayList arrayList3 = arrayList2;
                            C2168i2 c2168i23 = c2168i2;
                            Canvas canvas3 = canvas;
                            int i32 = i19;
                            int i33 = i18;
                            int i34 = i20;
                            int i35 = i21;
                            float f = i32;
                            float f2 = i33;
                            if (c2080g23.b) {
                                int i36 = c2080g23.e;
                                if (i36 == 3) {
                                    i4 = c1905c2.d[c2080g23.g];
                                    c3 = 2;
                                } else {
                                    c3 = 2;
                                    i4 = i36 == 2 ? c1905c2.c[c2080g23.h] : c1905c2.b[c2080g23.i];
                                }
                                Paint paint3 = (Paint) this.b;
                                paint3.setColor(i4);
                                float f3 = i35;
                                c2 = c3;
                                c = 3;
                                canvas = canvas3;
                                canvas.drawRect(f2, f, f3, i23, paint3);
                            } else {
                                canvas = canvas3;
                                c = 3;
                                c2 = 2;
                            }
                            Bitmap bitmapCreateBitmap2 = Bitmap.createBitmap((Bitmap) this.g, i33, i32, i34, i22);
                            float f4 = c1949d23.a;
                            float f5 = c1949d23.b;
                            arrayList3.add(new Gg(null, null, null, bitmapCreateBitmap2, f / f5, 0, 0, f2 / f4, 0, Integer.MIN_VALUE, -3.4028235E38f, i34 / f4, i22 / f5, Integer.MIN_VALUE, DefinitionKt.NO_Float_VALUE));
                            canvas.drawColor(0, PorterDuff.Mode.CLEAR);
                            canvas.restore();
                            arrayList2 = arrayList3;
                            c2168i2 = c2168i23;
                            c1949d22 = c1949d23;
                            i17 = i26 + 1;
                            z = z2;
                            c2338m14 = c2338m15;
                        }
                    }
                } else {
                    x1 = new X1(arrayList2, -9223372036854775807L, -9223372036854775807L);
                }
            }
        }
        c0186z.mo10b(x1);
    }

    public void b() {
        try {
            long jCurrentTimeMillis = System.currentTimeMillis();
            com.google.android.gms.ads.internal.client.zzr zzrVarA = com.google.android.gms.ads.internal.client.zzr.a();
            C1608n c1608n = C1614q.f.b;
            Context context = (Context) this.b;
            String str = (String) this.c;
            BinderC2739va binderC2739va = (BinderC2739va) this.f;
            c1608n.getClass();
            com.google.android.gms.ads.internal.client.K k = (com.google.android.gms.ads.internal.client.K) new C1596h(c1608n, context, zzrVarA, str, binderC2739va).d(context, false);
            this.a = k;
            if (k != null) {
                com.google.android.gms.ads.internal.client.y0 y0Var = (com.google.android.gms.ads.internal.client.y0) this.d;
                y0Var.n = jCurrentTimeMillis;
                k.g3(new U5((C2578rl) this.e, str));
                com.google.android.gms.ads.internal.client.K k2 = (com.google.android.gms.ads.internal.client.K) this.a;
                ((com.google.android.gms.ads.internal.client.R0) this.g).getClass();
                k2.I2(com.google.android.gms.ads.internal.client.R0.a(context, y0Var));
            }
        } catch (RemoteException e) {
            com.google.android.gms.ads.internal.util.client.i.j("#007 Could not call remote method.", e);
        }
    }

    public C2210j2(Context context, String str, com.google.android.gms.ads.internal.client.y0 y0Var, C2578rl c2578rl) {
        this.f = new BinderC2739va();
        this.b = context;
        this.c = str;
        this.d = y0Var;
        this.e = c2578rl;
        this.g = com.google.android.gms.ads.internal.client.R0.a;
    }

    public C2210j2(A7 a7, WebView webView, String str, String str2, Gr gr) {
        this.c = new ArrayList();
        this.d = new HashMap();
        this.a = a7;
        this.b = webView;
        this.g = gr;
        this.f = str;
        this.e = str2;
    }

    public C2210j2(List list) {
        Kn kn = new Kn((byte[]) list.get(0));
        int iD = kn.D();
        int iD2 = kn.D();
        Paint paint = new Paint();
        this.a = paint;
        paint.setStyle(Paint.Style.FILL_AND_STROKE);
        paint.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.SRC));
        paint.setPathEffect(null);
        Paint paint2 = new Paint();
        this.b = paint2;
        paint2.setStyle(Paint.Style.FILL);
        paint2.setXfermode(new PorterDuffXfermode(PorterDuff.Mode.DST_OVER));
        paint2.setPathEffect(null);
        this.c = new Canvas();
        this.d = new C1949d2(719, 575, 0, 719, 0, 575);
        this.e = new C1905c2(0, new int[]{0, -1, -16777216, -8421505}, h(), i());
        this.f = new C2168i2(iD, iD2);
    }
}
