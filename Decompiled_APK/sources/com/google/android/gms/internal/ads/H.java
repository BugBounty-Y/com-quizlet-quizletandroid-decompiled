package com.google.android.gms.internal.ads;

import java.util.ArrayList;

/* loaded from: classes2.dex */
public final class H {
    public final ArrayList a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;
    public final int i;
    public final int j;
    public final float k;
    public final String l;

    public H(ArrayList arrayList, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8, int i9, float f, String str) {
        this.a = arrayList;
        this.b = i;
        this.c = i2;
        this.d = i3;
        this.e = i4;
        this.f = i5;
        this.g = i6;
        this.h = i7;
        this.i = i8;
        this.j = i9;
        this.k = f;
        this.l = str;
    }

    public static H a(Kn kn) {
        String str;
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        float f;
        int i7;
        int i8;
        try {
            kn.k(4);
            int iZ = (kn.z() & 3) + 1;
            if (iZ == 3) {
                throw new IllegalStateException();
            }
            ArrayList arrayList = new ArrayList();
            int iZ2 = kn.z() & 31;
            for (int i9 = 0; i9 < iZ2; i9++) {
                int iD = kn.D();
                int i10 = kn.b;
                kn.k(iD);
                byte[] bArr = kn.a;
                byte[] bArr2 = Hi.a;
                byte[] bArr3 = new byte[iD + 4];
                System.arraycopy(Hi.a, 0, bArr3, 0, 4);
                System.arraycopy(bArr, i10, bArr3, 4, iD);
                arrayList.add(bArr3);
            }
            int iZ3 = kn.z();
            for (int i11 = 0; i11 < iZ3; i11++) {
                int iD2 = kn.D();
                int i12 = kn.b;
                kn.k(iD2);
                byte[] bArr4 = kn.a;
                byte[] bArr5 = Hi.a;
                byte[] bArr6 = new byte[iD2 + 4];
                System.arraycopy(Hi.a, 0, bArr6, 0, 4);
                System.arraycopy(bArr4, i12, bArr6, 4, iD2);
                arrayList.add(bArr6);
            }
            if (iZ2 > 0) {
                Js jsF = LA.F(5, (byte[]) arrayList.get(0), ((byte[]) arrayList.get(0)).length);
                int i13 = jsF.e;
                int i14 = jsF.f;
                int i15 = jsF.h + 8;
                int i16 = jsF.i + 8;
                int i17 = jsF.j;
                int i18 = jsF.k;
                int i19 = jsF.l;
                int i20 = jsF.m;
                float f2 = jsF.g;
                int i21 = jsF.a;
                int i22 = jsF.b;
                int i23 = jsF.c;
                byte[] bArr7 = Hi.a;
                str = String.format("avc1.%02X%02X%02X", Integer.valueOf(i21), Integer.valueOf(i22), Integer.valueOf(i23));
                i4 = i18;
                i5 = i19;
                i6 = i20;
                f = f2;
                i2 = i14;
                i3 = i15;
                i7 = i16;
                i8 = i17;
                i = i13;
            } else {
                str = null;
                i = -1;
                i2 = -1;
                i3 = -1;
                i4 = -1;
                i5 = -1;
                i6 = 16;
                f = 1.0f;
                i7 = -1;
                i8 = -1;
            }
            return new H(arrayList, iZ, i, i2, i3, i7, i8, i4, i5, i6, f, str);
        } catch (ArrayIndexOutOfBoundsException e) {
            throw zzaz.a(e, "Error parsing AVC config");
        }
    }
}
