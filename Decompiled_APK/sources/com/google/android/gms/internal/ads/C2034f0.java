package com.google.android.gms.internal.ads;

import java.io.Serializable;

/* renamed from: com.google.android.gms.internal.ads.f0, reason: case insensitive filesystem */
/* loaded from: classes2.dex */
public final class C2034f0 {
    public int a;
    public int b;
    public int c;
    public int d;
    public Serializable e;
    public int f;
    public int g;

    public boolean a(int i) {
        int i2;
        int i3;
        int i4;
        int i5;
        if ((i & (-2097152)) != -2097152 || (i2 = (i >>> 19) & 3) == 1 || (i3 = (i >>> 17) & 3) == 0 || (i4 = (i >>> 12) & 15) == 0 || i4 == 15 || (i5 = (i >>> 10) & 3) == 3) {
            return false;
        }
        int i6 = i4 - 1;
        this.a = i2;
        this.e = AbstractC2096gb.c[3 - i3];
        int i7 = AbstractC2096gb.d[i5];
        this.c = i7;
        if (i2 == 2) {
            i7 /= 2;
            this.c = i7;
        } else if (i2 == 0) {
            i7 /= 4;
            this.c = i7;
        }
        int i8 = (i >>> 9) & 1;
        int i9 = 1152;
        if (i3 != 1) {
            if (i3 != 2) {
                i9 = 384;
            }
        } else if (i2 != 3) {
            i9 = 576;
        }
        this.g = i9;
        if (i3 == 3) {
            int i10 = i2 == 3 ? AbstractC2096gb.e[i6] : AbstractC2096gb.f[i6];
            this.f = i10;
            this.b = (((i10 * 12) / i7) + i8) * 4;
        } else {
            if (i2 == 3) {
                int i11 = i3 == 2 ? AbstractC2096gb.g[i6] : AbstractC2096gb.h[i6];
                this.f = i11;
                this.b = ((i11 * 144) / i7) + i8;
            } else {
                int i12 = AbstractC2096gb.i[i6];
                this.f = i12;
                this.b = (((i3 == 1 ? 72 : 144) * i12) / i7) + i8;
            }
        }
        this.d = ((i >> 6) & 3) == 3 ? 1 : 2;
        return true;
    }
}
