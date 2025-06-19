package com.google.zxing.common.reedsolomon;

/* loaded from: classes2.dex */
public final class a {
    public static final a g = new a(4201, 4096, 1);
    public static final a h = new a(1033, 1024, 1);
    public static final a i = new a(67, 64, 1);
    public static final a j = new a(19, 16, 1);
    public static final a k = new a(285, 256, 0);
    public static final a l = new a(301, 256, 1);
    public final int[] a;
    public final int[] b;
    public final b c;
    public final int d;
    public final int e;
    public final int f;

    public a(int i2, int i3, int i4) {
        this.e = i2;
        this.d = i3;
        this.f = i4;
        this.a = new int[i3];
        this.b = new int[i3];
        int i5 = 1;
        for (int i6 = 0; i6 < i3; i6++) {
            this.a[i6] = i5;
            i5 <<= 1;
            if (i5 >= i3) {
                i5 = (i5 ^ i2) & (i3 - 1);
            }
        }
        for (int i7 = 0; i7 < i3 - 1; i7++) {
            this.b[this.a[i7]] = i7;
        }
        this.c = new b(this, new int[]{0});
    }

    public final int a(int i2, int i3) {
        if (i2 == 0 || i3 == 0) {
            return 0;
        }
        int[] iArr = this.b;
        return this.a[(iArr[i2] + iArr[i3]) % (this.d - 1)];
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder("GF(0x");
        sb.append(Integer.toHexString(this.e));
        sb.append(',');
        return android.support.v4.media.session.a.q(sb, this.d, ')');
    }
}
