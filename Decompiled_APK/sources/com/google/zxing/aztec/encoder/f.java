package com.google.zxing.aztec.encoder;

/* loaded from: classes2.dex */
public final class f {
    public static final f e = new f(g.b, 0, 0, 0);
    public final int a;
    public final g b;
    public final int c;
    public final int d;

    public f(g gVar, int i, int i2, int i3) {
        this.b = gVar;
        this.a = i;
        this.c = i2;
        this.d = i3;
    }

    public final f a(int i) {
        g eVar = this.b;
        int i2 = this.a;
        int i3 = this.d;
        if (i2 == 4 || i2 == 2) {
            int[] iArr = d.c[i2];
            i2 = 0;
            int i4 = iArr[0];
            int i5 = 65535 & i4;
            int i6 = i4 >> 16;
            eVar.getClass();
            i3 += i6;
            eVar = new e(eVar, i5, i6);
        }
        int i7 = this.c;
        int i8 = (i7 == 0 || i7 == 31) ? 18 : i7 == 62 ? 9 : 8;
        int i9 = i7 + 1;
        f fVar = new f(eVar, i2, i9, i3 + i8);
        return i9 == 2078 ? fVar.b(i + 1) : fVar;
    }

    public final f b(int i) {
        int i2 = this.c;
        if (i2 == 0) {
            return this;
        }
        g gVar = this.b;
        gVar.getClass();
        return new f(new a(gVar, i - i2, i2), this.a, 0, this.d);
    }

    public final boolean c(f fVar) {
        int i;
        int i2 = this.d + (d.c[this.a][fVar.a] >> 16);
        int i3 = fVar.c;
        if (i3 > 0 && ((i = this.c) == 0 || i > i3)) {
            i2 += 10;
        }
        return i2 <= fVar.d;
    }

    public final f d(int i, int i2) {
        int i3 = this.d;
        g eVar = this.b;
        int i4 = this.a;
        if (i != i4) {
            int i5 = d.c[i4][i];
            int i6 = 65535 & i5;
            int i7 = i5 >> 16;
            eVar.getClass();
            i3 += i7;
            eVar = new e(eVar, i6, i7);
        }
        int i8 = i == 2 ? 4 : 5;
        eVar.getClass();
        return new f(new e(eVar, i2, i8), i, 0, i3 + i8);
    }

    public final f e(int i, int i2) {
        int i3 = this.a;
        int i4 = i3 == 2 ? 4 : 5;
        int i5 = d.e[i3][i];
        g gVar = this.b;
        gVar.getClass();
        return new f(new e(new e(gVar, i5, i4), i2, 5), i3, 0, this.d + i4 + 5);
    }

    public final String toString() {
        return String.format("%s bits=%d bytes=%d", d.b[this.a], Integer.valueOf(this.d), Integer.valueOf(this.c));
    }
}
