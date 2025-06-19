package com.google.zxing.datamatrix.encoder;

import com.comscore.streaming.ContentType;

/* loaded from: classes2.dex */
public class e {
    public static final e[] i = {new e(3, 5, 8, 8, 1, 3, 5, false), new e(5, 7, 10, 10, 1, 5, 7, false), new e(5, 7, 16, 6, 1, 5, 7, true), new e(8, 10, 12, 12, 1, 8, 10, false), new e(10, 11, 14, 6, 2, 10, 11, true), new e(12, 12, 14, 14, 1, 12, 12, false), new e(16, 14, 24, 10, 1, 16, 14, true), new e(18, 14, 16, 16, 1, 18, 14, false), new e(22, 18, 18, 18, 1, 22, 18, false), new e(22, 18, 16, 10, 2, 22, 18, true), new e(30, 20, 20, 20, 1, 30, 20, false), new e(32, 24, 16, 14, 2, 32, 24, true), new e(36, 24, 22, 22, 1, 36, 24, false), new e(44, 28, 24, 24, 1, 44, 28, false), new e(49, 28, 22, 14, 2, 49, 28, true), new e(62, 36, 14, 14, 4, 62, 36, false), new e(86, 42, 16, 16, 4, 86, 42, false), new e(114, 48, 18, 18, 4, 114, 48, false), new e(144, 56, 20, 20, 4, 144, 56, false), new e(174, 68, 22, 22, 4, 174, 68, false), new e(204, 84, 24, 24, 4, 102, 42, false), new e(280, ContentType.LONG_FORM_ON_DEMAND, 14, 14, 16, 140, 56, false), new e(368, 144, 16, 16, 16, 92, 36, false), new e(456, 192, 18, 18, 16, 114, 48, false), new e(576, 224, 20, 20, 16, 144, 56, false), new e(696, 272, 22, 22, 16, 174, 68, false), new e(816, 336, 24, 24, 16, 136, 56, false), new e(1050, 408, 18, 18, 36, 175, 68, false), new e(1304, 496, 20, 20, 36, 163, 62, false), new a(1558, 620, 22, 22, 36, -1, 62, false)};
    public final boolean a;
    public final int b;
    public final int c;
    public final int d;
    public final int e;
    public final int f;
    public final int g;
    public final int h;

    public e(int i2, int i3, int i4, int i5, int i6, int i7, int i8, boolean z) {
        this.a = z;
        this.b = i2;
        this.c = i3;
        this.d = i4;
        this.e = i5;
        this.f = i6;
        this.g = i7;
        this.h = i8;
    }

    public static e e(int i2, f fVar) {
        e[] eVarArr = i;
        for (int i3 = 0; i3 < 30; i3++) {
            e eVar = eVarArr[i3];
            if (!(fVar == f.b && eVar.a) && ((fVar != f.c || eVar.a) && i2 <= eVar.b)) {
                return eVar;
            }
        }
        throw new IllegalArgumentException("Can't find a symbol arrangement that matches the message. Data codewords: ".concat(String.valueOf(i2)));
    }

    public int a(int i2) {
        return this.g;
    }

    public final int b() {
        int i2 = 1;
        int i3 = this.f;
        if (i3 != 1) {
            i2 = 2;
            if (i3 != 2 && i3 != 4) {
                if (i3 == 16) {
                    return 4;
                }
                if (i3 == 36) {
                    return 6;
                }
                throw new IllegalStateException("Cannot handle this number of data regions");
            }
        }
        return i2;
    }

    public int c() {
        return this.b / this.g;
    }

    public final int d() {
        int i2 = this.f;
        if (i2 == 1 || i2 == 2) {
            return 1;
        }
        if (i2 == 4) {
            return 2;
        }
        if (i2 == 16) {
            return 4;
        }
        if (i2 == 36) {
            return 6;
        }
        throw new IllegalStateException("Cannot handle this number of data regions");
    }

    public final String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(this.a ? "Rectangular Symbol:" : "Square Symbol:");
        sb.append(" data region ");
        int i2 = this.d;
        sb.append(i2);
        sb.append('x');
        int i3 = this.e;
        sb.append(i3);
        sb.append(", symbol size ");
        sb.append((b() * i2) + (b() << 1));
        sb.append('x');
        sb.append((d() * i3) + (d() << 1));
        sb.append(", symbol data size ");
        sb.append(b() * i2);
        sb.append('x');
        sb.append(d() * i3);
        sb.append(", codewords ");
        sb.append(this.b);
        sb.append('+');
        sb.append(this.c);
        return sb.toString();
    }
}
