package com.iabtcf.utils;

import com.iabtcf.exceptions.ByteParseException;

/* loaded from: classes2.dex */
public final class a {
    public final byte[] a;
    public final int b;
    public final com.quizlet.data.repository.folderwithcreator.e c = new com.quizlet.data.repository.folderwithcreator.e(this);

    public a(byte[] bArr) {
        this.a = bArr;
        this.b = bArr.length;
    }

    public static byte l(byte b, int i, int i2) {
        return i2 == 0 ? b : (byte) ((b & ((1 << i2) - 1)) << i);
    }

    public static byte m(byte b, int i, int i2) {
        if (i2 == 0) {
            return (byte) 0;
        }
        return (byte) ((b >>> ((8 - i2) - i)) & ((1 << i2) - 1));
    }

    public final void a(int i, int i2) {
        if (i + i2 > this.b) {
            throw new ByteParseException(String.format("read %d bytes at index %d out of bounds for buffer length %d", Integer.valueOf(i2), Integer.valueOf(i), Integer.valueOf(this.a.length)));
        }
    }

    public final boolean b(int i) {
        int i2 = i >>> 3;
        a(i2, 1);
        return ((this.a[i2] >>> (7 - (i % 8))) & 1) == 1;
    }

    public final boolean c(l lVar) {
        return b(lVar.b(this));
    }

    public final int d(int i) {
        int iL;
        byte bM;
        int i2 = i >>> 3;
        int i3 = i % 8;
        int i4 = 8 - i3;
        if (i4 < 4) {
            a(i2, 3);
            int iL2 = (l(this.a[i2], i3, i4) & 255) << 4;
            byte[] bArr = this.a;
            int i5 = i3 - 4;
            iL = iL2 | ((bArr[i2 + 1] & 255) << i5);
            bM = m(bArr[i2 + 2], 0, i5);
        } else {
            a(i2, 2);
            iL = (l(this.a[i2], i3, i4) & 255) << 4;
            bM = m(this.a[i2 + 1], 0, i3 + 4);
        }
        return (bM & 255) | iL;
    }

    public final int e(l lVar) {
        return d(lVar.b(this));
    }

    public final int f(int i) {
        int i2;
        byte bM;
        int i3 = i >>> 3;
        int i4 = i % 8;
        int i5 = 8 - i4;
        if (i5 < 8) {
            a(i3, 3);
            int iL = (l(this.a[i3], i4, i5) & 255) << 8;
            byte[] bArr = this.a;
            i2 = iL | ((bArr[i3 + 1] & 255) << i4);
            bM = m(bArr[i3 + 2], 0, i4);
        } else {
            a(i3, 2);
            byte[] bArr2 = this.a;
            i2 = (bArr2[i3] & 255) << 8;
            bM = bArr2[i3 + 1];
        }
        return (bM & 255) | i2;
    }

    public final long g(l lVar) {
        int iB = lVar.b(this);
        int i = iB >>> 3;
        int i2 = iB % 8;
        if (8 - i2 < 4) {
            a(i, 6);
            long jL = (l(this.a[i], i2, r1) & 255) << 28;
            byte[] bArr = this.a;
            return (m(bArr[i + 5], 0, r13) & 255) | jL | ((bArr[i + 1] & 255) << (i2 + 20)) | ((bArr[i + 2] & 255) << (i2 + 12)) | ((bArr[i + 3] & 255) << (i2 + 4)) | ((bArr[i + 4] & 255) << (i2 - 4));
        }
        a(i, 5);
        long jL2 = (l(this.a[i], i2, r1) & 255) << 28;
        byte[] bArr2 = this.a;
        return (m(bArr2[i + 4], 0, r13) & 255) | jL2 | ((bArr2[i + 1] & 255) << (i2 + 20)) | ((bArr2[i + 2] & 255) << (i2 + 12)) | ((bArr2[i + 3] & 255) << (i2 + 4));
    }

    public final byte h(int i) {
        int i2 = i >>> 3;
        int i3 = i % 8;
        int i4 = 8 - i3;
        if (i4 >= 6) {
            a(i2, 1);
            return m(this.a[i2], i3, 6);
        }
        a(i2, 2);
        int i5 = 6 - i4;
        return (byte) (l(this.a[i2], i5, i4) | m(this.a[i2 + 1], 0, i5));
    }

    public final byte i(l lVar) {
        return h(lVar.b(this));
    }

    public final byte j(int i, int i2) {
        int i3 = i >>> 3;
        int i4 = i % 8;
        int i5 = 8 - i4;
        if (i5 >= i2) {
            a(i3, 1);
            return m(this.a[i3], i4, i2);
        }
        a(i3, 2);
        int i6 = i2 - i5;
        return (byte) (l(this.a[i3], i6, i5) | m(this.a[i3 + 1], 0, i6));
    }

    public final String k(l lVar) {
        int iB = lVar.b(this);
        return String.valueOf(new char[]{(char) (h(iB) + 65), (char) (h(iB + 6) + 65)});
    }
}
