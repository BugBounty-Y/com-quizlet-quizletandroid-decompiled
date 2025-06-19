package com.google.android.gms.internal.ads;

import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/* loaded from: classes2.dex */
public final class Kn {
    public static final char[] d = {'\r', '\n'};
    public static final char[] e = {'\n'};
    public static final AbstractC2459ou f = AbstractC2459ou.o(5, StandardCharsets.US_ASCII, StandardCharsets.UTF_8, StandardCharsets.UTF_16, StandardCharsets.UTF_16BE, StandardCharsets.UTF_16LE);
    public byte[] a;
    public int b;
    public int c;

    public Kn(int i, byte[] bArr) {
        this.a = bArr;
        this.c = i;
    }

    public static int o(int i, int i2, int i3, int i4) {
        return ((AbstractC2025es.d(((i & 7) << 2) | ((i2 & 48) >> 4)) & 255) << 16) | ((AbstractC2025es.d(((i3 & 60) >> 2) | ((i2 & 15) << 4)) & 255) << 8) | (AbstractC2025es.d((i4 & 63) | ((i3 & 3) << 6)) & 255);
    }

    public static int p(Charset charset) {
        AbstractC1795We.G(f.contains(charset), "Unsupported charset: ".concat(String.valueOf(charset)));
        return (charset.equals(StandardCharsets.UTF_8) || charset.equals(StandardCharsets.US_ASCII)) ? 1 : 2;
    }

    public static boolean r(byte b) {
        return (b & 192) == 128;
    }

    public final int A() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        int i3 = bArr[i] & 255;
        this.b = i + 2;
        int i4 = bArr[i2] & 255;
        this.b = i + 4;
        return i4 | (i3 << 8);
    }

    public final int B() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        int i3 = bArr[i] & 255;
        int i4 = i + 2;
        this.b = i4;
        int i5 = bArr[i2] & 255;
        this.b = i + 3;
        return (bArr[i4] & 255) | (i3 << 16) | (i5 << 8);
    }

    public final int C() {
        int iU = u();
        if (iU >= 0) {
            return iU;
        }
        throw new IllegalStateException(android.support.v4.media.session.a.f(iU, "Top bit not zero: "));
    }

    public final int D() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        int i3 = bArr[i] & 255;
        this.b = i + 2;
        return (bArr[i2] & 255) | (i3 << 8);
    }

    public final long E() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        long j = bArr[i];
        int i3 = i + 2;
        this.b = i3;
        long j2 = bArr[i2];
        int i4 = i + 3;
        this.b = i4;
        long j3 = bArr[i3];
        int i5 = i + 4;
        this.b = i5;
        long j4 = bArr[i4];
        int i6 = i + 5;
        this.b = i6;
        long j5 = bArr[i5];
        int i7 = i + 6;
        this.b = i7;
        long j6 = bArr[i6];
        this.b = i + 7;
        long j7 = bArr[i7];
        this.b = i + 8;
        return ((bArr[r3] & 255) << 56) | (255 & j) | ((j2 & 255) << 8) | ((j3 & 255) << 16) | ((j4 & 255) << 24) | ((j5 & 255) << 32) | ((j6 & 255) << 40) | ((j7 & 255) << 48);
    }

    public final long F() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        long j = bArr[i];
        int i3 = i + 2;
        this.b = i3;
        long j2 = bArr[i2];
        this.b = i + 3;
        long j3 = bArr[i3];
        this.b = i + 4;
        return ((bArr[r2] & 255) << 24) | (j & 255) | ((j2 & 255) << 8) | ((j3 & 255) << 16);
    }

    public final long G() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        long j = bArr[i];
        int i3 = i + 2;
        this.b = i3;
        long j2 = bArr[i2];
        int i4 = i + 3;
        this.b = i4;
        long j3 = bArr[i3];
        int i5 = i + 4;
        this.b = i5;
        long j4 = bArr[i4];
        int i6 = i + 5;
        this.b = i6;
        long j5 = bArr[i5];
        int i7 = i + 6;
        this.b = i7;
        long j6 = bArr[i6];
        this.b = i + 7;
        long j7 = bArr[i7];
        this.b = i + 8;
        return (bArr[r3] & 255) | ((j & 255) << 56) | ((j2 & 255) << 48) | ((j3 & 255) << 40) | ((j4 & 255) << 32) | ((j5 & 255) << 24) | ((j6 & 255) << 16) | ((j7 & 255) << 8);
    }

    public final long H() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        long j = bArr[i];
        int i3 = i + 2;
        this.b = i3;
        long j2 = bArr[i2];
        this.b = i + 3;
        long j3 = bArr[i3];
        this.b = i + 4;
        return (bArr[r2] & 255) | ((j & 255) << 24) | ((j2 & 255) << 16) | ((j3 & 255) << 8);
    }

    public final long I() {
        long jG = G();
        if (jG >= 0) {
            return jG;
        }
        throw new IllegalStateException(androidx.compose.animation.d0.n(jG, "Top bit not zero: "));
    }

    public final long J() {
        int i;
        int i2;
        long j = this.a[this.b];
        int i3 = 7;
        while (true) {
            i = 0;
            if (i3 < 0) {
                break;
            }
            if (((1 << i3) & j) != 0) {
                i3--;
            } else if (i3 < 6) {
                j &= r7 - 1;
                i = 7 - i3;
            } else if (i3 == 7) {
                i = 1;
            }
        }
        if (i == 0) {
            throw new NumberFormatException(androidx.compose.animation.d0.n(j, "Invalid UTF-8 sequence first byte: "));
        }
        for (i2 = 1; i2 < i; i2++) {
            if ((this.a[this.b + i2] & 192) != 128) {
                throw new NumberFormatException(androidx.compose.animation.d0.n(j, "Invalid UTF-8 sequence continuation byte: "));
            }
            j = (j << 6) | (r2 & 63);
        }
        this.b += i;
        return j;
    }

    public final String K() {
        if (s() == 0) {
            return null;
        }
        int i = this.b;
        while (i < this.c && this.a[i] != 0) {
            i++;
        }
        byte[] bArr = this.a;
        int i2 = this.b;
        String str = Yo.a;
        String str2 = new String(bArr, i2, i - i2, StandardCharsets.UTF_8);
        this.b = i;
        if (i < this.c) {
            this.b = i + 1;
        }
        return str2;
    }

    /* JADX WARN: Removed duplicated region for block: B:34:0x0088  */
    /* JADX WARN: Removed duplicated region for block: B:44:0x00a9  */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.lang.String L(java.nio.charset.Charset r8) {
        /*
            r7 = this;
            r0 = 1
            com.google.android.gms.internal.ads.ou r1 = com.google.android.gms.internal.ads.Kn.f
            boolean r1 = r1.contains(r8)
            java.lang.String r2 = java.lang.String.valueOf(r8)
            java.lang.String r3 = "Unsupported charset: "
            java.lang.String r2 = r3.concat(r2)
            com.google.android.gms.internal.ads.AbstractC1795We.G(r1, r2)
            int r1 = r7.s()
            if (r1 != 0) goto L1c
            r8 = 0
            return r8
        L1c:
            java.nio.charset.Charset r1 = java.nio.charset.StandardCharsets.US_ASCII
            boolean r2 = r8.equals(r1)
            if (r2 != 0) goto L27
            r7.c()
        L27:
            java.nio.charset.Charset r2 = java.nio.charset.StandardCharsets.UTF_8
            boolean r2 = r8.equals(r2)
            if (r2 != 0) goto L35
            boolean r1 = r8.equals(r1)
            if (r1 == 0) goto L37
        L35:
            r2 = r0
            goto L5f
        L37:
            java.nio.charset.Charset r1 = java.nio.charset.StandardCharsets.UTF_16
            boolean r1 = r8.equals(r1)
            r2 = 2
            if (r1 != 0) goto L5f
            java.nio.charset.Charset r1 = java.nio.charset.StandardCharsets.UTF_16LE
            boolean r1 = r8.equals(r1)
            if (r1 != 0) goto L5f
            java.nio.charset.Charset r1 = java.nio.charset.StandardCharsets.UTF_16BE
            boolean r1 = r8.equals(r1)
            if (r1 == 0) goto L51
            goto L5f
        L51:
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            java.lang.String r8 = java.lang.String.valueOf(r8)
            java.lang.String r8 = r3.concat(r8)
            r0.<init>(r8)
            throw r0
        L5f:
            int r1 = r7.b
        L61:
            int r3 = r7.c
            int r4 = r2 + (-1)
            int r4 = r3 - r4
            r5 = 13
            if (r1 >= r4) goto Lc4
            java.nio.charset.Charset r3 = java.nio.charset.StandardCharsets.UTF_8
            boolean r3 = r8.equals(r3)
            r4 = 10
            if (r3 != 0) goto L7d
            java.nio.charset.Charset r3 = java.nio.charset.StandardCharsets.US_ASCII
            boolean r3 = r8.equals(r3)
            if (r3 == 0) goto L88
        L7d:
            byte[] r3 = r7.a
            r3 = r3[r1]
            java.lang.String r6 = com.google.android.gms.internal.ads.Yo.a
            if (r3 == r4) goto Lc5
            if (r3 != r5) goto L88
            goto Lc5
        L88:
            java.nio.charset.Charset r3 = java.nio.charset.StandardCharsets.UTF_16
            boolean r3 = r8.equals(r3)
            if (r3 != 0) goto L98
            java.nio.charset.Charset r3 = java.nio.charset.StandardCharsets.UTF_16BE
            boolean r3 = r8.equals(r3)
            if (r3 == 0) goto La9
        L98:
            byte[] r3 = r7.a
            r6 = r3[r1]
            if (r6 != 0) goto La9
            int r6 = r1 + 1
            r3 = r3[r6]
            java.lang.String r6 = com.google.android.gms.internal.ads.Yo.a
            if (r3 == r4) goto Lc5
            if (r3 != r5) goto La9
            goto Lc5
        La9:
            java.nio.charset.Charset r3 = java.nio.charset.StandardCharsets.UTF_16LE
            boolean r3 = r8.equals(r3)
            if (r3 == 0) goto Lc2
            int r3 = r1 + 1
            byte[] r6 = r7.a
            r3 = r6[r3]
            if (r3 != 0) goto Lc2
            r3 = r6[r1]
            java.lang.String r6 = com.google.android.gms.internal.ads.Yo.a
            if (r3 == r4) goto Lc5
            if (r3 != r5) goto Lc2
            goto Lc5
        Lc2:
            int r1 = r1 + r2
            goto L61
        Lc4:
            r1 = r3
        Lc5:
            int r0 = r7.b
            int r1 = r1 - r0
            java.lang.String r0 = r7.b(r1, r8)
            int r1 = r7.b
            int r2 = r7.c
            if (r1 == r2) goto Ldf
            char[] r1 = com.google.android.gms.internal.ads.Kn.d
            char r1 = r7.n(r8, r1)
            if (r1 != r5) goto Ldf
            char[] r1 = com.google.android.gms.internal.ads.Kn.e
            r7.n(r8, r1)
        Ldf:
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: com.google.android.gms.internal.ads.Kn.L(java.nio.charset.Charset):java.lang.String");
    }

    public final String a(int i) {
        if (i == 0) {
            return "";
        }
        int i2 = this.b;
        int i3 = (i2 + i) - 1;
        int i4 = (i3 >= this.c || this.a[i3] != 0) ? i : i - 1;
        byte[] bArr = this.a;
        String str = Yo.a;
        String str2 = new String(bArr, i2, i4, StandardCharsets.UTF_8);
        this.b += i;
        return str2;
    }

    public final String b(int i, Charset charset) {
        byte[] bArr = this.a;
        int i2 = this.b;
        String str = new String(bArr, i2, i, charset);
        this.b = i2 + i;
        return str;
    }

    public final Charset c() {
        if (s() >= 3) {
            byte[] bArr = this.a;
            int i = this.b;
            if (bArr[i] == -17 && bArr[i + 1] == -69 && bArr[i + 2] == -65) {
                this.b = i + 3;
                return StandardCharsets.UTF_8;
            }
        }
        if (s() < 2) {
            return null;
        }
        byte[] bArr2 = this.a;
        int i2 = this.b;
        byte b = bArr2[i2];
        if (b == -2) {
            if (bArr2[i2 + 1] != -1) {
                return null;
            }
            this.b = i2 + 2;
            return StandardCharsets.UTF_16BE;
        }
        if (b != -1 || bArr2[i2 + 1] != -2) {
            return null;
        }
        this.b = i2 + 2;
        return StandardCharsets.UTF_16LE;
    }

    public final short d() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        int i3 = bArr[i] & 255;
        this.b = i + 2;
        return (short) ((bArr[i2] & 255) | (i3 << 8));
    }

    public final void e(int i) {
        byte[] bArr = this.a;
        if (i > bArr.length) {
            this.a = Arrays.copyOf(bArr, i);
        }
    }

    public final void f(int i, byte[] bArr, int i2) {
        System.arraycopy(this.a, this.b, bArr, i, i2);
        this.b += i2;
    }

    public final void g(int i) {
        byte[] bArr = this.a;
        if (bArr.length < i) {
            bArr = new byte[i];
        }
        h(i, bArr);
    }

    public final void h(int i, byte[] bArr) {
        this.a = bArr;
        this.c = i;
        this.b = 0;
    }

    public final void i(int i) {
        boolean z = false;
        if (i >= 0 && i <= this.a.length) {
            z = true;
        }
        AbstractC1795We.B(z);
        this.c = i;
    }

    public final void j(int i) {
        boolean z = false;
        if (i >= 0 && i <= this.c) {
            z = true;
        }
        AbstractC1795We.B(z);
        this.b = i;
    }

    public final void k(int i) {
        j(this.b + i);
    }

    public final byte[] l() {
        return this.a;
    }

    public final char m(int i, ByteOrder byteOrder) {
        byte b;
        byte b2;
        if (byteOrder == ByteOrder.BIG_ENDIAN) {
            byte[] bArr = this.a;
            int i2 = this.b + i;
            b = bArr[i2];
            b2 = bArr[i2 + 1];
        } else {
            byte[] bArr2 = this.a;
            int i3 = this.b + i;
            b = bArr2[i3 + 1];
            b2 = bArr2[i3];
        }
        return (char) ((b << 8) | (b2 & 255));
    }

    public final char n(Charset charset, char[] cArr) {
        int iQ;
        if (s() >= p(charset) && (iQ = q(charset)) != 0) {
            if (!Character.isSupplementaryCodePoint(i)) {
                long j = i;
                char c = (char) j;
                AbstractC1981ds.I("Out of range: %s", j, ((long) c) == j);
                for (char c2 : cArr) {
                    if (c2 == c) {
                        this.b = AbstractC1981ds.k(iQ & 255) + this.b;
                        return c;
                    }
                }
            }
        }
        return (char) 0;
    }

    public final int q(Charset charset) {
        int codePoint;
        int i;
        int iO;
        AbstractC1795We.G(f.contains(charset), "Unsupported charset: ".concat(String.valueOf(charset)));
        if (s() < p(charset)) {
            throw new IndexOutOfBoundsException(androidx.compose.animation.d0.p("position=", this.b, ", limit=", this.c));
        }
        int i2 = 1;
        if (charset.equals(StandardCharsets.US_ASCII)) {
            byte b = this.a[this.b];
            if ((b & 128) == 0) {
                codePoint = b & 255;
                return (codePoint << 8) | i2;
            }
            return 0;
        }
        if (charset.equals(StandardCharsets.UTF_8)) {
            byte b2 = this.a[this.b];
            if ((b2 & 128) == 0) {
                i = 1;
            } else if ((b2 & 224) == 192 && s() >= 2 && r(this.a[this.b + 1])) {
                i = 2;
            } else {
                if ((this.a[this.b] & 240) == 224 && s() >= 3) {
                    byte[] bArr = this.a;
                    int i3 = this.b;
                    if (r(bArr[i3 + 1]) && r(bArr[i3 + 2])) {
                        i = 3;
                    }
                }
                if ((this.a[this.b] & 248) == 240 && s() >= 4) {
                    byte[] bArr2 = this.a;
                    int i4 = this.b;
                    if (r(bArr2[i4 + 1]) && r(bArr2[i4 + 2]) && r(bArr2[i4 + 3])) {
                        i = 4;
                    }
                }
                i = 0;
            }
            if (i == 1) {
                iO = this.a[this.b] & 255;
            } else if (i == 2) {
                byte[] bArr3 = this.a;
                int i5 = this.b;
                iO = o(0, 0, bArr3[i5], bArr3[i5 + 1]);
            } else {
                if (i != 3) {
                    if (i == 4) {
                        byte[] bArr4 = this.a;
                        int i6 = this.b;
                        iO = o(bArr4[i6], bArr4[i6 + 1], bArr4[i6 + 2], bArr4[i6 + 3]);
                    }
                    return 0;
                }
                byte[] bArr5 = this.a;
                int i7 = this.b;
                iO = o(0, bArr5[i7] & 15, bArr5[i7 + 1], bArr5[i7 + 2]);
            }
            i2 = i;
            codePoint = iO;
        } else {
            ByteOrder byteOrder = charset.equals(StandardCharsets.UTF_16LE) ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
            char cM = m(0, byteOrder);
            if (!Character.isHighSurrogate(cM) || s() < 4) {
                codePoint = cM;
                i2 = 2;
            } else {
                codePoint = Character.toCodePoint(cM, m(2, byteOrder));
                i2 = 4;
            }
        }
        return (codePoint << 8) | i2;
    }

    public final int s() {
        return Math.max(this.c - this.b, 0);
    }

    public final int t() {
        return this.b;
    }

    public final int u() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        int i3 = bArr[i] & 255;
        int i4 = i + 2;
        this.b = i4;
        int i5 = bArr[i2] & 255;
        int i6 = i + 3;
        this.b = i6;
        int i7 = bArr[i4] & 255;
        this.b = i + 4;
        return (bArr[i6] & 255) | (i3 << 24) | (i5 << 16) | (i7 << 8);
    }

    public final int v() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        int i3 = bArr[i] & 255;
        int i4 = i + 2;
        this.b = i4;
        int i5 = bArr[i2] & 255;
        int i6 = i + 3;
        this.b = i6;
        int i7 = bArr[i4] & 255;
        this.b = i + 4;
        return ((bArr[i6] & 255) << 24) | (i5 << 8) | i3 | (i7 << 16);
    }

    public final int w() {
        int iV = v();
        if (iV >= 0) {
            return iV;
        }
        throw new IllegalStateException(android.support.v4.media.session.a.f(iV, "Top bit not zero: "));
    }

    public final int x() {
        byte[] bArr = this.a;
        int i = this.b;
        int i2 = i + 1;
        this.b = i2;
        int i3 = bArr[i] & 255;
        this.b = i + 2;
        return ((bArr[i2] & 255) << 8) | i3;
    }

    public final int y() {
        return (z() << 21) | (z() << 14) | (z() << 7) | z();
    }

    public final int z() {
        byte[] bArr = this.a;
        int i = this.b;
        this.b = i + 1;
        return bArr[i] & 255;
    }

    public Kn() {
        this.a = Yo.b;
    }

    public Kn(int i) {
        this.a = new byte[i];
        this.c = i;
    }

    public Kn(byte[] bArr) {
        this.a = bArr;
        this.c = bArr.length;
    }
}
