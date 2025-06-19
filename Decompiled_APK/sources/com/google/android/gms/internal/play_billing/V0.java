package com.google.android.gms.internal.play_billing;

import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public final class V0 extends Z0 {
    public static final Logger f = Logger.getLogger(V0.class.getName());
    public static final boolean g = G1.e;
    public C3817m1 b;
    public final byte[] c;
    public final int d;
    public int e;

    public V0(int i, byte[] bArr) {
        super(11);
        int length = bArr.length;
        if (((length - i) | i) < 0) {
            Locale locale = Locale.US;
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("Array range is invalid. Buffer.length=", length, ", offset=0, length=", i));
        }
        this.c = bArr;
        this.e = 0;
        this.d = i;
    }

    public static int O(long j) {
        return (640 - (Long.numberOfLeadingZeros(j) * 9)) >>> 6;
    }

    public static int d0(String str) {
        int length;
        try {
            length = I1.c(str);
        } catch (H1 unused) {
            length = str.getBytes(AbstractC3802h1.a).length;
        }
        return e0(length) + length;
    }

    public static int e0(int i) {
        return (352 - (Integer.numberOfLeadingZeros(i) * 9)) >>> 6;
    }

    public final void P(int i, byte[] bArr) throws zzgp {
        try {
            System.arraycopy(bArr, 0, this.c, this.e, i);
            this.e += i;
        } catch (IndexOutOfBoundsException e) {
            throw new zzgp(this.e, this.d, i, e);
        }
    }

    public final void Q(int i, U0 u0) throws zzgp {
        a0((i << 3) | 2);
        a0(u0.c());
        P(u0.c(), u0.b);
    }

    public final void R(int i, int i2) throws zzgp {
        a0((i << 3) | 5);
        S(i2);
    }

    public final void S(int i) throws zzgp {
        int i2 = this.e;
        try {
            byte[] bArr = this.c;
            bArr[i2] = (byte) (i & 255);
            bArr[i2 + 1] = (byte) ((i >> 8) & 255);
            bArr[i2 + 2] = (byte) ((i >> 16) & 255);
            bArr[i2 + 3] = (byte) ((i >> 24) & 255);
            this.e = i2 + 4;
        } catch (IndexOutOfBoundsException e) {
            throw new zzgp(i2, this.d, 4, e);
        }
    }

    public final void T(int i, long j) throws zzgp {
        a0((i << 3) | 1);
        U(j);
    }

    public final void U(long j) throws zzgp {
        int i = this.e;
        try {
            byte[] bArr = this.c;
            bArr[i] = (byte) (((int) j) & 255);
            bArr[i + 1] = (byte) (((int) (j >> 8)) & 255);
            bArr[i + 2] = (byte) (((int) (j >> 16)) & 255);
            bArr[i + 3] = (byte) (((int) (j >> 24)) & 255);
            bArr[i + 4] = (byte) (((int) (j >> 32)) & 255);
            bArr[i + 5] = (byte) (((int) (j >> 40)) & 255);
            bArr[i + 6] = (byte) (((int) (j >> 48)) & 255);
            bArr[i + 7] = (byte) (((int) (j >> 56)) & 255);
            this.e = i + 8;
        } catch (IndexOutOfBoundsException e) {
            throw new zzgp(i, this.d, 8, e);
        }
    }

    public final void V(int i, int i2) throws zzgp {
        a0(i << 3);
        W(i2);
    }

    public final void W(int i) throws zzgp {
        if (i >= 0) {
            a0(i);
        } else {
            c0(i);
        }
    }

    public final void X(int i, String str) throws zzgp {
        a0((i << 3) | 2);
        int i2 = this.e;
        try {
            int iE0 = e0(str.length() * 3);
            int iE02 = e0(str.length());
            byte[] bArr = this.c;
            int i3 = this.d;
            if (iE02 != iE0) {
                a0(I1.c(str));
                int i4 = this.e;
                this.e = I1.b(str, bArr, i4, i3 - i4);
            } else {
                int i5 = i2 + iE02;
                this.e = i5;
                int iB = I1.b(str, bArr, i5, i3 - i5);
                this.e = i2;
                a0((iB - i2) - iE02);
                this.e = iB;
            }
        } catch (H1 e) {
            this.e = i2;
            f.logp(Level.WARNING, "com.google.protobuf.CodedOutputStream", "inefficientWriteStringNoTag", "Converting ill-formed UTF-16. Your Protocol Buffer will not round trip correctly!", (Throwable) e);
            byte[] bytes = str.getBytes(AbstractC3802h1.a);
            try {
                int length = bytes.length;
                a0(length);
                P(length, bytes);
            } catch (IndexOutOfBoundsException e2) {
                throw new zzgp(e2);
            }
        } catch (IndexOutOfBoundsException e3) {
            throw new zzgp(e3);
        }
    }

    public final void Y(int i, int i2) throws zzgp {
        a0((i << 3) | i2);
    }

    public final void Z(int i, int i2) throws zzgp {
        a0(i << 3);
        a0(i2);
    }

    public final void a0(int i) throws zzgp {
        while (true) {
            int i2 = i & (-128);
            byte[] bArr = this.c;
            if (i2 == 0) {
                int i3 = this.e;
                this.e = i3 + 1;
                bArr[i3] = (byte) i;
                return;
            } else {
                try {
                    int i4 = this.e;
                    this.e = i4 + 1;
                    bArr[i4] = (byte) ((i | 128) & 255);
                    i >>>= 7;
                } catch (IndexOutOfBoundsException e) {
                    throw new zzgp(this.e, this.d, 1, e);
                }
            }
            throw new zzgp(this.e, this.d, 1, e);
        }
    }

    public final void b0(int i, long j) throws zzgp {
        a0(i << 3);
        c0(j);
    }

    public final void c0(long j) throws zzgp {
        byte[] bArr = this.c;
        boolean z = g;
        int i = this.d;
        if (!z || i - this.e < 10) {
            while ((j & (-128)) != 0) {
                try {
                    int i2 = this.e;
                    this.e = i2 + 1;
                    bArr[i2] = (byte) ((((int) j) | 128) & 255);
                    j >>>= 7;
                } catch (IndexOutOfBoundsException e) {
                    throw new zzgp(this.e, i, 1, e);
                }
            }
            int i3 = this.e;
            this.e = i3 + 1;
            bArr[i3] = (byte) j;
            return;
        }
        while (true) {
            int i4 = (int) j;
            if ((j & (-128)) == 0) {
                int i5 = this.e;
                this.e = i5 + 1;
                G1.c.d(bArr, G1.f + i5, (byte) i4);
                return;
            }
            int i6 = this.e;
            this.e = i6 + 1;
            G1.c.d(bArr, G1.f + i6, (byte) ((i4 | 128) & 255));
            j >>>= 7;
        }
    }
}
