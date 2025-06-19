package com.google.android.gms.internal.measurement;

import com.google.android.gms.internal.mlkit_vision_common.AbstractC3571z3;
import java.util.Locale;
import java.util.logging.Level;
import java.util.logging.Logger;

/* loaded from: classes2.dex */
public final class P1 extends AbstractC3571z3 {
    public static final Logger f = Logger.getLogger(P1.class.getName());
    public static final boolean g = C2.e;
    public C3005i2 b;
    public final byte[] c;
    public final int d;
    public int e;

    public P1(int i, byte[] bArr) {
        int length = bArr.length;
        if (((length - i) | i) < 0) {
            Locale locale = Locale.US;
            throw new IllegalArgumentException(androidx.compose.animation.d0.p("Array range is invalid. Buffer.length=", length, ", offset=0, length=", i));
        }
        this.c = bArr;
        this.e = 0;
        this.d = i;
    }

    public static int a(long j) {
        return (640 - (Long.numberOfLeadingZeros(j) * 9)) >>> 6;
    }

    public static int p(String str) {
        int length;
        try {
            length = E2.c(str);
        } catch (D2 unused) {
            length = str.getBytes(AbstractC2980d2.a).length;
        }
        return q(length) + length;
    }

    public static int q(int i) {
        return (352 - (Integer.numberOfLeadingZeros(i) * 9)) >>> 6;
    }

    public final void b(int i, byte[] bArr) throws zzli {
        try {
            System.arraycopy(bArr, 0, this.c, this.e, i);
            this.e += i;
        } catch (IndexOutOfBoundsException e) {
            throw new zzli(this.e, this.d, i, e);
        }
    }

    public final void c(int i, O1 o1) throws zzli {
        m((i << 3) | 2);
        m(o1.c());
        b(o1.c(), o1.b);
    }

    public final void d(int i, int i2) throws zzli {
        m((i << 3) | 5);
        e(i2);
    }

    public final void e(int i) throws zzli {
        int i2 = this.e;
        try {
            byte[] bArr = this.c;
            bArr[i2] = (byte) i;
            bArr[i2 + 1] = (byte) (i >> 8);
            bArr[i2 + 2] = (byte) (i >> 16);
            bArr[i2 + 3] = (byte) (i >> 24);
            this.e = i2 + 4;
        } catch (IndexOutOfBoundsException e) {
            throw new zzli(i2, this.d, 4, e);
        }
    }

    public final void f(int i, long j) throws zzli {
        m((i << 3) | 1);
        g(j);
    }

    public final void g(long j) throws zzli {
        int i = this.e;
        try {
            byte[] bArr = this.c;
            bArr[i] = (byte) j;
            bArr[i + 1] = (byte) (j >> 8);
            bArr[i + 2] = (byte) (j >> 16);
            bArr[i + 3] = (byte) (j >> 24);
            bArr[i + 4] = (byte) (j >> 32);
            bArr[i + 5] = (byte) (j >> 40);
            bArr[i + 6] = (byte) (j >> 48);
            bArr[i + 7] = (byte) (j >> 56);
            this.e = i + 8;
        } catch (IndexOutOfBoundsException e) {
            throw new zzli(i, this.d, 8, e);
        }
    }

    public final void h(int i, int i2) throws zzli {
        m(i << 3);
        i(i2);
    }

    public final void i(int i) throws zzli {
        if (i >= 0) {
            m(i);
        } else {
            o(i);
        }
    }

    public final void j(int i, String str) throws zzli {
        m((i << 3) | 2);
        int i2 = this.e;
        try {
            int iQ = q(str.length() * 3);
            int iQ2 = q(str.length());
            byte[] bArr = this.c;
            int i3 = this.d;
            if (iQ2 != iQ) {
                m(E2.c(str));
                int i4 = this.e;
                this.e = E2.b(str, bArr, i4, i3 - i4);
            } else {
                int i5 = i2 + iQ2;
                this.e = i5;
                int iB = E2.b(str, bArr, i5, i3 - i5);
                this.e = i2;
                m((iB - i2) - iQ2);
                this.e = iB;
            }
        } catch (D2 e) {
            this.e = i2;
            f.logp(Level.WARNING, "com.google.protobuf.CodedOutputStream", "inefficientWriteStringNoTag", "Converting ill-formed UTF-16. Your Protocol Buffer will not round trip correctly!", (Throwable) e);
            byte[] bytes = str.getBytes(AbstractC2980d2.a);
            try {
                int length = bytes.length;
                m(length);
                b(length, bytes);
            } catch (IndexOutOfBoundsException e2) {
                throw new zzli(e2);
            }
        } catch (IndexOutOfBoundsException e3) {
            throw new zzli(e3);
        }
    }

    public final void k(int i, int i2) throws zzli {
        m((i << 3) | i2);
    }

    public final void l(int i, int i2) throws zzli {
        m(i << 3);
        m(i2);
    }

    public final void m(int i) throws zzli {
        int i2;
        int i3 = this.e;
        while (true) {
            int i4 = i & (-128);
            byte[] bArr = this.c;
            if (i4 == 0) {
                i2 = i3 + 1;
                bArr[i3] = (byte) i;
                this.e = i2;
                return;
            } else {
                i2 = i3 + 1;
                try {
                    bArr[i3] = (byte) (i | 128);
                    i >>>= 7;
                    i3 = i2;
                } catch (IndexOutOfBoundsException e) {
                    throw new zzli(i2, this.d, 1, e);
                }
            }
            throw new zzli(i2, this.d, 1, e);
        }
    }

    public final void n(int i, long j) throws zzli {
        m(i << 3);
        o(j);
    }

    public final void o(long j) throws zzli {
        int i;
        int i2 = this.e;
        byte[] bArr = this.c;
        boolean z = g;
        int i3 = this.d;
        if (!z || i3 - i2 < 10) {
            long j2 = j;
            while ((j2 & (-128)) != 0) {
                i = i2 + 1;
                try {
                    bArr[i2] = (byte) (((int) j2) | 128);
                    j2 >>>= 7;
                    i2 = i;
                } catch (IndexOutOfBoundsException e) {
                    throw new zzli(i, i3, 1, e);
                }
            }
            i = i2 + 1;
            bArr[i2] = (byte) j2;
        } else {
            long j3 = j;
            while ((j3 & (-128)) != 0) {
                C2.c.d(bArr, C2.f + i2, (byte) (((int) j3) | 128));
                j3 >>>= 7;
                i2++;
            }
            i = i2 + 1;
            C2.c.d(bArr, C2.f + i2, (byte) j3);
        }
        this.e = i;
    }
}
