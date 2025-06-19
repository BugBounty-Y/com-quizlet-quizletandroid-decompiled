package androidx.glance.appwidget.protobuf;

import com.google.android.gms.internal.mlkit_vision_barcode.A7;
import java.io.IOException;
import java.io.OutputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

/* renamed from: androidx.glance.appwidget.protobuf.j, reason: case insensitive filesystem */
/* loaded from: classes.dex */
public final class C1198j extends A7 {
    public static final Logger g = Logger.getLogger(C1198j.class.getName());
    public static final boolean h = Y.e;
    public A b;
    public final byte[] c;
    public final int d;
    public int e;
    public final OutputStream f;

    public C1198j(OutputStream outputStream, int i) {
        if (i < 0) {
            throw new IllegalArgumentException("bufferSize must be >= 0");
        }
        int iMax = Math.max(i, 20);
        this.c = new byte[iMax];
        this.d = iMax;
        if (outputStream == null) {
            throw new NullPointerException("out");
        }
        this.f = outputStream;
    }

    public static int h(int i, C1194f c1194f) {
        int iJ = j(i);
        int size = c1194f.size();
        return k(size) + size + iJ;
    }

    public static int i(String str) {
        int length;
        try {
            length = b0.a(str);
        } catch (a0 unused) {
            length = str.getBytes(AbstractC1209v.a).length;
        }
        return k(length) + length;
    }

    public static int j(int i) {
        return k(i << 3);
    }

    public static int k(int i) {
        return (352 - (Integer.numberOfLeadingZeros(i) * 9)) >>> 6;
    }

    public static int l(long j) {
        return (640 - (Long.numberOfLeadingZeros(j) * 9)) >>> 6;
    }

    public final void A(int i, int i2) throws IOException {
        n(20);
        e(i, 0);
        f(i2);
    }

    public final void B(int i) throws IOException {
        n(5);
        f(i);
    }

    public final void C(int i, long j) {
        n(20);
        e(i, 0);
        g(j);
    }

    public final void D(long j) throws IOException {
        n(10);
        g(j);
    }

    @Override // com.google.android.gms.internal.mlkit_vision_barcode.A7
    public final void b(int i, byte[] bArr, int i2) throws IOException {
        o(bArr, i, i2);
    }

    public final void c(int i) {
        int i2 = this.e;
        int i3 = i2 + 1;
        this.e = i3;
        byte[] bArr = this.c;
        bArr[i2] = (byte) (i & 255);
        int i4 = i2 + 2;
        this.e = i4;
        bArr[i3] = (byte) ((i >> 8) & 255);
        int i5 = i2 + 3;
        this.e = i5;
        bArr[i4] = (byte) ((i >> 16) & 255);
        this.e = i2 + 4;
        bArr[i5] = (byte) ((i >> 24) & 255);
    }

    public final void d(long j) {
        int i = this.e;
        int i2 = i + 1;
        this.e = i2;
        byte[] bArr = this.c;
        bArr[i] = (byte) (j & 255);
        int i3 = i + 2;
        this.e = i3;
        bArr[i2] = (byte) ((j >> 8) & 255);
        int i4 = i + 3;
        this.e = i4;
        bArr[i3] = (byte) ((j >> 16) & 255);
        int i5 = i + 4;
        this.e = i5;
        bArr[i4] = (byte) (255 & (j >> 24));
        int i6 = i + 5;
        this.e = i6;
        bArr[i5] = (byte) (((int) (j >> 32)) & 255);
        int i7 = i + 6;
        this.e = i7;
        bArr[i6] = (byte) (((int) (j >> 40)) & 255);
        int i8 = i + 7;
        this.e = i8;
        bArr[i7] = (byte) (((int) (j >> 48)) & 255);
        this.e = i + 8;
        bArr[i8] = (byte) (((int) (j >> 56)) & 255);
    }

    public final void e(int i, int i2) {
        f((i << 3) | i2);
    }

    public final void f(int i) {
        boolean z = h;
        byte[] bArr = this.c;
        if (!z) {
            while ((i & (-128)) != 0) {
                int i2 = this.e;
                this.e = i2 + 1;
                bArr[i2] = (byte) ((i | 128) & 255);
                i >>>= 7;
            }
            int i3 = this.e;
            this.e = i3 + 1;
            bArr[i3] = (byte) i;
            return;
        }
        while ((i & (-128)) != 0) {
            int i4 = this.e;
            this.e = i4 + 1;
            Y.j(bArr, (byte) ((i | 128) & 255), i4);
            i >>>= 7;
        }
        int i5 = this.e;
        this.e = i5 + 1;
        Y.j(bArr, (byte) i, i5);
    }

    public final void g(long j) {
        boolean z = h;
        byte[] bArr = this.c;
        if (!z) {
            while ((j & (-128)) != 0) {
                int i = this.e;
                this.e = i + 1;
                bArr[i] = (byte) ((((int) j) | 128) & 255);
                j >>>= 7;
            }
            int i2 = this.e;
            this.e = i2 + 1;
            bArr[i2] = (byte) j;
            return;
        }
        while ((j & (-128)) != 0) {
            int i3 = this.e;
            this.e = i3 + 1;
            Y.j(bArr, (byte) ((((int) j) | 128) & 255), i3);
            j >>>= 7;
        }
        int i4 = this.e;
        this.e = i4 + 1;
        Y.j(bArr, (byte) j, i4);
    }

    public final void m() throws IOException {
        this.f.write(this.c, 0, this.e);
        this.e = 0;
    }

    public final void n(int i) throws IOException {
        if (this.d - this.e < i) {
            m();
        }
    }

    public final void o(byte[] bArr, int i, int i2) throws IOException {
        int i3 = this.e;
        int i4 = this.d;
        int i5 = i4 - i3;
        byte[] bArr2 = this.c;
        if (i5 >= i2) {
            System.arraycopy(bArr, i, bArr2, i3, i2);
            this.e += i2;
            return;
        }
        System.arraycopy(bArr, i, bArr2, i3, i5);
        int i6 = i + i5;
        int i7 = i2 - i5;
        this.e = i4;
        m();
        if (i7 > i4) {
            this.f.write(bArr, i6, i7);
        } else {
            System.arraycopy(bArr, i6, bArr2, 0, i7);
            this.e = i7;
        }
    }

    public final void p(int i, boolean z) throws IOException {
        n(11);
        e(i, 0);
        byte b = z ? (byte) 1 : (byte) 0;
        int i2 = this.e;
        this.e = i2 + 1;
        this.c[i2] = b;
    }

    public final void q(int i, C1194f c1194f) {
        z(i, 2);
        B(c1194f.size());
        b(c1194f.e(), c1194f.b, c1194f.size());
    }

    public final void r(int i, int i2) {
        n(14);
        e(i, 5);
        c(i2);
    }

    public final void s(int i) throws IOException {
        n(4);
        c(i);
    }

    public final void t(int i, long j) {
        n(18);
        e(i, 1);
        d(j);
    }

    public final void u(long j) throws IOException {
        n(8);
        d(j);
    }

    public final void v(int i, int i2) throws IOException {
        n(20);
        e(i, 0);
        if (i2 >= 0) {
            f(i2);
        } else {
            g(i2);
        }
    }

    public final void w(int i) throws IOException {
        if (i >= 0) {
            B(i);
        } else {
            D(i);
        }
    }

    public final void x(int i, AbstractC1189a abstractC1189a, O o) throws IOException {
        z(i, 2);
        B(abstractC1189a.a(o));
        o.h(abstractC1189a, this.b);
    }

    public final void y(int i, String str) throws IOException {
        z(i, 2);
        try {
            int length = str.length() * 3;
            int iK = k(length);
            int i2 = iK + length;
            int i3 = this.d;
            if (i2 > i3) {
                byte[] bArr = new byte[length];
                int iD = b0.a.d(str, bArr, 0, length);
                B(iD);
                o(bArr, 0, iD);
                return;
            }
            if (i2 > i3 - this.e) {
                m();
            }
            int iK2 = k(str.length());
            int i4 = this.e;
            byte[] bArr2 = this.c;
            try {
                if (iK2 != iK) {
                    int iA = b0.a(str);
                    f(iA);
                    this.e = b0.a.d(str, bArr2, this.e, iA);
                    return;
                }
                int i5 = i4 + iK2;
                this.e = i5;
                int iD2 = b0.a.d(str, bArr2, i5, i3 - i5);
                this.e = i4;
                f((iD2 - i4) - iK2);
                this.e = iD2;
            } catch (a0 e) {
                this.e = i4;
                throw e;
            } catch (ArrayIndexOutOfBoundsException e2) {
                throw new CodedOutputStream$OutOfSpaceException(e2);
            }
        } catch (a0 e3) {
            g.log(Level.WARNING, "Converting ill-formed UTF-16. Your Protocol Buffer will not round trip correctly!", (Throwable) e3);
            byte[] bytes = str.getBytes(AbstractC1209v.a);
            try {
                B(bytes.length);
                b(0, bytes, bytes.length);
            } catch (IndexOutOfBoundsException e4) {
                throw new CodedOutputStream$OutOfSpaceException(e4);
            }
        }
    }

    public final void z(int i, int i2) {
        B((i << 3) | i2);
    }
}
