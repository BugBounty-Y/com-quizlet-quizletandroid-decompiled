package okio;

import androidx.compose.animation.d0;
import io.ktor.client.plugins.C4864k;
import java.io.EOFException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.ByteChannel;
import java.nio.charset.Charset;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* renamed from: okio.h, reason: case insensitive filesystem */
/* loaded from: classes3.dex */
public final class C5091h implements InterfaceC5093j, InterfaceC5092i, Cloneable, ByteChannel, AutoCloseable {
    public B a;
    public long b;

    public final byte[] B(long j) throws EOFException {
        if (j < 0 || j > 2147483647L) {
            throw new IllegalArgumentException(d0.n(j, "byteCount: ").toString());
        }
        if (this.b < j) {
            throw new EOFException();
        }
        byte[] sink = new byte[(int) j];
        Intrinsics.checkNotNullParameter(sink, "sink");
        int i = 0;
        while (i < sink.length) {
            int i2 = read(sink, i, sink.length - i);
            if (i2 == -1) {
                throw new EOFException();
            }
            i += i2;
        }
        return sink;
    }

    public final k D(long j) throws EOFException {
        if (j < 0 || j > 2147483647L) {
            throw new IllegalArgumentException(d0.n(j, "byteCount: ").toString());
        }
        if (this.b < j) {
            throw new EOFException();
        }
        if (j < 4096) {
            return new k(B(j));
        }
        k kVarK0 = k0((int) j);
        skip(j);
        return kVarK0;
    }

    @Override // okio.InterfaceC5092i
    public final /* bridge */ /* synthetic */ InterfaceC5092i F(int i, byte[] bArr) {
        o0(bArr, 0, i);
        return this;
    }

    @Override // okio.InterfaceC5092i
    public final /* bridge */ /* synthetic */ InterfaceC5092i H(String str) {
        u0(str);
        return this;
    }

    @Override // okio.InterfaceC5093j
    public final boolean J(long j, k bytes) {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        int length = bytes.a.length;
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        if (j >= 0 && length >= 0 && this.b - j >= length && bytes.a.length >= length) {
            for (int i = 0; i < length; i++) {
                if (p(i + j) == bytes.a[i]) {
                }
            }
            return true;
        }
        return false;
    }

    @Override // okio.InterfaceC5093j
    public final String K(Charset charset) {
        Intrinsics.checkNotNullParameter(charset, "charset");
        return c0(this.b, charset);
    }

    @Override // okio.E
    public final void L(C5091h source, long j) {
        B b;
        Intrinsics.checkNotNullParameter(source, "source");
        if (source == this) {
            throw new IllegalArgumentException("source == this");
        }
        AbstractC5085b.e(source.b, 0L, j);
        while (j > 0) {
            B b2 = source.a;
            Intrinsics.d(b2);
            int i = b2.c;
            B b3 = source.a;
            Intrinsics.d(b3);
            long j2 = i - b3.b;
            int i2 = 0;
            if (j < j2) {
                B b4 = this.a;
                B b5 = b4 != null ? b4.g : null;
                if (b5 != null && b5.e) {
                    if ((b5.c + j) - (b5.d ? 0 : b5.b) <= 8192) {
                        B b6 = source.a;
                        Intrinsics.d(b6);
                        b6.d(b5, (int) j);
                        source.b -= j;
                        this.b += j;
                        return;
                    }
                }
                B b7 = source.a;
                Intrinsics.d(b7);
                int i3 = (int) j;
                if (i3 <= 0 || i3 > b7.c - b7.b) {
                    throw new IllegalArgumentException("byteCount out of range");
                }
                if (i3 >= 1024) {
                    b = b7.c();
                } else {
                    b = C.b();
                    int i4 = b7.b;
                    C4930v.d(0, i4, i4 + i3, b7.a, b.a);
                }
                b.c = b.b + i3;
                b7.b += i3;
                B b8 = b7.g;
                Intrinsics.d(b8);
                b8.b(b);
                source.a = b;
            }
            B b9 = source.a;
            Intrinsics.d(b9);
            long j3 = b9.c - b9.b;
            source.a = b9.a();
            B b10 = this.a;
            if (b10 == null) {
                this.a = b9;
                b9.g = b9;
                b9.f = b9;
            } else {
                B b11 = b10.g;
                Intrinsics.d(b11);
                b11.b(b9);
                B b12 = b9.g;
                if (b12 == b9) {
                    throw new IllegalStateException("cannot compact");
                }
                Intrinsics.d(b12);
                if (b12.e) {
                    int i5 = b9.c - b9.b;
                    B b13 = b9.g;
                    Intrinsics.d(b13);
                    int i6 = 8192 - b13.c;
                    B b14 = b9.g;
                    Intrinsics.d(b14);
                    if (!b14.d) {
                        B b15 = b9.g;
                        Intrinsics.d(b15);
                        i2 = b15.b;
                    }
                    if (i5 <= i6 + i2) {
                        B b16 = b9.g;
                        Intrinsics.d(b16);
                        b9.d(b16, i5);
                        b9.a();
                        C.a(b9);
                    }
                }
            }
            source.b -= j3;
            this.b += j3;
            j -= j3;
        }
    }

    @Override // okio.InterfaceC5092i
    public final long M(G source) {
        Intrinsics.checkNotNullParameter(source, "source");
        long j = 0;
        while (true) {
            long jB0 = source.b0(this, 8192L);
            if (jB0 == -1) {
                return j;
            }
            j += jB0;
        }
    }

    @Override // okio.InterfaceC5092i
    public final /* bridge */ /* synthetic */ InterfaceC5092i O(int i, int i2, String str) {
        t0(i, i2, str);
        return this;
    }

    public final int P() throws EOFException {
        if (this.b < 4) {
            throw new EOFException();
        }
        B b = this.a;
        Intrinsics.d(b);
        int i = b.b;
        int i2 = b.c;
        if (i2 - i < 4) {
            return ((readByte() & 255) << 24) | ((readByte() & 255) << 16) | ((readByte() & 255) << 8) | (readByte() & 255);
        }
        byte[] bArr = b.a;
        int i3 = i + 3;
        int i4 = ((bArr[i + 1] & 255) << 16) | ((bArr[i] & 255) << 24) | ((bArr[i + 2] & 255) << 8);
        int i5 = i + 4;
        int i6 = i4 | (bArr[i3] & 255);
        this.b -= 4;
        if (i5 != i2) {
            b.b = i5;
            return i6;
        }
        this.a = b.a();
        C.a(b);
        return i6;
    }

    @Override // okio.InterfaceC5093j
    public final String S() throws EOFException {
        if (Long.MAX_VALUE < 0) {
            throw new IllegalArgumentException(d0.n(Long.MAX_VALUE, "limit < 0: ").toString());
        }
        long j = Long.MAX_VALUE != Long.MAX_VALUE ? Long.MAX_VALUE + 1 : Long.MAX_VALUE;
        long jQ = q((byte) 10, 0L, j);
        if (jQ != -1) {
            return okio.internal.a.b(this, jQ);
        }
        if (j < this.b && p(j - 1) == 13 && p(j) == 10) {
            return okio.internal.a.b(this, j);
        }
        C5091h c5091h = new C5091h();
        l(c5091h, 0L, Math.min(32, this.b));
        throw new EOFException("\\n not found: limit=" + Math.min(this.b, Long.MAX_VALUE) + " content=" + c5091h.D(c5091h.b).e() + (char) 8230);
    }

    @Override // okio.InterfaceC5093j
    public final String U() {
        return c0(this.b, Charsets.UTF_8);
    }

    @Override // okio.InterfaceC5092i
    public final /* bridge */ /* synthetic */ InterfaceC5092i X(byte[] bArr) {
        n0(bArr);
        return this;
    }

    public final short Y() throws EOFException {
        if (this.b < 2) {
            throw new EOFException();
        }
        B b = this.a;
        Intrinsics.d(b);
        int i = b.b;
        int i2 = b.c;
        if (i2 - i < 2) {
            return (short) (((readByte() & 255) << 8) | (readByte() & 255));
        }
        int i3 = i + 1;
        byte[] bArr = b.a;
        int i4 = (bArr[i] & 255) << 8;
        int i5 = i + 2;
        int i6 = (bArr[i3] & 255) | i4;
        this.b -= 2;
        if (i5 == i2) {
            this.a = b.a();
            C.a(b);
        } else {
            b.b = i5;
        }
        return (short) i6;
    }

    @Override // okio.InterfaceC5092i
    public final /* bridge */ /* synthetic */ InterfaceC5092i Z(k kVar) {
        m0(kVar);
        return this;
    }

    public final short a0() throws EOFException {
        short sY = Y();
        return (short) (((sY & 255) << 8) | ((65280 & sY) >>> 8));
    }

    @Override // okio.G
    public final long b0(C5091h sink, long j) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount < 0: ").toString());
        }
        long j2 = this.b;
        if (j2 == 0) {
            return -1L;
        }
        if (j > j2) {
            j = j2;
        }
        sink.L(this, j);
        return j;
    }

    @Override // okio.InterfaceC5093j
    public final C5091h c() {
        return this;
    }

    public final String c0(long j, Charset charset) throws EOFException {
        Intrinsics.checkNotNullParameter(charset, "charset");
        if (j < 0 || j > 2147483647L) {
            throw new IllegalArgumentException(d0.n(j, "byteCount: ").toString());
        }
        if (this.b < j) {
            throw new EOFException();
        }
        if (j == 0) {
            return "";
        }
        B b = this.a;
        Intrinsics.d(b);
        int i = b.b;
        if (i + j > b.c) {
            return new String(B(j), charset);
        }
        int i2 = (int) j;
        String str = new String(b.a, i, i2, charset);
        int i3 = b.b + i2;
        b.b = i3;
        this.b -= j;
        if (i3 == b.c) {
            this.a = b.a();
            C.a(b);
        }
        return str;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable, java.nio.channels.Channel, okio.E
    public final void close() {
    }

    public final void d() throws EOFException {
        skip(this.b);
    }

    public final int d0() throws EOFException {
        int i;
        int i2;
        int i3;
        if (this.b == 0) {
            throw new EOFException();
        }
        byte bP = p(0L);
        if ((bP & 128) == 0) {
            i = bP & Byte.MAX_VALUE;
            i2 = 0;
            i3 = 1;
        } else if ((bP & 224) == 192) {
            i = bP & 31;
            i3 = 2;
            i2 = 128;
        } else if ((bP & 240) == 224) {
            i = bP & 15;
            i3 = 3;
            i2 = 2048;
        } else {
            if ((bP & 248) != 240) {
                skip(1L);
                return 65533;
            }
            i = bP & 7;
            i2 = 65536;
            i3 = 4;
        }
        long j = i3;
        if (this.b < j) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i3, "size < ", ": ");
            sbV.append(this.b);
            sbV.append(" (to read code point prefixed 0x");
            char[] cArr = okio.internal.b.a;
            char[] cArr2 = {cArr[(bP >> 4) & 15], cArr[bP & 15]};
            Intrinsics.checkNotNullParameter(cArr2, "<this>");
            sbV.append(new String(cArr2));
            sbV.append(')');
            throw new EOFException(sbV.toString());
        }
        for (int i4 = 1; i4 < i3; i4++) {
            long j2 = i4;
            byte bP2 = p(j2);
            if ((bP2 & 192) != 128) {
                skip(j2);
                return 65533;
            }
            i = (i << 6) | (bP2 & 63);
        }
        skip(j);
        if (i <= 1114111 && ((55296 > i || i >= 57344) && i >= i2)) {
            return i;
        }
        return 65533;
    }

    @Override // okio.InterfaceC5093j
    public final boolean e(long j) {
        return this.b >= j;
    }

    @Override // okio.InterfaceC5093j
    public final long e0(InterfaceC5092i sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        long j = this.b;
        if (j > 0) {
            sink.L(this, j);
        }
        return j;
    }

    public final boolean equals(Object obj) {
        boolean z = true;
        if (this == obj) {
            return true;
        }
        boolean z2 = false;
        if (!(obj instanceof C5091h)) {
            return false;
        }
        long j = this.b;
        C5091h c5091h = (C5091h) obj;
        if (j != c5091h.b) {
            return false;
        }
        if (j == 0) {
            return true;
        }
        B b = this.a;
        Intrinsics.d(b);
        B b2 = c5091h.a;
        Intrinsics.d(b2);
        int i = b.b;
        int i2 = b2.b;
        long j2 = 0;
        while (j2 < this.b) {
            long jMin = Math.min(b.c - i, b2.c - i2);
            long j3 = 0;
            while (j3 < jMin) {
                int i3 = i + 1;
                boolean z3 = z;
                byte b3 = b.a[i];
                int i4 = i2 + 1;
                boolean z4 = z2;
                if (b3 != b2.a[i2]) {
                    return z4;
                }
                j3++;
                i2 = i4;
                i = i3;
                z = z3;
                z2 = z4;
            }
            boolean z5 = z;
            boolean z6 = z2;
            if (i == b.c) {
                B b4 = b.f;
                Intrinsics.d(b4);
                i = b4.b;
                b = b4;
            }
            if (i2 == b2.c) {
                b2 = b2.f;
                Intrinsics.d(b2);
                i2 = b2.b;
            }
            j2 += jMin;
            z = z5;
            z2 = z6;
        }
        return z;
    }

    /* renamed from: f, reason: merged with bridge method [inline-methods] */
    public final C5091h clone() {
        C5091h c5091h = new C5091h();
        if (this.b == 0) {
            return c5091h;
        }
        B b = this.a;
        Intrinsics.d(b);
        B bC = b.c();
        c5091h.a = bC;
        bC.g = bC;
        bC.f = bC;
        for (B b2 = b.f; b2 != b; b2 = b2.f) {
            B b3 = bC.g;
            Intrinsics.d(b3);
            Intrinsics.d(b2);
            b3.b(b2.c());
        }
        c5091h.b = this.b;
        return c5091h;
    }

    @Override // okio.InterfaceC5092i, okio.E, java.io.Flushable
    public final void flush() {
    }

    @Override // okio.G
    public final I h() {
        return I.d;
    }

    @Override // okio.InterfaceC5092i
    public final /* bridge */ /* synthetic */ InterfaceC5092i h0(long j) {
        q0(j);
        return this;
    }

    public final int hashCode() {
        B b = this.a;
        if (b == null) {
            return 0;
        }
        int i = 1;
        do {
            int i2 = b.c;
            for (int i3 = b.b; i3 < i2; i3++) {
                i = (i * 31) + b.a[i3];
            }
            b = b.f;
            Intrinsics.d(b);
        } while (b != this.a);
        return i;
    }

    public final long i() {
        long j = this.b;
        if (j == 0) {
            return 0L;
        }
        B b = this.a;
        Intrinsics.d(b);
        B b2 = b.g;
        Intrinsics.d(b2);
        return (b2.c >= 8192 || !b2.e) ? j : j - (r3 - b2.b);
    }

    @Override // okio.InterfaceC5093j
    public final InputStream i0() {
        return new C4864k(this, 2);
    }

    @Override // java.nio.channels.Channel
    public final boolean isOpen() {
        return true;
    }

    @Override // okio.InterfaceC5093j
    public final int j0(w options) throws EOFException {
        Intrinsics.checkNotNullParameter(options, "options");
        int iC = okio.internal.a.c(this, options, false);
        if (iC == -1) {
            return -1;
        }
        skip(options.b[iC].d());
        return iC;
    }

    @Override // okio.InterfaceC5093j
    public final void k(long j) throws EOFException {
        if (this.b < j) {
            throw new EOFException();
        }
    }

    public final k k0(int i) {
        if (i == 0) {
            return k.d;
        }
        AbstractC5085b.e(this.b, 0L, i);
        B b = this.a;
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        while (i3 < i) {
            Intrinsics.d(b);
            int i5 = b.c;
            int i6 = b.b;
            if (i5 == i6) {
                throw new AssertionError("s.limit == s.pos");
            }
            i3 += i5 - i6;
            i4++;
            b = b.f;
        }
        byte[][] bArr = new byte[i4][];
        int[] iArr = new int[i4 * 2];
        B b2 = this.a;
        int i7 = 0;
        while (i2 < i) {
            Intrinsics.d(b2);
            bArr[i7] = b2.a;
            i2 += b2.c - b2.b;
            iArr[i7] = Math.min(i2, i);
            iArr[i7 + i4] = b2.b;
            b2.d = true;
            i7++;
            b2 = b2.f;
        }
        return new D(bArr, iArr);
    }

    public final void l(C5091h out, long j, long j2) {
        Intrinsics.checkNotNullParameter(out, "out");
        long j3 = j;
        AbstractC5085b.e(this.b, j3, j2);
        if (j2 == 0) {
            return;
        }
        out.b += j2;
        B b = this.a;
        while (true) {
            Intrinsics.d(b);
            long j4 = b.c - b.b;
            if (j3 < j4) {
                break;
            }
            j3 -= j4;
            b = b.f;
        }
        B b2 = b;
        long j5 = j2;
        while (j5 > 0) {
            Intrinsics.d(b2);
            B bC = b2.c();
            int i = bC.b + ((int) j3);
            bC.b = i;
            bC.c = Math.min(i + ((int) j5), bC.c);
            B b3 = out.a;
            if (b3 == null) {
                bC.g = bC;
                bC.f = bC;
                out.a = bC;
            } else {
                B b4 = b3.g;
                Intrinsics.d(b4);
                b4.b(bC);
            }
            j5 -= bC.c - bC.b;
            b2 = b2.f;
            j3 = 0;
        }
    }

    public final B l0(int i) {
        if (i < 1 || i > 8192) {
            throw new IllegalArgumentException("unexpected capacity");
        }
        B b = this.a;
        if (b == null) {
            B b2 = C.b();
            this.a = b2;
            b2.g = b2;
            b2.f = b2;
            return b2;
        }
        B b3 = b.g;
        Intrinsics.d(b3);
        if (b3.c + i <= 8192 && b3.e) {
            return b3;
        }
        B b4 = C.b();
        b3.b(b4);
        return b4;
    }

    public final void m0(k byteString) {
        Intrinsics.checkNotNullParameter(byteString, "byteString");
        byteString.t(this, byteString.d());
    }

    public final void n0(byte[] source) {
        Intrinsics.checkNotNullParameter(source, "source");
        o0(source, 0, source.length);
    }

    public final void o0(byte[] source, int i, int i2) {
        Intrinsics.checkNotNullParameter(source, "source");
        long j = i2;
        AbstractC5085b.e(source.length, i, j);
        int i3 = i2 + i;
        while (i < i3) {
            B bL0 = l0(1);
            int iMin = Math.min(i3 - i, 8192 - bL0.c);
            int i4 = i + iMin;
            C4930v.d(bL0.c, i, i4, source, bL0.a);
            bL0.c += iMin;
            i = i4;
        }
        this.b += j;
    }

    public final byte p(long j) {
        AbstractC5085b.e(this.b, j, 1L);
        B b = this.a;
        if (b == null) {
            Intrinsics.d(null);
            throw null;
        }
        long j2 = this.b;
        if (j2 - j < j) {
            while (j2 > j) {
                b = b.g;
                Intrinsics.d(b);
                j2 -= b.c - b.b;
            }
            return b.a[(int) ((b.b + j) - j2)];
        }
        long j3 = 0;
        while (true) {
            int i = b.c;
            int i2 = b.b;
            long j4 = (i - i2) + j3;
            if (j4 > j) {
                return b.a[(int) ((i2 + j) - j3)];
            }
            b = b.f;
            Intrinsics.d(b);
            j3 = j4;
        }
    }

    public final void p0(int i) {
        B bL0 = l0(1);
        int i2 = bL0.c;
        bL0.c = i2 + 1;
        bL0.a[i2] = (byte) i;
        this.b++;
    }

    @Override // okio.InterfaceC5093j
    public final A peek() {
        return AbstractC5085b.c(new y(this));
    }

    public final long q(byte b, long j, long j2) {
        B b2;
        long j3 = 0;
        if (0 > j || j > j2) {
            throw new IllegalArgumentException(("size=" + this.b + " fromIndex=" + j + " toIndex=" + j2).toString());
        }
        long j4 = this.b;
        if (j2 > j4) {
            j2 = j4;
        }
        if (j == j2 || (b2 = this.a) == null) {
            return -1L;
        }
        if (j4 - j < j) {
            while (j4 > j) {
                b2 = b2.g;
                Intrinsics.d(b2);
                j4 -= b2.c - b2.b;
            }
            while (j4 < j2) {
                int iMin = (int) Math.min(b2.c, (b2.b + j2) - j4);
                for (int i = (int) ((b2.b + j) - j4); i < iMin; i++) {
                    if (b2.a[i] == b) {
                        return (i - b2.b) + j4;
                    }
                }
                j4 += b2.c - b2.b;
                b2 = b2.f;
                Intrinsics.d(b2);
                j = j4;
            }
            return -1L;
        }
        while (true) {
            long j5 = (b2.c - b2.b) + j3;
            if (j5 > j) {
                break;
            }
            b2 = b2.f;
            Intrinsics.d(b2);
            j3 = j5;
        }
        while (j3 < j2) {
            int iMin2 = (int) Math.min(b2.c, (b2.b + j2) - j3);
            for (int i2 = (int) ((b2.b + j) - j3); i2 < iMin2; i2++) {
                if (b2.a[i2] == b) {
                    return (i2 - b2.b) + j3;
                }
            }
            j3 += b2.c - b2.b;
            b2 = b2.f;
            Intrinsics.d(b2);
            j = j3;
        }
        return -1L;
    }

    public final void q0(long j) {
        boolean z;
        byte[] bArr;
        if (j == 0) {
            p0(48);
            return;
        }
        if (j < 0) {
            j = -j;
            if (j < 0) {
                u0("-9223372036854775808");
                return;
            }
            z = true;
        } else {
            z = false;
        }
        byte[] bArr2 = okio.internal.a.a;
        int iNumberOfLeadingZeros = ((64 - Long.numberOfLeadingZeros(j)) * 10) >>> 5;
        int i = iNumberOfLeadingZeros + (j > okio.internal.a.b[iNumberOfLeadingZeros] ? 1 : 0);
        if (z) {
            i++;
        }
        B bL0 = l0(i);
        int i2 = bL0.c + i;
        while (true) {
            bArr = bL0.a;
            if (j == 0) {
                break;
            }
            long j2 = 10;
            i2--;
            bArr[i2] = okio.internal.a.a[(int) (j % j2)];
            j /= j2;
        }
        if (z) {
            bArr[i2 - 1] = 45;
        }
        bL0.c += i;
        this.b += i;
    }

    public final long r(long j, k bytes) {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        if (bytes.a.length <= 0) {
            throw new IllegalArgumentException("bytes is empty");
        }
        long j2 = 0;
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "fromIndex < 0: ").toString());
        }
        B b = this.a;
        if (b == null) {
            return -1L;
        }
        long j3 = this.b;
        if (j3 - j < j) {
            while (j3 > j) {
                b = b.g;
                Intrinsics.d(b);
                j3 -= b.c - b.b;
            }
            byte[] bArr = bytes.a;
            byte b2 = bArr[0];
            int length = bArr.length;
            long j4 = (this.b - length) + 1;
            while (j3 < j4) {
                int iMin = (int) Math.min(b.c, (b.b + j4) - j3);
                for (int i = (int) ((b.b + j) - j3); i < iMin; i++) {
                    if (b.a[i] == b2 && okio.internal.a.a(b, i + 1, bArr, length)) {
                        return (i - b.b) + j3;
                    }
                }
                j3 += b.c - b.b;
                b = b.f;
                Intrinsics.d(b);
                j = j3;
            }
            return -1L;
        }
        while (true) {
            long j5 = (b.c - b.b) + j2;
            if (j5 > j) {
                break;
            }
            b = b.f;
            Intrinsics.d(b);
            j2 = j5;
        }
        byte[] bArr2 = bytes.a;
        byte b3 = bArr2[0];
        int length2 = bArr2.length;
        long j6 = (this.b - length2) + 1;
        while (j2 < j6) {
            int iMin2 = (int) Math.min(b.c, (b.b + j6) - j2);
            for (int i2 = (int) ((b.b + j) - j2); i2 < iMin2; i2++) {
                if (b.a[i2] == b3 && okio.internal.a.a(b, i2 + 1, bArr2, length2)) {
                    return (i2 - b.b) + j2;
                }
            }
            j2 += b.c - b.b;
            b = b.f;
            Intrinsics.d(b);
            j = j2;
        }
        return -1L;
    }

    public final void r0(long j) {
        if (j == 0) {
            p0(48);
            return;
        }
        long j2 = (j >>> 1) | j;
        long j3 = j2 | (j2 >>> 2);
        long j4 = j3 | (j3 >>> 4);
        long j5 = j4 | (j4 >>> 8);
        long j6 = j5 | (j5 >>> 16);
        long j7 = j6 | (j6 >>> 32);
        long j8 = j7 - ((j7 >>> 1) & 6148914691236517205L);
        long j9 = ((j8 >>> 2) & 3689348814741910323L) + (j8 & 3689348814741910323L);
        long j10 = ((j9 >>> 4) + j9) & 1085102592571150095L;
        long j11 = j10 + (j10 >>> 8);
        long j12 = j11 + (j11 >>> 16);
        int i = (int) ((((j12 & 63) + ((j12 >>> 32) & 63)) + 3) / 4);
        B bL0 = l0(i);
        int i2 = bL0.c;
        for (int i3 = (i2 + i) - 1; i3 >= i2; i3--) {
            bL0.a[i3] = okio.internal.a.a[(int) (15 & j)];
            j >>>= 4;
        }
        bL0.c += i;
        this.b += i;
    }

    @Override // java.nio.channels.ReadableByteChannel
    public final int read(ByteBuffer sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        B b = this.a;
        if (b == null) {
            return -1;
        }
        int iMin = Math.min(sink.remaining(), b.c - b.b);
        sink.put(b.a, b.b, iMin);
        int i = b.b + iMin;
        b.b = i;
        this.b -= iMin;
        if (i == b.c) {
            this.a = b.a();
            C.a(b);
        }
        return iMin;
    }

    public final byte readByte() {
        if (this.b == 0) {
            throw new EOFException();
        }
        B b = this.a;
        Intrinsics.d(b);
        int i = b.b;
        int i2 = b.c;
        int i3 = i + 1;
        byte b2 = b.a[i];
        this.b--;
        if (i3 != i2) {
            b.b = i3;
            return b2;
        }
        this.a = b.a();
        C.a(b);
        return b2;
    }

    public final void s0(int i) {
        B bL0 = l0(4);
        int i2 = bL0.c;
        byte[] bArr = bL0.a;
        bArr[i2] = (byte) ((i >>> 24) & 255);
        bArr[i2 + 1] = (byte) ((i >>> 16) & 255);
        bArr[i2 + 2] = (byte) ((i >>> 8) & 255);
        bArr[i2 + 3] = (byte) (i & 255);
        bL0.c = i2 + 4;
        this.b += 4;
    }

    @Override // okio.InterfaceC5093j
    public final void skip(long j) throws EOFException {
        while (j > 0) {
            B b = this.a;
            if (b == null) {
                throw new EOFException();
            }
            int iMin = (int) Math.min(j, b.c - b.b);
            long j2 = iMin;
            this.b -= j2;
            j -= j2;
            int i = b.b + iMin;
            b.b = i;
            if (i == b.c) {
                this.a = b.a();
                C.a(b);
            }
        }
    }

    @Override // okio.InterfaceC5093j
    public final long t(k bytes) {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        return r(0L, bytes);
    }

    public final void t0(int i, int i2, String string) {
        char cCharAt;
        Intrinsics.checkNotNullParameter(string, "string");
        if (i < 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "beginIndex < 0: ").toString());
        }
        if (i2 < i) {
            throw new IllegalArgumentException(d0.p("endIndex < beginIndex: ", i2, " < ", i).toString());
        }
        if (i2 > string.length()) {
            StringBuilder sbV = android.support.v4.media.session.a.v(i2, "endIndex > string.length: ", " > ");
            sbV.append(string.length());
            throw new IllegalArgumentException(sbV.toString().toString());
        }
        while (i < i2) {
            char cCharAt2 = string.charAt(i);
            if (cCharAt2 < 128) {
                B bL0 = l0(1);
                int i3 = bL0.c - i;
                int iMin = Math.min(i2, 8192 - i3);
                int i4 = i + 1;
                byte[] bArr = bL0.a;
                bArr[i + i3] = (byte) cCharAt2;
                while (true) {
                    i = i4;
                    if (i >= iMin || (cCharAt = string.charAt(i)) >= 128) {
                        break;
                    }
                    i4 = i + 1;
                    bArr[i + i3] = (byte) cCharAt;
                }
                int i5 = bL0.c;
                int i6 = (i3 + i) - i5;
                bL0.c = i5 + i6;
                this.b += i6;
            } else {
                if (cCharAt2 < 2048) {
                    B bL02 = l0(2);
                    int i7 = bL02.c;
                    byte[] bArr2 = bL02.a;
                    bArr2[i7] = (byte) ((cCharAt2 >> 6) | 192);
                    bArr2[i7 + 1] = (byte) ((cCharAt2 & '?') | 128);
                    bL02.c = i7 + 2;
                    this.b += 2;
                } else if (cCharAt2 < 55296 || cCharAt2 > 57343) {
                    B bL03 = l0(3);
                    int i8 = bL03.c;
                    byte[] bArr3 = bL03.a;
                    bArr3[i8] = (byte) ((cCharAt2 >> '\f') | 224);
                    bArr3[i8 + 1] = (byte) ((63 & (cCharAt2 >> 6)) | 128);
                    bArr3[i8 + 2] = (byte) ((cCharAt2 & '?') | 128);
                    bL03.c = i8 + 3;
                    this.b += 3;
                } else {
                    int i9 = i + 1;
                    char cCharAt3 = i9 < i2 ? string.charAt(i9) : (char) 0;
                    if (cCharAt2 > 56319 || 56320 > cCharAt3 || cCharAt3 >= 57344) {
                        p0(63);
                        i = i9;
                    } else {
                        int i10 = (((cCharAt2 & 1023) << 10) | (cCharAt3 & 1023)) + 65536;
                        B bL04 = l0(4);
                        int i11 = bL04.c;
                        byte[] bArr4 = bL04.a;
                        bArr4[i11] = (byte) ((i10 >> 18) | 240);
                        bArr4[i11 + 1] = (byte) (((i10 >> 12) & 63) | 128);
                        bArr4[i11 + 2] = (byte) (((i10 >> 6) & 63) | 128);
                        bArr4[i11 + 3] = (byte) ((i10 & 63) | 128);
                        bL04.c = i11 + 4;
                        this.b += 4;
                        i += 2;
                    }
                }
                i++;
            }
        }
    }

    public final String toString() {
        long j = this.b;
        if (j <= 2147483647L) {
            return k0((int) j).toString();
        }
        throw new IllegalStateException(("size > Int.MAX_VALUE: " + this.b).toString());
    }

    public final boolean u() {
        return this.b == 0;
    }

    public final void u0(String string) {
        Intrinsics.checkNotNullParameter(string, "string");
        t0(0, string.length(), string);
    }

    @Override // okio.InterfaceC5092i
    public final /* bridge */ /* synthetic */ InterfaceC5092i v(int i) {
        p0(i);
        return this;
    }

    public final void v0(int i) {
        if (i < 128) {
            p0(i);
            return;
        }
        if (i < 2048) {
            B bL0 = l0(2);
            int i2 = bL0.c;
            byte[] bArr = bL0.a;
            bArr[i2] = (byte) ((i >> 6) | 192);
            bArr[i2 + 1] = (byte) ((i & 63) | 128);
            bL0.c = i2 + 2;
            this.b += 2;
            return;
        }
        if (55296 <= i && i < 57344) {
            p0(63);
            return;
        }
        if (i < 65536) {
            B bL02 = l0(3);
            int i3 = bL02.c;
            byte[] bArr2 = bL02.a;
            bArr2[i3] = (byte) ((i >> 12) | 224);
            bArr2[i3 + 1] = (byte) (((i >> 6) & 63) | 128);
            bArr2[i3 + 2] = (byte) ((i & 63) | 128);
            bL02.c = i3 + 3;
            this.b += 3;
            return;
        }
        if (i > 1114111) {
            throw new IllegalArgumentException("Unexpected code point: 0x".concat(AbstractC5085b.l(i)));
        }
        B bL03 = l0(4);
        int i4 = bL03.c;
        byte[] bArr3 = bL03.a;
        bArr3[i4] = (byte) ((i >> 18) | 240);
        bArr3[i4 + 1] = (byte) (((i >> 12) & 63) | 128);
        bArr3[i4 + 2] = (byte) (((i >> 6) & 63) | 128);
        bArr3[i4 + 3] = (byte) ((i & 63) | 128);
        bL03.c = i4 + 4;
        this.b += 4;
    }

    @Override // okio.InterfaceC5093j
    public final void w(C5091h sink, long j) throws EOFException {
        Intrinsics.checkNotNullParameter(sink, "sink");
        long j2 = this.b;
        if (j2 >= j) {
            sink.L(this, j);
        } else {
            sink.L(this, j2);
            throw new EOFException();
        }
    }

    @Override // java.nio.channels.WritableByteChannel
    public final int write(ByteBuffer source) {
        Intrinsics.checkNotNullParameter(source, "source");
        int iRemaining = source.remaining();
        int i = iRemaining;
        while (i > 0) {
            B bL0 = l0(1);
            int iMin = Math.min(i, 8192 - bL0.c);
            source.get(bL0.a, bL0.c, iMin);
            i -= iMin;
            bL0.c += iMin;
        }
        this.b += iRemaining;
        return iRemaining;
    }

    @Override // okio.InterfaceC5093j
    public final long x(k targetBytes) {
        Intrinsics.checkNotNullParameter(targetBytes, "targetBytes");
        return y(0L, targetBytes);
    }

    public final long y(long j, k targetBytes) {
        Intrinsics.checkNotNullParameter(targetBytes, "targetBytes");
        long j2 = 0;
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "fromIndex < 0: ").toString());
        }
        B b = this.a;
        if (b == null) {
            return -1L;
        }
        long j3 = this.b;
        if (j3 - j < j) {
            while (j3 > j) {
                b = b.g;
                Intrinsics.d(b);
                j3 -= b.c - b.b;
            }
            if (targetBytes.d() == 2) {
                byte bJ = targetBytes.j(0);
                byte bJ2 = targetBytes.j(1);
                while (j3 < this.b) {
                    int i = b.c;
                    for (int i2 = (int) ((b.b + j) - j3); i2 < i; i2++) {
                        byte b2 = b.a[i2];
                        if (b2 == bJ || b2 == bJ2) {
                            return (i2 - b.b) + j3;
                        }
                    }
                    j3 += b.c - b.b;
                    b = b.f;
                    Intrinsics.d(b);
                    j = j3;
                }
            } else {
                byte[] bArrH = targetBytes.h();
                while (j3 < this.b) {
                    int i3 = b.c;
                    for (int i4 = (int) ((b.b + j) - j3); i4 < i3; i4++) {
                        byte b3 = b.a[i4];
                        for (byte b4 : bArrH) {
                            if (b3 == b4) {
                                return (i4 - b.b) + j3;
                            }
                        }
                    }
                    j3 += b.c - b.b;
                    b = b.f;
                    Intrinsics.d(b);
                    j = j3;
                }
            }
            return -1L;
        }
        while (true) {
            long j4 = (b.c - b.b) + j2;
            if (j4 > j) {
                break;
            }
            b = b.f;
            Intrinsics.d(b);
            j2 = j4;
        }
        if (targetBytes.d() == 2) {
            byte bJ3 = targetBytes.j(0);
            byte bJ4 = targetBytes.j(1);
            while (j2 < this.b) {
                int i5 = b.c;
                for (int i6 = (int) ((b.b + j) - j2); i6 < i5; i6++) {
                    byte b5 = b.a[i6];
                    if (b5 == bJ3 || b5 == bJ4) {
                        return (i6 - b.b) + j2;
                    }
                }
                j2 += b.c - b.b;
                b = b.f;
                Intrinsics.d(b);
                j = j2;
            }
        } else {
            byte[] bArrH2 = targetBytes.h();
            while (j2 < this.b) {
                int i7 = b.c;
                for (int i8 = (int) ((b.b + j) - j2); i8 < i7; i8++) {
                    byte b6 = b.a[i8];
                    for (byte b7 : bArrH2) {
                        if (b6 == b7) {
                            return (i8 - b.b) + j2;
                        }
                    }
                }
                j2 += b.c - b.b;
                b = b.f;
                Intrinsics.d(b);
                j = j2;
            }
        }
        return -1L;
    }

    public final int read(byte[] sink, int i, int i2) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        AbstractC5085b.e(sink.length, i, i2);
        B b = this.a;
        if (b == null) {
            return -1;
        }
        int iMin = Math.min(i2, b.c - b.b);
        int i3 = b.b;
        C4930v.d(i, i3, i3 + iMin, b.a, sink);
        int i4 = b.b + iMin;
        b.b = i4;
        this.b -= iMin;
        if (i4 == b.c) {
            this.a = b.a();
            C.a(b);
        }
        return iMin;
    }
}
