package okio;

import androidx.compose.animation.d0;
import io.ktor.client.plugins.C4864k;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.Charsets;

/* loaded from: classes3.dex */
public final class A implements InterfaceC5093j {
    public final G a;
    public final C5091h b;
    public boolean c;

    public A(G source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
        this.b = new C5091h();
    }

    @Override // okio.InterfaceC5093j
    public final boolean J(long j, k bytes) {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        int length = bytes.a.length;
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        if (length < 0 || bytes.a.length < length) {
            return false;
        }
        for (int i = 0; i < length; i++) {
            long j2 = i;
            if (!e(1 + j2) || this.b.p(j2) != bytes.a[i]) {
                return false;
            }
        }
        return true;
    }

    @Override // okio.InterfaceC5093j
    public final String K(Charset charset) {
        Intrinsics.checkNotNullParameter(charset, "charset");
        G g = this.a;
        C5091h c5091h = this.b;
        c5091h.M(g);
        return c5091h.K(charset);
    }

    @Override // okio.InterfaceC5093j
    public final String S() {
        return y(Long.MAX_VALUE);
    }

    @Override // okio.InterfaceC5093j
    public final String U() {
        G g = this.a;
        C5091h c5091h = this.b;
        c5091h.M(g);
        return c5091h.U();
    }

    public final long a(byte b, long j, long j2) {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        if (0 > j2) {
            throw new IllegalArgumentException(d0.n(j2, "fromIndex=0 toIndex=").toString());
        }
        long jMax = 0;
        while (jMax < j2) {
            C5091h c5091h = this.b;
            byte b2 = b;
            long j3 = j2;
            long jQ = c5091h.q(b2, jMax, j3);
            if (jQ != -1) {
                return jQ;
            }
            long j4 = c5091h.b;
            if (j4 >= j3 || this.a.b0(c5091h, 8192L) == -1) {
                break;
            }
            jMax = Math.max(jMax, j4);
            b = b2;
            j2 = j3;
        }
        return -1L;
    }

    @Override // okio.G
    public final long b0(C5091h sink, long j) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount < 0: ").toString());
        }
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        C5091h c5091h = this.b;
        if (c5091h.b == 0) {
            if (j == 0) {
                return 0L;
            }
            if (this.a.b0(c5091h, 8192L) == -1) {
                return -1L;
            }
        }
        return c5091h.b0(sink, Math.min(j, c5091h.b));
    }

    @Override // okio.InterfaceC5093j
    public final C5091h c() {
        return this.b;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable, java.nio.channels.Channel
    public final void close() throws IOException {
        if (this.c) {
            return;
        }
        this.c = true;
        this.a.close();
        this.b.d();
    }

    public final k d(long j) throws EOFException {
        k(j);
        return this.b.D(j);
    }

    @Override // okio.InterfaceC5093j
    public final boolean e(long j) {
        C5091h c5091h;
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount < 0: ").toString());
        }
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        do {
            c5091h = this.b;
            if (c5091h.b >= j) {
                return true;
            }
        } while (this.a.b0(c5091h, 8192L) != -1);
        return false;
    }

    @Override // okio.InterfaceC5093j
    public final long e0(InterfaceC5092i sink) {
        C5091h c5091h;
        Intrinsics.checkNotNullParameter(sink, "sink");
        long j = 0;
        while (true) {
            c5091h = this.b;
            if (this.a.b0(c5091h, 8192L) == -1) {
                break;
            }
            long jI = c5091h.i();
            if (jI > 0) {
                j += jI;
                sink.L(c5091h, jI);
            }
        }
        long j2 = c5091h.b;
        if (j2 <= 0) {
            return j;
        }
        long j3 = j + j2;
        sink.L(c5091h, j2);
        return j3;
    }

    /* JADX WARN: Code restructure failed: missing block: B:41:0x00d2, code lost:
    
        if (r13 == 0) goto L64;
     */
    /* JADX WARN: Code restructure failed: missing block: B:42:0x00d4, code lost:
    
        r17 = r16;
     */
    /* JADX WARN: Code restructure failed: missing block: B:43:0x00d7, code lost:
    
        r3 = okio.internal.b.a;
        r4 = r3[(r15 >> 4) & 15];
        r3 = r3[r15 & 15];
        r5 = new char[2];
        r5[r21] = r4;
        r5[r16] = r3;
        kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, "<this>");
     */
    /* JADX WARN: Code restructure failed: missing block: B:44:0x00fd, code lost:
    
        throw new java.lang.NumberFormatException("Expected leading [0-9a-fA-F] character but was 0x".concat(new java.lang.String(r5)));
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final long f() throws java.io.EOFException {
        /*
            Method dump skipped, instructions count: 305
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: okio.A.f():long");
    }

    @Override // okio.G
    public final I h() {
        return this.a.h();
    }

    public final int i() throws EOFException {
        k(4L);
        return this.b.P();
    }

    @Override // okio.InterfaceC5093j
    public final InputStream i0() {
        return new C4864k(this, 3);
    }

    @Override // java.nio.channels.Channel
    public final boolean isOpen() {
        return !this.c;
    }

    public final int j() throws EOFException {
        k(4L);
        int iP = this.b.P();
        return ((iP & 255) << 24) | (((-16777216) & iP) >>> 24) | ((16711680 & iP) >>> 8) | ((65280 & iP) << 8);
    }

    @Override // okio.InterfaceC5093j
    public final int j0(w options) throws EOFException {
        Intrinsics.checkNotNullParameter(options, "options");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        while (true) {
            C5091h c5091h = this.b;
            int iC = okio.internal.a.c(c5091h, options, true);
            if (iC != -2) {
                if (iC != -1) {
                    c5091h.skip(options.b[iC].d());
                    return iC;
                }
            } else if (this.a.b0(c5091h, 8192L) == -1) {
                break;
            }
        }
        return -1;
    }

    @Override // okio.InterfaceC5093j
    public final void k(long j) throws EOFException {
        if (!e(j)) {
            throw new EOFException();
        }
    }

    public final long l() throws EOFException {
        long jP;
        k(8L);
        C5091h c5091h = this.b;
        if (c5091h.b < 8) {
            throw new EOFException();
        }
        B b = c5091h.a;
        Intrinsics.d(b);
        int i = b.b;
        int i2 = b.c;
        if (i2 - i < 8) {
            jP = ((c5091h.P() & 4294967295L) << 32) | (4294967295L & c5091h.P());
        } else {
            byte[] bArr = b.a;
            int i3 = i + 7;
            long j = ((bArr[i + 1] & 255) << 48) | ((bArr[i] & 255) << 56) | ((bArr[i + 2] & 255) << 40) | ((bArr[i + 3] & 255) << 32) | ((bArr[i + 4] & 255) << 24) | ((bArr[i + 5] & 255) << 16) | ((bArr[i + 6] & 255) << 8);
            int i4 = i + 8;
            long j2 = j | (bArr[i3] & 255);
            c5091h.b -= 8;
            if (i4 == i2) {
                c5091h.a = b.a();
                C.a(b);
            } else {
                b.b = i4;
            }
            jP = j2;
        }
        return ((jP & 255) << 56) | (((-72057594037927936L) & jP) >>> 56) | ((71776119061217280L & jP) >>> 40) | ((280375465082880L & jP) >>> 24) | ((1095216660480L & jP) >>> 8) | ((4278190080L & jP) << 8) | ((16711680 & jP) << 24) | ((65280 & jP) << 40);
    }

    public final short p() throws EOFException {
        k(2L);
        return this.b.Y();
    }

    @Override // okio.InterfaceC5093j
    public final A peek() {
        return AbstractC5085b.c(new y(this));
    }

    public final short q() throws EOFException {
        k(2L);
        return this.b.a0();
    }

    public final String r(long j) throws EOFException {
        k(j);
        C5091h c5091h = this.b;
        c5091h.getClass();
        return c5091h.c0(j, Charsets.UTF_8);
    }

    @Override // java.nio.channels.ReadableByteChannel
    public final int read(ByteBuffer sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        C5091h c5091h = this.b;
        if (c5091h.b == 0 && this.a.b0(c5091h, 8192L) == -1) {
            return -1;
        }
        return c5091h.read(sink);
    }

    public final byte readByte() throws EOFException {
        k(1L);
        return this.b.readByte();
    }

    @Override // okio.InterfaceC5093j
    public final void skip(long j) throws EOFException {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        while (j > 0) {
            C5091h c5091h = this.b;
            if (c5091h.b == 0 && this.a.b0(c5091h, 8192L) == -1) {
                throw new EOFException();
            }
            long jMin = Math.min(j, c5091h.b);
            c5091h.skip(jMin);
            j -= jMin;
        }
    }

    @Override // okio.InterfaceC5093j
    public final long t(k bytes) {
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        Intrinsics.checkNotNullParameter(bytes, "bytes");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        long jMax = 0;
        while (true) {
            C5091h c5091h = this.b;
            long jR = c5091h.r(jMax, bytes);
            if (jR != -1) {
                return jR;
            }
            long j = c5091h.b;
            if (this.a.b0(c5091h, 8192L) == -1) {
                return -1L;
            }
            jMax = Math.max(jMax, (j - bytes.a.length) + 1);
        }
    }

    public final String toString() {
        return "buffer(" + this.a + ')';
    }

    public final boolean u() {
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        C5091h c5091h = this.b;
        return c5091h.u() && this.a.b0(c5091h, 8192L) == -1;
    }

    @Override // okio.InterfaceC5093j
    public final void w(C5091h sink, long j) throws EOFException {
        C5091h c5091h = this.b;
        Intrinsics.checkNotNullParameter(sink, "sink");
        try {
            k(j);
            c5091h.w(sink, j);
        } catch (EOFException e) {
            sink.M(c5091h);
            throw e;
        }
    }

    @Override // okio.InterfaceC5093j
    public final long x(k targetBytes) {
        Intrinsics.checkNotNullParameter(targetBytes, "targetBytes");
        Intrinsics.checkNotNullParameter(targetBytes, "targetBytes");
        if (this.c) {
            throw new IllegalStateException("closed");
        }
        long jMax = 0;
        while (true) {
            C5091h c5091h = this.b;
            long jY = c5091h.y(jMax, targetBytes);
            if (jY != -1) {
                return jY;
            }
            long j = c5091h.b;
            if (this.a.b0(c5091h, 8192L) == -1) {
                return -1L;
            }
            jMax = Math.max(jMax, j);
        }
    }

    public final String y(long j) {
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "limit < 0: ").toString());
        }
        long j2 = j == Long.MAX_VALUE ? Long.MAX_VALUE : j + 1;
        long jA = a((byte) 10, 0L, j2);
        C5091h c5091h = this.b;
        if (jA != -1) {
            return okio.internal.a.b(c5091h, jA);
        }
        if (j2 < Long.MAX_VALUE && e(j2) && c5091h.p(j2 - 1) == 13 && e(j2 + 1) && c5091h.p(j2) == 10) {
            return okio.internal.a.b(c5091h, j2);
        }
        C5091h c5091h2 = new C5091h();
        c5091h.l(c5091h2, 0L, Math.min(32, c5091h.b));
        throw new EOFException("\\n not found: limit=" + Math.min(c5091h.b, j) + " content=" + c5091h2.D(c5091h2.b).e() + (char) 8230);
    }
}
