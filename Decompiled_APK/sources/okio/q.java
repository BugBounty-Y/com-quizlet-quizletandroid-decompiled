package okio;

import androidx.compose.animation.d0;
import java.io.EOFException;
import java.io.IOException;
import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt;

/* loaded from: classes3.dex */
public final class q implements G {
    public byte a;
    public final A b;
    public final Inflater c;
    public final r d;
    public final CRC32 e;

    public q(G source) {
        Intrinsics.checkNotNullParameter(source, "source");
        A a = new A(source);
        this.b = a;
        Inflater inflater = new Inflater(true);
        this.c = inflater;
        this.d = new r(a, inflater);
        this.e = new CRC32();
    }

    public static void a(int i, int i2, String str) throws IOException {
        if (i2 == i) {
            return;
        }
        StringBuilder sbX = android.support.v4.media.session.a.x(str, ": actual 0x");
        sbX.append(StringsKt.S('0', 8, AbstractC5085b.l(i2)));
        sbX.append(" != expected 0x");
        sbX.append(StringsKt.S('0', 8, AbstractC5085b.l(i)));
        throw new IOException(sbX.toString());
    }

    @Override // okio.G
    public final long b0(C5091h sink, long j) throws DataFormatException, IOException {
        q qVar = this;
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount < 0: ").toString());
        }
        if (j == 0) {
            return 0L;
        }
        byte b = qVar.a;
        CRC32 crc32 = qVar.e;
        A a = qVar.b;
        if (b == 0) {
            a.k(10L);
            C5091h c5091h = a.b;
            byte bP = c5091h.p(3L);
            boolean z = ((bP >> 1) & 1) == 1;
            if (z) {
                qVar.d(c5091h, 0L, 10L);
            }
            a(8075, a.p(), "ID1ID2");
            a.skip(8L);
            if (((bP >> 2) & 1) == 1) {
                a.k(2L);
                if (z) {
                    d(c5091h, 0L, 2L);
                }
                long jA0 = c5091h.a0() & 65535;
                a.k(jA0);
                if (z) {
                    d(c5091h, 0L, jA0);
                }
                a.skip(jA0);
            }
            if (((bP >> 3) & 1) == 1) {
                long jA = a.a((byte) 0, 0L, Long.MAX_VALUE);
                if (jA == -1) {
                    throw new EOFException();
                }
                if (z) {
                    d(c5091h, 0L, jA + 1);
                }
                a.skip(jA + 1);
            }
            if (((bP >> 4) & 1) == 1) {
                long jA2 = a.a((byte) 0, 0L, Long.MAX_VALUE);
                if (jA2 == -1) {
                    throw new EOFException();
                }
                if (z) {
                    qVar = this;
                    qVar.d(c5091h, 0L, jA2 + 1);
                } else {
                    qVar = this;
                }
                a.skip(jA2 + 1);
            } else {
                qVar = this;
            }
            if (z) {
                a(a.q(), (short) crc32.getValue(), "FHCRC");
                crc32.reset();
            }
            qVar.a = (byte) 1;
        }
        if (qVar.a == 1) {
            long j2 = sink.b;
            long jB0 = qVar.d.b0(sink, j);
            if (jB0 != -1) {
                qVar.d(sink, j2, jB0);
                return jB0;
            }
            qVar.a = (byte) 2;
        }
        if (qVar.a == 2) {
            a(a.j(), (int) crc32.getValue(), "CRC");
            a(a.j(), (int) qVar.c.getBytesWritten(), "ISIZE");
            qVar.a = (byte) 3;
            if (!a.u()) {
                throw new IOException("gzip finished without exhausting source");
            }
        }
        return -1L;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        this.d.close();
    }

    public final void d(C5091h c5091h, long j, long j2) {
        B b = c5091h.a;
        Intrinsics.d(b);
        while (true) {
            int i = b.c;
            int i2 = b.b;
            if (j < i - i2) {
                break;
            }
            j -= i - i2;
            b = b.f;
            Intrinsics.d(b);
        }
        while (j2 > 0) {
            int iMin = (int) Math.min(b.c - r6, j2);
            this.e.update(b.a, (int) (b.b + j), iMin);
            j2 -= iMin;
            b = b.f;
            Intrinsics.d(b);
            j = 0;
        }
    }

    @Override // okio.G
    public final I h() {
        return this.b.a.h();
    }
}
