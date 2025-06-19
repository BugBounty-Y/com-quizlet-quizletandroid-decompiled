package okio;

import androidx.compose.animation.d0;
import java.io.EOFException;
import java.io.IOException;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import kotlin.jvm.internal.Intrinsics;

/* loaded from: classes3.dex */
public final class r implements G {
    public final A a;
    public final Inflater b;
    public int c;
    public boolean d;

    public r(A source, Inflater inflater) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        this.a = source;
        this.b = inflater;
    }

    @Override // okio.G
    public final long b0(C5091h sink, long j) throws DataFormatException, IOException {
        Intrinsics.checkNotNullParameter(sink, "sink");
        do {
            Inflater inflater = this.b;
            Intrinsics.checkNotNullParameter(sink, "sink");
            long j2 = 0;
            if (j < 0) {
                throw new IllegalArgumentException(d0.n(j, "byteCount < 0: ").toString());
            }
            if (this.d) {
                throw new IllegalStateException("closed");
            }
            if (j != 0) {
                try {
                    B bL0 = sink.l0(1);
                    int iMin = (int) Math.min(j, 8192 - bL0.c);
                    boolean zNeedsInput = inflater.needsInput();
                    A a = this.a;
                    if (zNeedsInput && !a.u()) {
                        B b = a.b.a;
                        Intrinsics.d(b);
                        int i = b.c;
                        int i2 = b.b;
                        int i3 = i - i2;
                        this.c = i3;
                        inflater.setInput(b.a, i2, i3);
                    }
                    int iInflate = inflater.inflate(bL0.a, bL0.c, iMin);
                    int i4 = this.c;
                    if (i4 != 0) {
                        int remaining = i4 - inflater.getRemaining();
                        this.c -= remaining;
                        a.skip(remaining);
                    }
                    if (iInflate > 0) {
                        bL0.c += iInflate;
                        long j3 = iInflate;
                        sink.b += j3;
                        j2 = j3;
                    } else if (bL0.b == bL0.c) {
                        sink.a = bL0.a();
                        C.a(bL0);
                    }
                } catch (DataFormatException e) {
                    throw new IOException(e);
                }
            }
            if (j2 > 0) {
                return j2;
            }
            Inflater inflater2 = this.b;
            if (inflater2.finished() || inflater2.needsDictionary()) {
                return -1L;
            }
        } while (!this.a.u());
        throw new EOFException("source exhausted prematurely");
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() throws IOException {
        if (this.d) {
            return;
        }
        this.b.end();
        this.d = true;
        this.a.close();
    }

    @Override // okio.G
    public final I h() {
        return this.a.a.h();
    }
}
