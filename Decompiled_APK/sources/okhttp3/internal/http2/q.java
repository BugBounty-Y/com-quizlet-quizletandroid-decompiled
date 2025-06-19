package okhttp3.internal.http2;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.jvm.internal.Intrinsics;
import okio.A;
import okio.C5091h;
import okio.G;
import okio.I;

/* loaded from: classes3.dex */
public final class q implements G {
    public final A a;
    public int b;
    public int c;
    public int d;
    public int e;
    public int f;

    public q(A source) {
        Intrinsics.checkNotNullParameter(source, "source");
        this.a = source;
    }

    @Override // okio.G
    public final long b0(C5091h sink, long j) throws IOException {
        int i;
        int i2;
        Intrinsics.checkNotNullParameter(sink, "sink");
        do {
            int i3 = this.e;
            A a = this.a;
            if (i3 == 0) {
                a.skip(this.f);
                this.f = 0;
                if ((this.c & 4) == 0) {
                    i = this.d;
                    int iU = okhttp3.internal.b.u(a);
                    this.e = iU;
                    this.b = iU;
                    int i4 = a.readByte() & 255;
                    this.c = a.readByte() & 255;
                    Logger logger = r.d;
                    if (logger.isLoggable(Level.FINE)) {
                        okio.k kVar = e.a;
                        logger.fine(e.a(this.d, this.b, i4, this.c, true));
                    }
                    i2 = a.i() & SubsamplingScaleImageView.TILE_SIZE_AUTO;
                    this.d = i2;
                    if (i4 != 9) {
                        throw new IOException(i4 + " != TYPE_CONTINUATION");
                    }
                }
            } else {
                long jB0 = a.b0(sink, Math.min(j, i3));
                if (jB0 != -1) {
                    this.e -= (int) jB0;
                    return jB0;
                }
            }
            return -1L;
        } while (i2 == i);
        throw new IOException("TYPE_CONTINUATION streamId changed");
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
    }

    @Override // okio.G
    public final I h() {
        return this.a.a.h();
    }
}
