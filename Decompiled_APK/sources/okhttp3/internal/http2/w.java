package okhttp3.internal.http2;

import com.davemorrissey.labs.subscaleview.SubsamplingScaleImageView;
import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.collections.C4930v;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;

/* loaded from: classes3.dex */
public final class w implements Closeable, AutoCloseable {
    public static final Logger f = Logger.getLogger(e.class.getName());
    public final okio.z a;
    public final C5091h b;
    public int c;
    public boolean d;
    public final c e;

    public w(okio.z sink) {
        Intrinsics.checkNotNullParameter(sink, "sink");
        this.a = sink;
        C5091h c5091h = new C5091h();
        this.b = c5091h;
        this.c = 16384;
        this.e = new c(c5091h);
    }

    public final synchronized void a(z peerSettings) {
        try {
            Intrinsics.checkNotNullParameter(peerSettings, "peerSettings");
            if (this.d) {
                throw new IOException("closed");
            }
            int i = this.c;
            int i2 = peerSettings.a;
            if ((i2 & 32) != 0) {
                i = peerSettings.b[5];
            }
            this.c = i;
            if (((i2 & 2) != 0 ? peerSettings.b[1] : -1) != -1) {
                c cVar = this.e;
                int i3 = (i2 & 2) != 0 ? peerSettings.b[1] : -1;
                cVar.getClass();
                int iMin = Math.min(i3, 16384);
                int i4 = cVar.d;
                if (i4 != iMin) {
                    if (iMin < i4) {
                        cVar.b = Math.min(cVar.b, iMin);
                    }
                    cVar.c = true;
                    cVar.d = iMin;
                    int i5 = cVar.h;
                    if (iMin < i5) {
                        if (iMin == 0) {
                            b[] bVarArr = cVar.e;
                            C4930v.o(bVarArr, null, 0, bVarArr.length);
                            cVar.f = cVar.e.length - 1;
                            cVar.g = 0;
                            cVar.h = 0;
                        } else {
                            cVar.a(i5 - iMin);
                        }
                    }
                }
            }
            f(0, 0, 4, 1);
            this.a.flush();
        } catch (Throwable th) {
            throw th;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final synchronized void close() {
        this.d = true;
        this.a.close();
    }

    public final synchronized void d(boolean z, int i, C5091h c5091h, int i2) {
        if (this.d) {
            throw new IOException("closed");
        }
        f(i, i2, 0, z ? 1 : 0);
        if (i2 > 0) {
            Intrinsics.d(c5091h);
            this.a.L(c5091h, i2);
        }
    }

    public final void f(int i, int i2, int i3, int i4) {
        Level level = Level.FINE;
        Logger logger = f;
        if (logger.isLoggable(level)) {
            logger.fine(e.a(i, i2, i3, i4, false));
        }
        if (i2 > this.c) {
            throw new IllegalArgumentException(("FRAME_SIZE_ERROR length > " + this.c + ": " + i2).toString());
        }
        if ((Integer.MIN_VALUE & i) != 0) {
            throw new IllegalArgumentException(android.support.v4.media.session.a.f(i, "reserved bit set: ").toString());
        }
        byte[] bArr = okhttp3.internal.b.a;
        okio.z zVar = this.a;
        Intrinsics.checkNotNullParameter(zVar, "<this>");
        zVar.v((i2 >>> 16) & 255);
        zVar.v((i2 >>> 8) & 255);
        zVar.v(i2 & 255);
        zVar.v(i3 & 255);
        zVar.v(i4 & 255);
        zVar.d(i & SubsamplingScaleImageView.TILE_SIZE_AUTO);
    }

    public final synchronized void flush() {
        if (this.d) {
            throw new IOException("closed");
        }
        this.a.flush();
    }

    public final synchronized void i(int i, a errorCode, byte[] debugData) {
        Intrinsics.checkNotNullParameter(errorCode, "errorCode");
        Intrinsics.checkNotNullParameter(debugData, "debugData");
        if (this.d) {
            throw new IOException("closed");
        }
        if (errorCode.a == -1) {
            throw new IllegalArgumentException("errorCode.httpCode == -1");
        }
        f(0, debugData.length + 8, 7, 0);
        this.a.d(i);
        this.a.d(errorCode.a);
        if (debugData.length != 0) {
            this.a.X(debugData);
        }
        this.a.flush();
    }

    public final synchronized void j(int i, ArrayList headerBlock, boolean z) {
        Intrinsics.checkNotNullParameter(headerBlock, "headerBlock");
        if (this.d) {
            throw new IOException("closed");
        }
        this.e.d(headerBlock);
        long j = this.b.b;
        long jMin = Math.min(this.c, j);
        int i2 = j == jMin ? 4 : 0;
        if (z) {
            i2 |= 1;
        }
        f(i, (int) jMin, 1, i2);
        this.a.L(this.b, jMin);
        if (j > jMin) {
            long j2 = j - jMin;
            while (j2 > 0) {
                long jMin2 = Math.min(this.c, j2);
                j2 -= jMin2;
                f(i, (int) jMin2, 9, j2 == 0 ? 4 : 0);
                this.a.L(this.b, jMin2);
            }
        }
    }

    public final synchronized void l(int i, int i2, boolean z) {
        if (this.d) {
            throw new IOException("closed");
        }
        f(0, 8, 6, z ? 1 : 0);
        this.a.d(i);
        this.a.d(i2);
        this.a.flush();
    }

    public final synchronized void p(int i, a errorCode) {
        Intrinsics.checkNotNullParameter(errorCode, "errorCode");
        if (this.d) {
            throw new IOException("closed");
        }
        if (errorCode.a == -1) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        f(i, 4, 3, 0);
        this.a.d(errorCode.a);
        this.a.flush();
    }

    public final synchronized void q(int i, long j) {
        if (this.d) {
            throw new IOException("closed");
        }
        if (j == 0 || j > 2147483647L) {
            throw new IllegalArgumentException(("windowSizeIncrement == 0 || windowSizeIncrement > 0x7fffffffL: " + j).toString());
        }
        f(i, 4, 8, 0);
        this.a.d((int) j);
        this.a.flush();
    }
}
