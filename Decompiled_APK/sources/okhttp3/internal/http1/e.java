package okhttp3.internal.http1;

import androidx.compose.animation.d0;
import java.io.IOException;
import kotlin.jvm.internal.Intrinsics;
import okio.C5091h;

/* loaded from: classes3.dex */
public final class e extends a {
    public boolean d;

    @Override // okhttp3.internal.http1.a, okio.G
    public final long b0(C5091h sink, long j) throws IOException {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount < 0: ").toString());
        }
        if (this.b) {
            throw new IllegalStateException("closed");
        }
        if (this.d) {
            return -1L;
        }
        long jB0 = super.b0(sink, j);
        if (jB0 != -1) {
            return jB0;
        }
        this.d = true;
        a();
        return -1L;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        if (this.b) {
            return;
        }
        if (!this.d) {
            a();
        }
        this.b = true;
    }
}
