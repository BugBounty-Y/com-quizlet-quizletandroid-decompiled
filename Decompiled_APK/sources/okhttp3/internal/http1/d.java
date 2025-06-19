package okhttp3.internal.http1;

import androidx.compose.animation.d0;
import com.google.android.gms.internal.ads.C2007ea;
import java.io.IOException;
import java.net.ProtocolException;
import java.util.concurrent.TimeUnit;
import kotlin.jvm.internal.Intrinsics;
import okhttp3.internal.connection.i;
import okio.C5091h;

/* loaded from: classes3.dex */
public final class d extends a {
    public long d;
    public final /* synthetic */ C2007ea e;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public d(C2007ea c2007ea, long j) {
        super(c2007ea);
        this.e = c2007ea;
        this.d = j;
        if (j == 0) {
            a();
        }
    }

    @Override // okhttp3.internal.http1.a, okio.G
    public final long b0(C5091h sink, long j) throws IOException {
        Intrinsics.checkNotNullParameter(sink, "sink");
        if (j < 0) {
            throw new IllegalArgumentException(d0.n(j, "byteCount < 0: ").toString());
        }
        if (this.b) {
            throw new IllegalStateException("closed");
        }
        long j2 = this.d;
        if (j2 == 0) {
            return -1L;
        }
        long jB0 = super.b0(sink, Math.min(j2, j));
        if (jB0 == -1) {
            ((i) this.e.d).k();
            ProtocolException protocolException = new ProtocolException("unexpected end of stream");
            a();
            throw protocolException;
        }
        long j3 = this.d - jB0;
        this.d = j3;
        if (j3 == 0) {
            a();
        }
        return jB0;
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public final void close() {
        if (this.b) {
            return;
        }
        if (this.d != 0) {
            TimeUnit timeUnit = TimeUnit.MILLISECONDS;
            if (!okhttp3.internal.b.i(this)) {
                ((i) this.e.d).k();
                a();
            }
        }
        this.b = true;
    }
}
